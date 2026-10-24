"""
End-to-end Threat Email Analysis pipeline.

This is the shared Stage H assembly layer used by both the CLI runner and
the HTTP API. It keeps one canonical A -> B/B2 -> D -> E -> F -> G flow.
"""

from __future__ import annotations

import logging
import os
import re
import time
from datetime import date, datetime
from typing import Any

from email_parser import parse_email, parse_email_from_upload
from forensics.header_forensics import analyze_headers
from forensics.attachment_forensics import analyze_attachments
from forensics.ioc_extraction import extract_iocs
from forensics.link_analysis import analyze_links
from forensics.qr_trace import build_qr_trace
from privacy import build_privacy_report, sanitize_for_external_ai
from threat_intel import enrich_iocs, attach_hop_geo
from correlation import correlate_and_store
from db import connection, repository
from ai_engine.stage_g import analyze_with_stage_g
from verdicts import finalize_verdict, LIKELY_LEGITIMATE
from evidence import build_evidence_ledger, build_evidence_report, compact_ledger
from provider_status import build_provider_status

logger = logging.getLogger("E-TAP.pipeline")

# How the message reached us. "quick_content_check" = rebuilt from the text
# visible in a mail client (no original headers/attachments/HTML links).
SOURCE_FULL_MESSAGE = "full_message"
SOURCE_QUICK_CHECK = "quick_content_check"
VALID_SOURCES = frozenset({SOURCE_FULL_MESSAGE, SOURCE_QUICK_CHECK})


def _env_truthy(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


_SECRET_PATTERNS = (
    re.compile(r"AIza[0-9A-Za-z_\-]{20,}"),
    re.compile(r"(?i)(api[_-]?key|key|token|secret)=[^&\s]+"),
)


def _short_reason(exc_text: Any, limit: int = 160) -> str | None:
    """Single-line, secret-scrubbed, length-limited version of an error message."""
    if not exc_text:
        return None
    text = " ".join(str(exc_text).split())
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub("[redacted]", text)
    return text if len(text) <= limit else text[: limit - 1] + "…"


def _count_unavailable_lookups(threat_intel: dict) -> tuple[int, int]:
    """Count attempted IOC lookups and true failures, excluding intentional skips."""
    total = failed = 0
    ignored = {"skipped_privacy", "skipped_limit", "skipped_non_public", "private_or_reserved", "not_checked", "skipped_by_policy", "disabled"}
    for section in ("ip_reputation", "domain_info", "url_reputation", "hash_reputation", "geo_lookup"):
        for info in (threat_intel.get(section) or {}).values():
            if not isinstance(info, dict):
                continue
            status = str(info.get("status") or "").lower()
            if status in ignored:
                continue
            total += 1
            if info.get("error") or status in {"timeout", "network_error", "provider_error", "invalid_response", "not_configured", "rate_limited", "rate_limited_internal", "unavailable"}:
                failed += 1
    return total, failed


def _json_safe(value: Any) -> Any:
    """
    Convert datetimes/ObjectIds and other backend values to JSON-safe data.
    FastAPI can do some of this itself, but the CLI runner should emit the
    exact same shape.
    """
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {str(k): _json_safe(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_json_safe(v) for v in value]
    if isinstance(value, tuple):
        return [_json_safe(v) for v in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return str(value)


def _build_email_summary(data: dict) -> dict:
    return {
        "subject": data.get("subject"),
        "from_raw": data.get("from_raw"),
        "from_display_name": data.get("from_display_name"),
        "from_email": data.get("from_email"),
        "to": data.get("to"),
        "reply_to": data.get("reply_to"),
        "date": data.get("date"),
        "message_id": data.get("message_id"),
        "source_format": data.get("source_format"),
        "parse_warnings": data.get("parse_warnings") or [],
        "body_text": data.get("body_text"),
        "body_html": data.get("body_html"),
    }


def _noop_progress(stage: str, state: str, detail: str | None = None) -> None:
    return None


def _plural(n: int, word: str) -> str:
    return f"{n} {word}{'' if n == 1 else 's'}"


def _sandbox_plan(attachments: list, sandbox: dict | None) -> tuple[str, list, dict | None, str, str]:
    """Decide stage S before the record exists; never raises.

    Returns (backend, candidates, paired agent, timeline state, timeline detail).
    `sandbox` is the caller's request: {"requested": bool, "token": str | None}.
    """
    try:
        from sandbox import get_backend
        from sandbox.policy import get_detonation_candidates
        backend = get_backend()
        if backend == "none":
            return backend, [], None, "not_available", "Deeper attachment analysis is not set up on this server"
        if not attachments:
            return backend, [], None, "skipped", "No attachments to open in the sandbox"
        agent = None
        online = False
        problem = None
        # Every backend runs only when the caller chose a deeper analysis.
        if not (sandbox or {}).get("requested"):
            return backend, [], None, "skipped", "Standard analysis: attachments were not opened"
        if backend == "agent":
            from sandbox.agent_queue import agent_for_client, is_online, problem_of
            agent = agent_for_client((sandbox or {}).get("token"))
            if agent is None:
                return backend, [], None, "not_available", "Deeper analysis needs your sandbox to be paired first"
            online = is_online(agent)
            problem = problem_of(agent) if online else None
        candidates = get_detonation_candidates(attachments)
        if not candidates:
            return backend, [], agent, "skipped", "No attachment type that needs dynamic analysis"
        where = {
            "agent": "sent to your sandbox" + (
                "" if online and not problem else
                f" (it reports a problem: {problem})" if online else
                " (offline now; it runs when the agent reconnects)"),
            "virtualbox": "queued for the Windows 11 VM",
            "replay": "checked against a recorded trace",
        }[backend]
        return backend, candidates, agent, "done", f"{_plural(len(candidates), 'attachment')} {where}; results follow in the report"
    except Exception as exc:
        logger.warning("Sandbox planning failed (non-fatal): %s", type(exc).__name__)
        return "none", [], None, "error", "Deeper attachment analysis could not be prepared"


def _submit_to_sandbox(email_id: str, raw_attachments: list, attachment_analysis: dict,
                       backend: str, candidates: list, agent: dict | None) -> tuple[dict, str]:
    """Queue eligible attachments for detonation. Returns (sandbox status, stage S label)."""
    status = {"status": "not_applicable", "email_id": email_id, "mode": backend}
    if backend == "none":
        return {**status, "status": "unavailable", "message": "Sandbox is not configured."}, "unavailable"
    if not candidates:
        if attachment_analysis.get("attachments") and (backend != "agent" or agent is None):
            return {**status, "status": "not_requested"}, "not_requested"
        return status, "not_applicable"
    try:
        from sandbox import submit
        status = submit(email_id, raw_attachments, attachment_analysis, agent=agent)
        return status, status.get("status", "submitted")
    except Exception as exc:
        # The sandbox must never break the static report.
        logger.warning("Sandbox submit failed (non-fatal): %s", type(exc).__name__)
        return {**status, "status": "error", "message": "Deeper attachment analysis could not be queued."}, "error"


def _run_parsed_pipeline(parsed_email, source: str | None = None, progress=None,
                         sandbox: dict | None = None) -> dict:
    # `progress(stage, state, detail)` reports live stage changes to a caller
    # (see analysis_jobs.py). It never affects the analysis itself.
    progress = progress or _noop_progress
    started_at = time.perf_counter()
    db = connection.get_db()
    data = parsed_email.to_dict()
    source = source if source in VALID_SOURCES else SOURCE_FULL_MESSAGE
    quick_check = source == SOURCE_QUICK_CHECK

    progress("headers", "running")
    header_analysis = analyze_headers(parsed_email, headers_available=not quick_check)
    if quick_check:
        progress("headers", "skipped", "Original headers were not available")
    else:
        flags = len(header_analysis.get("red_flags") or [])
        progress("headers", "done", _plural(flags, "red flag") if flags else "No header red flags")

    progress("static_attachments", "running")
    attachment_analysis = analyze_attachments(data.get("attachments") or [])
    _atts = attachment_analysis.get("attachments") or []
    _sus = sum(1 for a in _atts if a.get("suspicious"))
    if not _atts:
        progress("static_attachments", "done", "No attachments")
    else:
        progress("static_attachments", "done",
                 f"{_plural(len(_atts), 'file')} checked" + (f", {_sus} suspicious" if _sus else ", none suspicious"))

    # Stage S planning: which attachments the sandbox will open. The run
    # itself starts after the record is stored (it needs the email id) and
    # finishes in the background; see the submit step near the end.
    _sb_backend, _sb_candidates, _sb_agent, _sb_state, _sb_detail = _sandbox_plan(_atts, sandbox)
    progress("sandbox", _sb_state, _sb_detail)

    progress("indicators", "running")
    ioc_analysis = extract_iocs(
        all_headers=data.get("all_headers"),
        body_text=data.get("body_text"),
        body_html=data.get("body_html"),
        attachment_analysis=attachment_analysis,
        header_analysis=header_analysis,
    )

    # B5/B6: what each link's visible text claims vs where it points, and where
    # QR codes lead. Static only: nothing is fetched or followed.
    link_analysis = analyze_links(data.get("body_html"))
    qr_trace = build_qr_trace(attachment_analysis.get("attachments"))
    _n_ind = sum(len(ioc_analysis.get(k) or []) for k in ("ips", "domains", "urls", "hashes"))
    _n_links = (link_analysis.get("summary") or {}).get("total", 0)
    progress("indicators", "done", f"{_plural(_n_ind, 'indicator')}, {_plural(_n_links, 'link')}")

    threat_intel_live = _env_truthy("THREAT_INTEL_LIVE", default="0")
    progress("reputation", "running")
    threat_intel_analysis = enrich_iocs(ioc_analysis, live_lookup=threat_intel_live)
    attach_hop_geo(header_analysis, threat_intel_analysis, live=threat_intel_live)
    if threat_intel_live:
        _flagged = sum(
            1 for sec in ("ip_reputation", "domain_info", "url_reputation", "hash_reputation")
            for info in (threat_intel_analysis.get(sec) or {}).values()
            if isinstance(info, dict) and info.get("malicious") is True
        )
        progress("reputation", "done", f"{_flagged} flagged by reputation services" if _flagged else "Nothing flagged")
    else:
        progress("reputation", "skipped", "Live reputation lookups are turned off")

    progress("history", "running")

    correlation_result = correlate_and_store(
        ioc_analysis,
        db=db,
        message_id=data.get("message_id"),
        subject=data.get("subject"),
        from_email=data.get("from_email"),
        to_email=data.get("to"),
        email_date=data.get("date"),
        source_format=data.get("source_format"),
        header_analysis=header_analysis,
        attachment_analysis=attachment_analysis,
        threat_intel_analysis=threat_intel_analysis,
    )
    _related = len(correlation_result.get("related_emails") or [])
    progress("history", "done",
             f"Linked to {_plural(_related, 'earlier email')}" if _related else "No match with earlier emails")

    # Stage F' -- Graph Diffusion Score Engine (Personalized PageRank Label Propagation)
    try:
        from ai_engine.graph_diffusion import extract_graph_from_correlation, compute_graph_diffusion
        g_nodes, g_edges, g_seeds = extract_graph_from_correlation(
            email_id=correlation_result["email_id"],
            correlation=correlation_result,
            iocs=ioc_analysis,
            threat_intel=threat_intel_analysis,
        )
        graph_diffusion_result = compute_graph_diffusion(
            graph_nodes=g_nodes,
            graph_edges=g_edges,
            target_node_id=correlation_result["email_id"],
            seed_node_ids=g_seeds,
        )
    except Exception as diff_exc:
        graph_diffusion_result = {
            "available": False,
            "diffusion_score": None,
            "reason": f"diffusion execution exception: {diff_exc}",
            "hops_used": 3,
            "nearest_seed_distance": None,
            "contributing_seeds": [],
            "node_scores": {},
            "explanation": "Graph diffusion engine encountered an unexpected condition (failed open).",
        }

    email_summary = _build_email_summary(data)
    # Append OCR-extracted text from image attachments for Stage G evaluation
    ocr_snippets = []
    for att in (attachment_analysis.get("attachments") or []):
        text = (att.get("ocr_text") or "").strip()
        if text:
            fname = att.get("filename") or "attachment"
            ocr_snippets.append(f"\n\n[OCR from {fname}]:\n{text}")
    if ocr_snippets:
        existing_body = email_summary.get("body_text") or ""
        email_summary["body_text"] = existing_body + "".join(ocr_snippets)

    # Deterministic observed + reputation evidence, with stable ids. The model
    # sees these ids and must cite them; see evidence.py and ai_findings.
    evidence_ledger = build_evidence_ledger(
        headers=header_analysis,
        attachments=attachment_analysis.get("attachments") or [],
        iocs=ioc_analysis,
        threat_intel=threat_intel_analysis,
        correlation=correlation_result,
        input_mode=source,
        link_analysis=link_analysis,
        qr_trace=qr_trace,
    )

    context = {
        "email": email_summary,
        "header_forensics": header_analysis,
        "attachment_forensics": attachment_analysis,
        "iocs": ioc_analysis,
        "threat_intelligence": threat_intel_analysis,
        "correlation": correlation_result,
        "graph_diffusion": graph_diffusion_result,
        "evidence_ledger": compact_ledger(evidence_ledger),
    }

    progress("ai", "running")
    # Stage C' -- Fast Metadata Triage Pre-Filter (XGBoost)
    try:
        from ai_engine.triage_model import extract_features, predict_triage
        triage_features = extract_features(
            email=email_summary,
            header_analysis=header_analysis,
            attachment_analysis=attachment_analysis,
            iocs=ioc_analysis,
            threat_intel=threat_intel_analysis,
        )
        triage_result = predict_triage(triage_features)
    except Exception as triage_exc:
        triage_result = {"available": False, "label": None, "confidence": 0.0, "is_safe": False}

    triage_safe_threshold = float(os.getenv("TRIAGE_SAFE_THRESHOLD", "0.90"))
    gemini_skipped = False

    # Hackathon Fix: XGBoost only looks at metadata (headers, domains). 
    # If a scammer uses a clean Gmail account but puts a scam link in the body, 
    # XGBoost might falsely score it 99% safe and bypass Gemini.
    # We add a heuristic override to FORCE Gemini if risky keywords or links exist.
    force_gemini = False
    body_text = email_summary.get("body_text", "")
    # Never log message content, URLs or matched keywords: stdout goes to the
    # hosting platform's log store. Counts only.
    if body_text:
        body_lower = body_text.lower()
        risky_keywords = ["urgent", "won", "$", "prize", "password", "gift card", "tinyurl.com", "bit.ly", "login"]
        matched_count = sum(1 for k in risky_keywords if k in body_lower)
        logger.debug("heuristic: body_len=%d risky_keyword_hits=%d", len(body_text), matched_count)
        if matched_count:
            force_gemini = True

    if ioc_analysis.get("urls"):
        logger.debug("heuristic: %d url(s) found, forcing Gemini review", len(ioc_analysis["urls"]))
        force_gemini = True

    # A quick content check has no real headers, so the metadata-only XGBoost
    # pre-filter has nothing trustworthy to judge. Always do the content review.
    if quick_check:
        force_gemini = True

    # If any attachment is flagged suspicious (macros, type mismatch,
    # password-protected Office doc, disguised executable, QR codes, etc.),
    # force Gemini to review -- XGBoost metadata features don't capture
    # attachment content risk.
    for att in (attachment_analysis.get("attachments") or []):
        if att.get("suspicious"):
            logger.debug("heuristic: suspicious attachment present, forcing Gemini review")
            force_gemini = True
            break

    if (
        not force_gemini
        and triage_result.get("available")
        and triage_result.get("label") == 0
        and triage_result.get("confidence", 0.0) >= triage_safe_threshold
    ):
        gemini_skipped = True
        triage_risk = max(0, min(10, round((1.0 - triage_result["confidence"]) * 20)))
        triage_evidence = [
            "Passed Stage C' metadata triage with high confidence",
            "Authentication & infrastructure indicators consistent with benign traffic",
        ]
        if not threat_intel_live:
            triage_evidence.append(
                "External reputation lookups (VirusTotal, AbuseIPDB, WHOIS) were NOT performed: threat intelligence is offline"
            )
        final_assessment = {
            "verdict": LIKELY_LEGITIMATE,
            "risk_score": triage_risk,
            "confidence": triage_result["confidence"],
            "explanation": (
                f"Passed fast metadata triage pre-filter (XGBoost) with {round(triage_result['confidence'] * 100)}% "
                f"benign confidence. Deep generative AI interpretation bypassed to conserve latency and quota."
            ),
            "supporting_evidence": triage_evidence,
            "evidence_assessments": [],
            "mitre_attack": [],
            "recommended_actions": ["No action required. Deliver normally."],
            "provider": "xgboost_triage",
        }
        ai_analysis = {
            "content_classification": {
                "verdict": LIKELY_LEGITIMATE,
                "categories": [],
                "provider": "xgboost_triage",
                "content_risk_score": triage_risk,
                "confidence": triage_result["confidence"],
            },
            "final_assessment": final_assessment,
            "mitre_attack": [],
        }
    else:
        # B10: external Gemini receives a privacy-reduced copy. The original
        # context remains intact for the E-TAP report and IOC correlation.
        ai_analysis = analyze_with_stage_g(sanitize_for_external_ai(context))
        final_assessment = ai_analysis.get("final_assessment") or {}

    # One place decides the label, the score band and what clients should show.
    if gemini_skipped:
        progress("ai", "done", "Clearly benign metadata; AI review not needed")
    elif (final_assessment.get("provider") or "") == "offline_fallback":
        progress("ai", "done", "AI unavailable; offline assessment used")
    else:
        progress("ai", "done", "AI assessment complete")

    progress("verdict", "running")
    decision = finalize_verdict(final_assessment.get("verdict"), final_assessment.get("risk_score"))
    final_assessment["verdict"] = decision["verdict"]
    final_assessment["risk_score"] = decision["risk_score"]
    final_assessment["verdict_band"] = decision["verdict_band"]

    ti_total, ti_failed = _count_unavailable_lookups(threat_intel_analysis) if threat_intel_live else (0, 0)
    provider = final_assessment.get("provider") or "unknown"
    # Never send raw Google SDK exceptions to the browser; they may include
    # request details. ProviderStatus below carries the stable user-facing state.
    raw_fallback_reason = str(final_assessment.get("fallback_reason") or "").lower()
    if provider == "offline_fallback":
        if not os.getenv("GEMINI_API_KEY"):
            fallback_reason = "Gemini is not configured; the deterministic fallback was used."
        elif "404" in raw_fallback_reason or "not_found" in raw_fallback_reason or "not found" in raw_fallback_reason:
            fallback_reason = "Gemini model name not available for this key; the deterministic fallback was used."
        elif "timeout" in raw_fallback_reason or "deadline" in raw_fallback_reason:
            fallback_reason = "Gemini timed out; the deterministic fallback was used."
        elif "429" in raw_fallback_reason or "quota" in raw_fallback_reason or "rate limit" in raw_fallback_reason:
            fallback_reason = "Gemini rate or quota limits prevented analysis; the deterministic fallback was used."
        else:
            fallback_reason = "Gemini model attempts failed; the deterministic fallback was used."
    else:
        fallback_reason = None
    analysis_provenance = {
        "input_mode": source,
        "headers_available": not quick_check,
        "threat_intel_mode": "live" if threat_intel_live else "offline_placeholder",
        "threat_intel_lookups": ti_total,
        "threat_intel_unavailable": ti_failed,
        "assessment_provider": provider,
        "assessment_model": final_assessment.get("model"),
        "fallback_used": provider == "offline_fallback" or bool(fallback_reason),
        "fallback_reason": fallback_reason,
        "gemini_skipped_by_triage": gemini_skipped,
        "verdict_reconciled": decision["reconciled"],
        "verdict_original": decision["original_label"],
    }
    provider_status = build_provider_status(
        threat_intel=threat_intel_analysis,
        iocs=ioc_analysis,
        threat_intel_live=threat_intel_live,
        final_assessment=final_assessment,
        gemini_skipped=gemini_skipped,
    )
    analysis_provenance["provider_status_summary"] = provider_status["summary"]
    analysis_provenance["provider_coverage_status"] = provider_status["coverage_status"]
    # Never ship the raw exception text to clients; only stable provider states.
    final_assessment.pop("fallback_reason", None)
    (ai_analysis.get("content_classification") or {}).pop("fallback_reason", None)

    triage_summary = {
        "triage_label": triage_result.get("label"),
        "triage_confidence": triage_result.get("confidence"),
        "gemini_skipped": gemini_skipped,
        "available": triage_result.get("available", False),
    }
    evidence_report = build_evidence_report(
        decision=decision,
        final_assessment=final_assessment,
        content_classification=ai_analysis.get("content_classification"),
        headers=header_analysis,
        attachments=attachment_analysis.get("attachments") or [],
        iocs=ioc_analysis,
        threat_intel=threat_intel_analysis,
        correlation=correlation_result,
        triage=triage_summary,
        provenance=analysis_provenance,
        input_mode=source,
        link_analysis=link_analysis,
        qr_trace=qr_trace,
    )
    privacy_report = build_privacy_report(
        email=email_summary,
        iocs=ioc_analysis,
        threat_intel=threat_intel_analysis,
        provenance=analysis_provenance,
    )
    analysis_duration_ms = round((time.perf_counter() - started_at) * 1000)
    analysis_provenance["analysis_duration_ms"] = analysis_duration_ms
    provider_status["analysis_duration_ms"] = analysis_duration_ms

    stage_status = {
        "A": "complete",
        "B": "complete" if not quick_check else "headers_unavailable",
        "B2": "complete",
        "D": "complete",
        "E": "live" if threat_intel_live else "offline_placeholder",
        "F": "complete",
        "F_prime": "complete" if graph_diffusion_result.get("available") else "insufficient_data",
        "C_prime": "bypassed_gemini" if gemini_skipped else ("evaluated" if triage_result.get("available") else "offline"),
        "G": "skipped_by_triage" if gemini_skipped else provider,
        "H": "complete",
    }

    repository.update_analysis_fields(
        db,
        correlation_result["email_id"],
        {
            "analysis_provenance": analysis_provenance,
            "stage_status": stage_status,
            "verdict_band": decision["verdict_band"],
            "evidence_report": evidence_report,
            "link_analysis": link_analysis,
            "qr_trace": qr_trace,
            "privacy_report": privacy_report,
            "provider_status": provider_status,
            "content_analysis": ai_analysis.get("content_classification"),
            "final_assessment": final_assessment,
            "mitre_attack": ai_analysis.get("mitre_attack", []),
            "risk_score": final_assessment.get("risk_score"),
            "verdict": final_assessment.get("verdict"),
            "triage": {
                "triage_label": triage_result.get("label"),
                "triage_confidence": triage_result.get("confidence"),
                "gemini_skipped": gemini_skipped,
                "available": triage_result.get("available", False),
            },
            "graph_diffusion": graph_diffusion_result,
        },
    )

    result = {
        "email_id": correlation_result["email_id"],
        "risk_score": final_assessment.get("risk_score"),
        "verdict": final_assessment.get("verdict"),
        "verdict_band": decision["verdict_band"],
        "analysis_provenance": analysis_provenance,
        "evidence_report": evidence_report,
        "link_analysis": link_analysis,
        "qr_trace": qr_trace,
        "privacy_report": privacy_report,
        "provider_status": provider_status,
        "email": context["email"],
        "headers": header_analysis,
        "attachments": attachment_analysis.get("attachments", []),
        "iocs": ioc_analysis,
        "threat_intel": threat_intel_analysis,
        "correlation": correlation_result,
        "historical_correlation": correlation_result.get("historical_stats") or {},
        "category_status": correlation_result.get("category_status", "NEW_THREAT_CLUSTER"),
        "graph_diffusion": graph_diffusion_result,
        "ai_analysis": ai_analysis,
        "mitre_attack": ai_analysis.get("mitre_attack", []),
        "triage": {
            "triage_label": triage_result.get("label"),
            "triage_confidence": triage_result.get("confidence"),
            "gemini_skipped": gemini_skipped,
            "available": triage_result.get("available", False),
        },
        "stage_status": stage_status,
    }

    # Stage S -- dynamic attachment analysis (see sandbox/__init__.py).
    # Runs in the background; the report polls GET /sandbox/{id}.
    sandbox_status, stage_status["S"] = _submit_to_sandbox(
        correlation_result["email_id"], data.get("attachments") or [], attachment_analysis,
        _sb_backend, _sb_candidates, _sb_agent)
    result["sandbox"] = sandbox_status
    repository.update_analysis_fields(db, correlation_result["email_id"], {"stage_status": stage_status})

    # Fire-and-forget background persistence of RAG summary and vector embedding
    def _bg_persist_rag(email_id: str, doc_snapshot: dict):
        try:
            from rag.embeddings import build_summary, embed_text
            from db.schema import ANALYSES_COLLECTION
            rag_sum = build_summary(doc_snapshot)
            rag_vec = embed_text(rag_sum)
            # `db` is captured from the enclosing scope so the worker thread reuses the same handle.
            # No upsert: a deleted record must never be resurrected by this worker.
            repository.update_analysis_fields(db, email_id, {
                'rag_summary': rag_sum, 'rag_embedding': rag_vec,
            })
        except Exception:
            # Non-blocking defensive catch
            pass

    import threading
    threading.Thread(
        target=_bg_persist_rag,
        args=(correlation_result["email_id"], result),
        daemon=True,
    ).start()

    progress("verdict", "done", f"{decision['verdict']} ({decision['risk_score']}/100)")
    return _json_safe(result)


def analyze_email_file(path: str, source: str | None = None) -> dict:
    """Analyze one .eml/.msg file from disk."""
    parsed = parse_email(path)
    return _run_parsed_pipeline(parsed, source=source)


def analyze_email_upload(filename: str, raw_bytes: bytes, source: str | None = None, progress=None,
                         sandbox: dict | None = None) -> dict:
    """Analyze one uploaded .eml/.msg file from raw bytes."""
    progress = progress or _noop_progress
    progress("parse", "running")
    parsed = parse_email_from_upload(filename, raw_bytes)
    n_att = len(parsed.attachments or [])
    progress("parse", "done", f"Email read, {_plural(n_att, 'attachment')}")
    return _run_parsed_pipeline(parsed, source=source, progress=progress, sandbox=sandbox)
