"""
End-to-end Threat Email Analysis pipeline.

This is the shared Stage H assembly layer used by both the CLI runner and
the HTTP API. It keeps one canonical A -> B/B2 -> D -> E -> F -> G flow.
"""

from __future__ import annotations

import os
from datetime import date, datetime
from typing import Any

from email_parser import parse_email, parse_email_from_upload
from forensics.header_forensics import analyze_headers
from forensics.attachment_forensics import analyze_attachments
from forensics.ioc_extraction import extract_iocs
from threat_intel import enrich_iocs
from correlation import correlate_and_store
from db import connection, repository
from ai_engine.stage_g import analyze_with_stage_g


def _env_truthy(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


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


def _run_parsed_pipeline(parsed_email) -> dict:
    db = connection.get_db()
    data = parsed_email.to_dict()

    header_analysis = analyze_headers(parsed_email)
    attachment_analysis = analyze_attachments(data.get("attachments") or [])
    ioc_analysis = extract_iocs(
        all_headers=data.get("all_headers"),
        body_text=data.get("body_text"),
        body_html=data.get("body_html"),
        attachment_analysis=attachment_analysis,
        header_analysis=header_analysis,
    )

    threat_intel_live = _env_truthy("THREAT_INTEL_LIVE", default="0")
    threat_intel_analysis = enrich_iocs(ioc_analysis, live_lookup=threat_intel_live)

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

    context = {
        "email": email_summary,
        "header_forensics": header_analysis,
        "attachment_forensics": attachment_analysis,
        "iocs": ioc_analysis,
        "threat_intelligence": threat_intel_analysis,
        "correlation": correlation_result,
        "graph_diffusion": graph_diffusion_result,
    }

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
    print(f"\n[DEBUG Heuristic] Extracted Body Length: {len(body_text) if body_text else 0}")
    if body_text:
        body_lower = body_text.lower()
        risky_keywords = ["urgent", "won", "$", "prize", "password", "gift card", "tinyurl.com", "bit.ly", "login"]
        matched_words = [k for k in risky_keywords if k in body_lower]
        print(f"[DEBUG Heuristic] Matched risky words: {matched_words}")
        if matched_words:
            force_gemini = True
            
    if ioc_analysis.get("urls"):
        print(f"[DEBUG Heuristic] URLs found: {ioc_analysis.get('urls')}")
        force_gemini = True

    if (
        not force_gemini
        and triage_result.get("available")
        and triage_result.get("label") == 0
        and triage_result.get("confidence", 0.0) >= triage_safe_threshold
    ):
        gemini_skipped = True
        triage_risk = max(0, min(10, round((1.0 - triage_result["confidence"]) * 20)))
        final_assessment = {
            "verdict": "Likely Legitimate",
            "risk_score": triage_risk,
            "confidence": triage_result["confidence"],
            "explanation": (
                f"Passed fast metadata triage pre-filter (XGBoost) with {round(triage_result['confidence'] * 100)}% "
                f"benign confidence. Deep generative AI interpretation bypassed to conserve latency and quota."
            ),
            "supporting_evidence": [
                "Passed Stage C' metadata triage with high confidence",
                "Authentication & infrastructure indicators consistent with benign traffic",
            ],
            "evidence_assessments": [],
            "mitre_attack": [],
            "recommended_actions": ["No action required. Deliver normally."],
            "provider": "xgboost_triage",
        }
        ai_analysis = {
            "content_classification": {
                "verdict": "Likely Legitimate",
                "categories": [],
                "provider": "xgboost_triage",
                "content_risk_score": triage_risk,
                "confidence": triage_result["confidence"],
            },
            "final_assessment": final_assessment,
            "mitre_attack": [],
        }
    else:
        ai_analysis = analyze_with_stage_g(context)
        final_assessment = ai_analysis.get("final_assessment") or {}

    repository.update_analysis_fields(
        db,
        correlation_result["email_id"],
        {
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
        "stage_status": {
            "A": "complete",
            "B": "complete",
            "B2": "complete",
            "D": "complete",
            "E": "live" if threat_intel_live else "offline_placeholder",
            "F": "complete",
            "F_prime": "complete" if graph_diffusion_result.get("available") else "insufficient_data",
            "C_prime": "bypassed_gemini" if gemini_skipped else ("evaluated" if triage_result.get("available") else "offline"),
            "G": "skipped_by_triage" if gemini_skipped else final_assessment.get("provider", "unknown"),
            "H": "complete",
        },
    }

    # Fire-and-forget background persistence of RAG summary and vector embedding
    def _bg_persist_rag(email_id: str, doc_snapshot: dict):
        try:
            from rag.embeddings import build_summary, embed_text
            from db.schema import ANALYSES_COLLECTION
            rag_sum = build_summary(doc_snapshot)
            rag_vec = embed_text(rag_sum)
            active_db = connection.get_db()
            for coll_name in (ANALYSES_COLLECTION, "emails"):
                try:
                    active_db[coll_name].update_one(
                        {"$or": [{"email_id": email_id}, {"_id": email_id}]},
                        {"$set": {"rag_summary": rag_sum, "rag_embedding": rag_vec}},
                    )
                except Exception:
                    pass
        except Exception:
            # Non-blocking defensive catch
            pass

    import threading
    threading.Thread(
        target=_bg_persist_rag,
        args=(correlation_result["email_id"], result),
        daemon=True,
    ).start()

    return _json_safe(result)


def analyze_email_file(path: str) -> dict:
    """Analyze one .eml/.msg file from disk."""
    parsed = parse_email(path)
    return _run_parsed_pipeline(parsed)


def analyze_email_upload(filename: str, raw_bytes: bytes) -> dict:
    """Analyze one uploaded .eml/.msg file from raw bytes."""
    parsed = parse_email_from_upload(filename, raw_bytes)
    return _run_parsed_pipeline(parsed)
