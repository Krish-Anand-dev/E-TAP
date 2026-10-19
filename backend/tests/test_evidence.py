"""
B1/B9 evidence model tests (no network, no API keys).

    cd backend && python tests/test_evidence.py
"""
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from evidence import (
    GROUND_EVIDENCE,
    GROUND_UNGROUNDED,
    STATE_HIGH_RISK,
    STATE_NONE_FOUND,
    STATE_UNCERTAIN,
    build_evidence_ledger,
    build_evidence_report,
    build_for_stored_record,
    compact_ledger,
)
from verdicts import finalize_verdict


OFFLINE_TI = {"lookup_mode": "offline_placeholder", "url_reputation": {}, "ip_reputation": {}}


def _live_ti(**sections):
    base = {"lookup_mode": "live", "url_reputation": {}, "ip_reputation": {}, "domain_info": {}, "hash_reputation": {}}
    base.update(sections)
    return base


def _report(label="Suspicious", score=45, **kw):
    decision = finalize_verdict(label, score)
    kw.setdefault("headers", {"available": True, "spf": "pass", "dkim": "pass", "dmarc": "pass", "red_flags": []})
    kw.setdefault("threat_intel", _live_ti())
    kw.setdefault("final_assessment", {"provider": "gemini", "confidence": 0.9, "explanation": "x"})
    return build_evidence_report(decision=decision, **kw)


def _by_id(report):
    return {i["id"]: i for i in report["evidence"]}


# --- unknown is never safe --------------------------------------------------

def test_quick_check_with_offline_ti_is_not_called_safe():
    r = _report(
        "Likely Legitimate", 5,
        headers={"available": False, "spf": "not_available", "dkim": "not_available",
                 "dmarc": "not_available", "red_flags": [], "unavailable_reason": "no headers"},
        threat_intel=OFFLINE_TI,
        iocs={"urls": ["http://a.example/x?token=SECRET"]},
        input_mode="quick_content_check",
        final_assessment={"provider": "gemini", "confidence": 0.9},
    )
    ev = _by_id(r)
    assert ev["hdr.auth"]["status"] == "unavailable"
    assert ev["att.scope"]["status"] == "unavailable"
    assert ev["link.scope"]["status"] == "unavailable"
    assert ev["rep.offline"]["status"] == "unavailable"
    assert r["conclusion"]["evidence_state"] == STATE_NONE_FOUND
    assert "not a guarantee" in r["conclusion"]["state_text"].lower()
    assert len(r["conclusion"]["limitations"]) >= 3
    assert r["conclusion"]["confidence_level"] == "low", r["conclusion"]
    text = (r["headline"] + " " + json.dumps(r["what_to_do"])).lower()
    assert "is safe" not in text and "no action required" not in text
    # query strings (tokens) never reach the displayed evidence
    assert "SECRET" not in json.dumps(r)


def test_unavailable_items_never_push_the_verdict():
    r = _report(threat_intel=OFFLINE_TI, input_mode="quick_content_check")
    for it in r["evidence"]:
        if it["status"] == "unavailable":
            assert it["direction"] == "neutral"
    assert all(i not in r["top_reasons"] for i in r["sections"]["not_checked"])


def test_vt_failure_is_unavailable_not_clean():
    ti = _live_ti(url_reputation={
        "http://a.example/": {"malicious": None, "status": "rate_limited", "error": "VirusTotal rate limit hit"},
        "http://b.example/": {"malicious": None, "status": "error", "error": "failed"},
    })
    ev = _by_id(_report(threat_intel=ti, iocs={"urls": ["http://a.example/", "http://b.example/"]}))
    assert ev["rep.url.unavailable"]["status"] == "unavailable"
    assert "rep.url.clean" not in ev
    assert "2 URL lookups unavailable" in ev["rep.url.unavailable"]["title"]


def test_vt_no_record_is_unknown_not_clean():
    ti = _live_ti(url_reputation={"http://a.example/": {"malicious": None, "status": "not previously scanned by VirusTotal"}})
    ev = _by_id(_report(threat_intel=ti))
    assert ev["rep.url.unseen"]["status"] == "unavailable"
    assert "rep.url.clean" not in ev


def test_clean_reputation_is_weak_and_hedged():
    ti = _live_ti(url_reputation={"http://a.example/": {"malicious": False, "malicious_engine_count": 0, "total_engines": 70}})
    it = _by_id(_report(threat_intel=ti))["rep.url.clean"]
    assert it["direction"] == "lowers_risk" and it["weight"] == "weak"
    assert "not prove" in it["why"].lower() or "does not prove" in it["why"].lower()


def test_low_count_detection_is_weak_high_count_strong():
    ti = _live_ti(url_reputation={
        "http://one.example/": {"malicious": True, "malicious_engine_count": 1, "total_engines": 70},
        "http://many.example/": {"malicious": True, "malicious_engine_count": 14, "total_engines": 70},
    })
    ev = _by_id(_report("Likely Phishing", 70, threat_intel=ti))
    weights = sorted(i["weight"] for k, i in ev.items() if k.startswith("rep.url.flagged."))
    assert weights == ["strong", "weak"], weights


def test_private_ip_is_unavailable_not_clean():
    ti = _live_ti(ip_reputation={"10.0.0.1": {"malicious": False, "status": "private_or_reserved", "error": "blocked"}})
    ev = _by_id(_report(threat_intel=ti))
    assert ev["rep.ip.unavailable"]["status"] == "unavailable"
    assert "rep.ip.clean" not in ev


# --- headers ---------------------------------------------------------------

def test_auth_pass_does_not_claim_safety():
    ev = _by_id(_report())
    assert ev["hdr.auth"]["direction"] == "lowers_risk" and ev["hdr.auth"]["weight"] == "weak"
    assert "does not show" in ev["hdr.auth"]["why"]


def test_auth_fail_is_strong_and_flags_are_not_duplicated():
    r = _report(
        "Likely Phishing", 80,
        headers={"available": True, "spf": "fail", "dkim": "pass", "dmarc": "fail",
                 "red_flags": ["spf_fail", "dmarc_fail", "reply_to_domain_mismatch", "lookalike_of_paypal"]},
    )
    ev = _by_id(r)
    assert ev["hdr.auth"]["direction"] == "raises_risk" and ev["hdr.auth"]["weight"] == "strong"
    assert not any(k.startswith("hdr.flag.spf") or k.startswith("hdr.flag.dmarc") for k in ev)
    assert ev["hdr.flag.lookalike_of_paypal"]["weight"] == "strong"
    assert ev["hdr.flag.reply_to_domain_mismatch"]["weight"] == "weak"
    assert r["conclusion"]["evidence_state"] == STATE_HIGH_RISK
    assert r["top_reasons"] and ev[r["top_reasons"][0]]["weight"] == "strong"


# --- attachments -----------------------------------------------------------

def test_attachment_findings_and_static_only_wording():
    atts = [
        {"filename": "inv.docm", "has_macro": True, "type_mismatch": False, "suspicious": True,
         "sha256": "ab" * 32, "flags": []},
        {"filename": "ok.pdf", "has_macro": False, "type_mismatch": False, "suspicious": False, "flags": []},
    ]
    r = _report("Likely Phishing", 70, attachments=atts)
    ev = _by_id(r)
    assert ev["att.0.macro"]["direction"] == "raises_risk"
    assert ev["att.1.clean"]["direction"] == "neutral"
    assert "not opened or run" in ev["att.1.clean"]["detail"]
    steps = [s["text"] for s in r["what_to_do"]["steps"]]
    assert any("inv.docm" in t for t in steps)
    assert not any("ok.pdf" in t for t in steps)


# --- AI grounding ------------------------------------------------------------

def test_ai_findings_grounded_vs_ungrounded():
    fa = {
        "provider": "gemini", "model": "m", "confidence": 0.8, "explanation": "Looks like phishing.",
        "ai_findings": [
            {"claim": "Sender authentication failed", "why_it_matters": "Sender may be forged",
             "direction": "raises_risk", "evidence_ids": ["hdr.auth", "does.not.exist"]},
            {"claim": "The link is surely safe", "why_it_matters": "n/a",
             "direction": "lowers_risk", "evidence_ids": ["made.up.id"]},
            {"claim": "Odd direction value", "why_it_matters": "n/a", "direction": "bogus", "evidence_ids": []},
        ],
    }
    r = _report(
        "Likely Phishing", 75,
        headers={"available": True, "spf": "fail", "dkim": "pass", "dmarc": "pass", "red_flags": []},
        final_assessment=fa,
    )
    ev = _by_id(r)
    assert ev["ai.finding.0"]["grounding"] == GROUND_EVIDENCE
    assert ev["ai.finding.0"]["evidence_ids"] == ["hdr.auth"]  # invalid id dropped
    assert ev["ai.finding.1"]["grounding"] == GROUND_UNGROUNDED
    assert ev["ai.finding.2"]["direction"] == "neutral"
    # an ungrounded claim can never become a headline reason, even if it lowers risk
    assert "ai.finding.1" not in r["top_reasons"] + r["contradicting"]
    assert r["counts"]["ungrounded_ai"] == 2
    assert r["ai_summary"]["text"] == "Looks like phishing."


def test_offline_fallback_does_not_echo_its_own_evidence():
    fa = {
        "provider": "offline_fallback", "confidence": 0.62,
        "explanation": "Offline final assessment produced X",
        "supporting_evidence": ["Header red flags: spf_fail", "1 URL IOC(s) extracted"],
        "recommended_actions": ["Review extracted URLs"],
    }
    cc = {"provider": "offline_fallback", "verdict": "Suspicious", "reasons": ["Detected urgency or pressure language in the email content."]}
    r = _report("Suspicious", 50, final_assessment=fa, content_classification=cc,
                provenance={"fallback_used": True})
    assert r["ai_summary"] is None
    assert r["what_to_do"]["ai_suggestions"] == []
    titles = [i["title"] for i in r["evidence"] if i["kind"] == "ai_inferred"]
    assert titles == ["Detected urgency or pressure language in the email content."]
    src = [i["source"] for i in r["evidence"] if i["kind"] == "ai_inferred"]
    assert src == ["offline_heuristic"]
    assert any("offline check" in l for l in r["conclusion"]["limitations"])


def test_triage_bypass_is_described_as_metadata_only():
    fa = {"provider": "xgboost_triage", "confidence": 0.95, "explanation": "bypassed"}
    r = _report("Likely Legitimate", 2, final_assessment=fa,
                triage={"gemini_skipped": True, "triage_confidence": 0.95})
    it = _by_id(r)["ai.triage"]
    assert "metadata" in it["detail"].lower() and it["direction"] == "lowers_risk"
    assert any("skipped" in l for l in r["conclusion"]["limitations"])


# --- what to do / headline ---------------------------------------------------

def test_what_to_do_by_band_is_conservative():
    danger = _report("Likely Phishing", 80)["what_to_do"]["steps"]
    txt = " ".join(s["text"] for s in danger).lower()
    assert "do not click" in txt and "official website" in txt
    assert "infected" not in txt  # never claims compromise
    assert "does not necessarily mean" in txt

    caution = " ".join(s["text"] for s in _report("Suspicious", 45)["what_to_do"]["steps"]).lower()
    assert "separate, trusted channel" in caution

    safe = " ".join(s["text"] for s in _report("Low Risk", 10)["what_to_do"]["steps"]).lower()
    assert "not proof of safety" in safe


def test_ai_suggestion_cannot_say_no_action_when_risky():
    fa = {"provider": "gemini", "confidence": 0.9, "recommended_actions": ["No action required.", "Report to IT."]}
    r = _report("Likely Phishing", 80, final_assessment=fa)
    assert r["what_to_do"]["ai_suggestions"] == ["Report to IT."]


def test_caution_band_without_reasons_says_so():
    r = _report("Suspicious", 45)
    assert r["top_reasons"] == []
    assert "no single strong indicator" in r["headline"].lower()
    assert r["conclusion"]["evidence_state"] == STATE_UNCERTAIN


# --- structure ----------------------------------------------------------------

def test_payload_is_json_safe_with_unique_ids_and_resolving_sections():
    r = _report(
        "Likely Phishing", 80,
        attachments=[{"filename": "a.exe", "type_mismatch": True, "declared_type": "pdf", "actual_type": "exe"}],
        iocs={"urls": ["http://x.example/p"]},
        correlation={"related_emails": [1, 2], "shared_infrastructure": ["x.example"], "campaign_id": "C-1"},
        threat_intel=_live_ti(url_reputation={"http://x.example/p": {"malicious": True, "malicious_engine_count": 9, "total_engines": 70}},
                              domain_info={"x.example": {"age_days": 3}}),
    )
    json.dumps(r)
    ids = [i["id"] for i in r["evidence"]]
    assert len(ids) == len(set(ids))
    known = set(ids)
    for section in r["sections"].values():
        assert set(section) <= known
    assert set(r["top_reasons"]) <= known and set(r["contradicting"]) <= known
    assert r["schema_version"] == 2 and r["reconstructed"] is False
    assert all(it["status"] in ("present", "absent", "unavailable") for it in r["evidence"])
    assert all(it["kind"] in ("observed", "reputation", "ai_inferred") for it in r["evidence"])
    assert _by_id(r)["rep.domain.young.0"]["direction"] == "raises_risk"


def test_ledger_is_deterministic_and_compact_view_keeps_ids():
    kw = dict(headers={"available": True, "spf": "pass", "dkim": "pass", "dmarc": "pass", "red_flags": []},
              iocs={"urls": ["http://x.example/"]}, threat_intel=OFFLINE_TI)
    a, b = build_evidence_ledger(**kw), build_evidence_ledger(**kw)
    assert a == b
    assert [c["id"] for c in compact_ledger(a)] == [i["id"] for i in a]


def test_rebuild_for_old_record_is_marked_reconstructed():
    doc = {
        "header_analysis": {"spf": "fail", "dkim": "pass", "dmarc": "pass", "red_flags": ["spf_fail"]},
        "attachment_analysis": {"attachments": []},
        "ioc_analysis": {"urls": []},
        "threat_intel_analysis": {},  # old record, nothing stored
        "final_assessment": {"provider": "gemini", "confidence": 0.7, "supporting_evidence": ["Sender failed SPF"]},
        "triage": {},
    }
    r = build_for_stored_record(doc, finalize_verdict("Suspicious", 50))
    assert r["reconstructed"] is True
    ev = _by_id(r)
    assert ev["rep.none"]["status"] == "unavailable"
    assert ev["ai.finding.0"]["grounding"] == GROUND_UNGROUNDED
    json.dumps(r)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS:", name)
    print("All evidence tests passed.")
