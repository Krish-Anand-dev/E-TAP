"""
Stage G -- Gemini interpretation, final verdict, and MITRE ATT&CK mapping.

This module keeps the old Stage C content classifier's useful taxonomy but
moves AI interpretation to the end of the pipeline:

    content classification + full-evidence final assessment

When GEMINI_API_KEY is configured, both interpretation levels call Gemini.
When it is not configured, Stage G returns explicit offline fallback results
so the end-to-end pipeline remains runnable for local demos and tests.
"""

from __future__ import annotations

import json
import re
from typing import Any

from .main import analyze_email as gemini_content_analysis
from .main import calculate_content_risk
from .main import _get_gemini_client, DEFAULT_GEMINI_MODEL
from .prompts import SYSTEM_PROMPT
from .schemas import EmailAnalysis, FinalAssessment

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover - dotenv is optional for library import
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv()

import os


CATEGORY_WEIGHTS = {
    "Credential Phishing": 90,
    "General Phishing": 85,
    "Business Email Compromise (BEC)": 90,
    "Account Takeover / Account Compromise": 90,
    "Financial Fraud": 90,
    "Payment / Invoice Fraud": 90,
    "Impersonation": 80,
    "Malware Delivery": 95,
    "Ransomware": 100,
    "Malicious Attachment": 90,
    "Malicious Link / URL": 85,
    "Tech Support Scam": 70,
    "Investment / Cryptocurrency Scam": 75,
    "Advance-Fee Scam": 70,
    "Prize / Lottery Scam": 60,
    "Job / Recruitment Scam": 65,
    "Delivery / Shipping Scam": 65,
    "Refund / Payment Scam": 75,
    "CEO / Executive Fraud": 90,
    "Payroll / HR Fraud": 85,
    "Extortion / Sextortion": 85,
    "Blackmail / Threat Scam": 80,
    "Social Engineering": 75,
    "Data Theft / Data Exfiltration Attempt": 90,
    "Business Information Request": 65,
    "OAuth / Application Consent Phishing": 90,
    "MFA / Verification Code Phishing": 90,
    "Spam / Unwanted Commercial Email": 20,
    "Suspicious / Uncategorized": 50,
    "Other": 10,
}


def _model_to_dict(value: Any) -> dict:
    if hasattr(value, "model_dump"):
        return value.model_dump()
    if hasattr(value, "dict"):
        return value.dict()
    return dict(value)


def _safe_json(value: Any) -> str:
    return json.dumps(value, indent=2, default=str, ensure_ascii=False)


def _email_text(email: dict) -> str:
    return "\n".join(
        str(email.get(key) or "")
        for key in ("subject", "body_text", "body_html")
    )


def _has_any(text: str, terms: list[str]) -> bool:
    lowered = text.lower()
    return any(term in lowered for term in terms)


def _category(name: str) -> dict:
    return {"name": name, "weight": CATEGORY_WEIGHTS[name]}


def _offline_content_classification(email: dict) -> dict:
    """
    Deterministic content-only fallback used when Gemini is not configured.

    This is not a replacement for Gemini. It lets A -> B/B2 -> D -> E -> F
    -> G -> H be exercised locally while clearly marking the provider as
    offline_fallback.
    """
    text = _email_text(email)
    lowered = text.lower()
    categories: list[dict] = []
    indicators: list[str] = []
    reasons: list[str] = []

    if _has_any(lowered, ["password", "login", "credential", "verify your account", "sign in"]):
        categories.append(_category("Credential Phishing"))
        indicators.append("credential or login language")
    if _has_any(lowered, ["click here", "open the link", "visit http", "http://", "https://"]):
        categories.append(_category("Malicious Link / URL"))
        indicators.append("link-based call to action")
    if _has_any(lowered, ["urgent", "immediately", "within 24 hours", "final warning", "suspended"]):
        categories.append(_category("Social Engineering"))
        indicators.append("urgency or pressure language")
    if _has_any(lowered, ["invoice", "payment", "wire transfer", "bank account", "remittance"]):
        categories.append(_category("Payment / Invoice Fraud"))
        indicators.append("payment or invoice language")
    if _has_any(lowered, ["ceo", "chief executive", "gift card", "payroll", "hr department"]):
        categories.append(_category("Business Email Compromise (BEC)"))
        indicators.append("business impersonation language")
    if _has_any(lowered, ["attachment", "attached file", ".exe", ".scr", ".js", "enable macros"]):
        categories.append(_category("Malicious Attachment"))
        indicators.append("attachment execution language")

    if not categories and _has_any(lowered, ["free", "offer", "prize", "winner", "unsubscribe"]):
        categories.append(_category("Spam / Unwanted Commercial Email"))
        indicators.append("commercial or unsolicited language")

    if categories:
        verdict = "Suspicious"
        if any(c["weight"] >= 85 for c in categories):
            verdict = "Likely Malicious"
        reasons = [f"Detected {indicator} in the email content." for indicator in indicators]
        attack_type = categories[0]["name"]
        confidence = 0.62
    else:
        categories = [_category("Other")]
        verdict = "Likely Legitimate"
        attack_type = "No clear content threat"
        confidence = 0.45
        reasons = ["No strong phishing or scam language was detected by the offline classifier."]

    content_score = max(c["weight"] for c in categories)
    if verdict == "Likely Legitimate":
        content_score = min(content_score, 15)

    return {
        "content_verdict": verdict,
        "verdict": verdict,
        "content_risk_score": content_score,
        "confidence": confidence,
        "attack_type": attack_type,
        "categories": categories,
        "reasons": reasons,
        "suspicious_indicators": indicators,
        "provider": "offline_fallback",
        "status": "GEMINI_API_KEY not configured; used deterministic content fallback",
    }


def classify_email_content(email: dict) -> dict:
    """Level 1: content-only classification using Gemini when available."""
    try:
        analysis: EmailAnalysis = gemini_content_analysis(email)
    except Exception as exc:
        result = _offline_content_classification(email)
        result["fallback_reason"] = str(exc)
        return result

    result = _model_to_dict(analysis)
    result["verdict"] = result.get("content_verdict")
    result["content_risk_score"] = calculate_content_risk(analysis.categories)
    result["provider"] = "gemini"
    result["model"] = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    return result


def _count_malicious_threat_intel(threat_intel: dict) -> tuple[int, list[str]]:
    count = 0
    evidence: list[str] = []

    for section_name in ("ip_reputation", "domain_info", "url_reputation", "hash_reputation"):
        section = threat_intel.get(section_name) or {}
        if not isinstance(section, dict):
            continue
        for indicator, info in section.items():
            if not isinstance(info, dict):
                continue
            if info.get("malicious") is True:
                count += 1
                evidence.append(f"{section_name}: {indicator} marked malicious")
            malicious_engines = info.get("malicious_engine_count")
            if isinstance(malicious_engines, int) and malicious_engines > 0:
                count += 1
                evidence.append(f"{section_name}: {indicator} flagged by {malicious_engines} engines")
            age_days = info.get("age_days")
            if isinstance(age_days, int) and age_days < 30:
                evidence.append(f"domain_info: {indicator} is newly registered ({age_days} days old)")

    return count, evidence


def _attachment_evidence(attachment_analysis: dict) -> list[str]:
    evidence: list[str] = []
    for attachment in (attachment_analysis.get("attachments") or []):
        if not isinstance(attachment, dict):
            continue
        name = attachment.get("filename") or "attachment"
        if attachment.get("suspicious"):
            evidence.append(f"{name} marked suspicious by attachment forensics")
        if attachment.get("type_mismatch"):
            evidence.append(f"{name} has declared/actual file type mismatch")
        if attachment.get("has_macro"):
            evidence.append(f"{name} contains macros")
    return evidence


def _final_verdict(score: int) -> str:
    if score >= 85:
        return "HIGH-RISK PHISHING"
    if score >= 65:
        return "LIKELY PHISHING"
    if score >= 40:
        return "SUSPICIOUS"
    if score >= 20:
        return "LOW RISK"
    return "LIKELY LEGITIMATE"


def _build_mitre_mappings(
    content: dict,
    iocs: dict,
    attachment_analysis: dict,
) -> list[dict]:
    mappings: list[dict] = []
    category_names = {c.get("name") for c in content.get("categories", []) if isinstance(c, dict)}
    urls = iocs.get("urls") or []
    suspicious_attachments = _attachment_evidence(attachment_analysis)

    if urls and category_names & {"Credential Phishing", "General Phishing", "Malicious Link / URL"}:
        mappings.append({
            "technique": "T1566.002",
            "name": "Phishing: Spearphishing Link",
            "tactic": "Initial Access",
            "confidence": 0.82,
            "evidence": [
                "Email content contains phishing/link-based language",
                f"Extracted URL IOC(s): {', '.join(urls[:3])}",
            ],
        })

    if suspicious_attachments:
        mappings.append({
            "technique": "T1566.001",
            "name": "Phishing: Spearphishing Attachment",
            "tactic": "Initial Access",
            "confidence": 0.78,
            "evidence": suspicious_attachments[:3],
        })

    macro_evidence = [
        item for item in suspicious_attachments
        if re.search(r"\bmacro", item, flags=re.IGNORECASE)
    ]
    if macro_evidence:
        mappings.append({
            "technique": "T1204.002",
            "name": "User Execution: Malicious File",
            "tactic": "Execution",
            "confidence": 0.72,
            "evidence": macro_evidence[:3],
        })

    return mappings


def _offline_final_assessment(context: dict, content: dict) -> dict:
    email = context.get("email") or {}
    headers = context.get("header_forensics") or {}
    attachments = context.get("attachment_forensics") or {}
    iocs = context.get("iocs") or {}
    threat_intel = context.get("threat_intelligence") or {}
    correlation = context.get("correlation") or {}

    evidence_assessments: list[dict] = []
    supporting_evidence: list[str] = []

    content_score = int(content.get("content_risk_score") or 0)
    content_confidence = float(content.get("confidence") or 0.5)
    score = int(content_score * max(content_confidence, 0.35))
    if content_score >= 85 and content_confidence >= 0.55:
        score = max(score, 55)
    evidence_assessments.append({
        "source": "content_classification",
        "risk_score": content_score,
        "summary": content.get("verdict") or content.get("content_verdict") or "No content verdict",
        "evidence": content.get("reasons") or [],
    })
    supporting_evidence.extend(content.get("reasons") or [])

    header_flags = headers.get("red_flags") or []
    header_points = min(35, len(header_flags) * 6)
    if headers.get("reply_to_mismatch"):
        header_points += 10
    for auth_key in ("spf", "dkim", "dmarc"):
        if headers.get(auth_key) in {"fail", "softfail", "misaligned", "key_not_found"}:
            header_points += 8
    header_score = min(100, header_points * 2)
    score += min(35, header_points)
    if header_flags:
        supporting_evidence.append(f"Header red flags: {', '.join(header_flags[:6])}")
    evidence_assessments.append({
        "source": "header_forensics",
        "risk_score": header_score,
        "summary": f"{len(header_flags)} header red flag(s) found",
        "evidence": list(header_flags),
    })

    attachment_evidence = _attachment_evidence(attachments)
    attachment_points = min(35, len(attachment_evidence) * 12)
    score += attachment_points
    supporting_evidence.extend(attachment_evidence)
    evidence_assessments.append({
        "source": "attachment_forensics",
        "risk_score": min(100, attachment_points * 3),
        "summary": f"{len(attachment_evidence)} suspicious attachment finding(s)",
        "evidence": attachment_evidence,
    })

    ioc_evidence = []
    if iocs.get("urls"):
        ioc_evidence.append(f"{len(iocs.get('urls') or [])} URL IOC(s) extracted")
        score += min(12, 6 + len(iocs.get("urls") or []))
    if iocs.get("hashes"):
        ioc_evidence.append(f"{len(iocs.get('hashes') or [])} file hash IOC(s) extracted")
        score += min(10, 5 + len(iocs.get("hashes") or []))
    if iocs.get("ips") or iocs.get("domains"):
        ioc_evidence.append("Network/domain indicators extracted")
        score += min(8, len(iocs.get("ips") or []) + len(iocs.get("domains") or []))
    supporting_evidence.extend(ioc_evidence)
    evidence_assessments.append({
        "source": "ioc_extraction",
        "risk_score": min(100, len(ioc_evidence) * 25),
        "summary": "IOC extraction completed",
        "evidence": ioc_evidence,
    })

    malicious_count, ti_evidence = _count_malicious_threat_intel(threat_intel)
    score += min(35, malicious_count * 18 + len(ti_evidence) * 3)
    supporting_evidence.extend(ti_evidence)
    evidence_assessments.append({
        "source": "threat_intelligence",
        "risk_score": min(100, malicious_count * 35 + len(ti_evidence) * 10),
        "summary": f"{malicious_count} malicious reputation finding(s)",
        "evidence": ti_evidence,
    })

    related_count = len(correlation.get("related_emails") or [])
    shared_count = len(correlation.get("shared_infrastructure") or [])
    correlation_evidence = []
    if related_count:
        correlation_evidence.append(f"{related_count} related historical email(s)")
    if shared_count:
        correlation_evidence.append(
            f"Shared infrastructure: {', '.join((correlation.get('shared_infrastructure') or [])[:5])}"
        )
    if correlation.get("campaign_id"):
        correlation_evidence.append(f"Assigned to {correlation['campaign_id']}")
    score += min(18, related_count * 6 + shared_count * 4)
    supporting_evidence.extend(correlation_evidence)
    evidence_assessments.append({
        "source": "correlation",
        "risk_score": min(100, related_count * 30 + shared_count * 20),
        "summary": "Historical correlation completed",
        "evidence": correlation_evidence,
    })

    score = max(0, min(100, score))
    verdict = _final_verdict(score)
    mitre = _build_mitre_mappings(content, iocs, attachments)
    explanation = (
        f"Offline final assessment produced {verdict} with score {score}. "
        "The score is driven by content classification plus technical evidence, "
        "including headers, attachments, IOCs, threat intelligence, and correlation."
    )

    if not supporting_evidence:
        supporting_evidence = ["No strong malicious evidence was collected across the pipeline."]

    return {
        "verdict": verdict,
        "risk_score": score,
        "confidence": 0.65 if score >= 40 else 0.5,
        "explanation": explanation,
        "evidence_assessments": evidence_assessments,
        "supporting_evidence": supporting_evidence,
        "mitre_attack": mitre,
        "recommended_actions": [
            "Review extracted URLs and attachments before user release.",
            "Confirm external reputation with live API keys before production decisions.",
        ] if score >= 40 else ["No immediate action required beyond normal monitoring."],
        "provider": "offline_fallback",
        "status": "GEMINI_API_KEY not configured; used deterministic final-assessment fallback",
        "email_subject": email.get("subject"),
    }


FINAL_ASSESSMENT_PROMPT = """
You are the final cybersecurity decision engine for an email analysis
pipeline. You receive the original email content plus completed technical
evidence from header forensics, attachment forensics, IOC extraction,
threat intelligence, historical correlation, and a separate content-only
classification.

Make the final verdict from ALL available evidence. Do not base it only on
the body text, and do not average unrelated scores mechanically. Weigh
malicious technical evidence, authentication failures, suspicious content,
attachments, IOC reputation, and historical correlation according to their
security significance.

Map MITRE ATT&CK techniques only when directly supported by observed
evidence. Use real technique IDs/names. If evidence is insufficient, return
an empty MITRE list rather than guessing.
"""


def _gemini_final_assessment(context: dict, content: dict) -> dict:
    client = _get_gemini_client()
    model = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    response = client.models.generate_content(
        model=model,
        contents=f"""
{FINAL_ASSESSMENT_PROMPT}

Content-only classification:
{_safe_json(content)}

Complete evidence context:
{_safe_json(context)}
""",
        config={
            "response_mime_type": "application/json",
            "response_schema": FinalAssessment,
        },
    )
    assessment = FinalAssessment.model_validate_json(response.text)
    result = _model_to_dict(assessment)
    result["provider"] = "gemini"
    result["model"] = model
    return result


def interpret_evidence(context: dict, content_classification: dict) -> dict:
    """Level 2: final decision and MITRE mapping over the complete evidence set."""
    try:
        return _gemini_final_assessment(context, content_classification)
    except Exception as exc:
        result = _offline_final_assessment(context, content_classification)
        result["fallback_reason"] = str(exc)
        return result


# Models tried in order for the combined Stage G call. The first entry is
# whatever GEMINI_MODEL is set to (or DEFAULT_GEMINI_MODEL); the rest are
# fallbacks tried only if an earlier model fails.
#
# Why a model-fallback chain instead of retrying the SAME model 3x with
# sleeps: the newest Gemini 3.x flash models (3.7/3.8) have had widespread,
# well-documented 503 "high demand" issues industry-wide -- retrying the
# same overloaded model repeatedly mostly just waits out the SAME capacity
# problem 3 times (slow, and often still fails). A different model is
# usually NOT experiencing the same capacity issue, so trying it once is
# both faster and more likely to actually succeed than sleeping and
# retrying the original model.
#
# Fallback order is Lite-first, not "most similar to primary" first:
# Lite variants have ~500/day quota (vs 20/day for full Flash models) and
# are 4-6x faster (p50 latency ~0.4-0.7s vs ~1.3-3s for full Flash, per
# OpenRouter benchmarks) -- when a fallback fires, something already went
# wrong, so speed and headroom matter more at that point than squeezing
# out marginally better reasoning quality on a model that's just as
# quota-starved as the primary.
#
# Verified live models: lite variants offer high daily quota and ultra-low latency,
# with gemini-3.6-flash as a powerful fallback before offline heuristics.
FALLBACK_MODELS = [
    "gemini-3.5-flash-lite",
    "gemini-flash-lite-latest",
    "gemini-3.1-flash-lite",
    "gemini-3.6-flash",
]


def _candidate_models() -> list[str]:
    primary = os.getenv("GEMINI_MODEL", DEFAULT_GEMINI_MODEL)
    chain = [primary] + [m for m in FALLBACK_MODELS if m != primary]
    return chain


COMBINED_ASSESSMENT_PROMPT = f"""
{SYSTEM_PROMPT}

{FINAL_ASSESSMENT_PROMPT}

You will produce BOTH outputs from ONE analysis pass:

1. "content_classification" -- the content-only classification described
   above, using ONLY the email's subject/body/HTML. Do not let the
   technical evidence below influence this part; it must reflect what the
   message content alone would suggest to a reader with no other context.

2. "final_assessment" -- the full-evidence final verdict described above,
   which DOES use everything: the content classification you just produced,
   plus header forensics, attachment forensics, IOCs, threat intelligence,
   and historical correlation.

Keep the two outputs internally consistent with each other (final_assessment
should reference/build on content_classification, not contradict it for no
reason), but do not simply copy one into the other -- they serve different
purposes and evaluate different scopes of evidence.
"""


def _gemini_combined_analysis(context: dict) -> tuple["CombinedAssessment", str]:
    from .schemas import CombinedAssessment  # local import: keeps top-level import list unchanged for existing callers

    client = _get_gemini_client()
    email = context.get("email") or {}

    subject = email.get("subject", "")
    body_text = email.get("body_text", "")
    body_html = email.get("body_html")

    email_content = f"""
Subject:
{subject}

Body Text:
{body_text}

Body HTML:
{body_html if body_html else "Not available"}
"""

    contents = f"""
{COMBINED_ASSESSMENT_PROMPT}

Email content (for content_classification ONLY):
{email_content}

Complete evidence context (for final_assessment):
{_safe_json(context)}
"""

    last_error: Exception | None = None
    for model in _candidate_models():
        try:
            response = client.models.generate_content(
                model=model,
                contents=contents,
                config={
                    "response_mime_type": "application/json",
                    "response_schema": CombinedAssessment,
                },
            )
            return CombinedAssessment.model_validate_json(response.text), model
        except Exception as exc:
            last_error = exc
            print(f"Gemini model '{model}' failed, trying next fallback: {exc}")
            continue

    raise last_error


def analyze_with_stage_g(context: dict) -> dict:
    """
    Run both Stage G interpretation levels in a SINGLE Gemini call when
    live (halves quota usage vs. calling classify_email_content() and
    interpret_evidence() separately), trying a short chain of fallback
    models before giving up -- see FALLBACK_MODELS above. Falls back to
    the existing two-step offline logic unchanged if every model in the
    chain fails (missing key, network, rate limit, schema validation
    failure, etc).
    """
    try:
        combined, model_used = _gemini_combined_analysis(context)

        content = _model_to_dict(combined.content_classification)
        content["verdict"] = content.get("content_verdict")
        content["content_risk_score"] = calculate_content_risk(combined.content_classification.categories)
        content["provider"] = "gemini"
        content["model"] = model_used

        final = _model_to_dict(combined.final_assessment)
        final["provider"] = "gemini"
        final["model"] = model_used

        return {
            "content_classification": content,
            "final_assessment": final,
            "mitre_attack": final.get("mitre_attack", []),
        }
    except Exception as exc:
        # Same fallback chain as before the merge -- unchanged behavior,
        # unchanged output shape, just reached via a different path.
        content = _offline_content_classification(context.get("email") or {})
        content["fallback_reason"] = str(exc)
        final = _offline_final_assessment(context, content)
        final["fallback_reason"] = str(exc)
        return {
            "content_classification": content,
            "final_assessment": final,
            "mitre_attack": final.get("mitre_attack", []),
        }
