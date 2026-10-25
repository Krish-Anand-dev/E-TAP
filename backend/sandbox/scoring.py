"""
sandbox.scoring — Risk score adjustment that can only RAISE, never lower.
=========================================================================
"""

from __future__ import annotations

import logging

logger = logging.getLogger("E-TAP.sandbox.scoring")

# Verdict strings used by E-TAP (from stage_g.py)
VERDICT_LIKELY_MALICIOUS = "Likely Malicious"
VERDICT_LIKELY_LEGITIMATE = "Likely Legitimate"
VERDICT_SUSPICIOUS = "Suspicious"


def apply_sandbox(doc_fields: dict, sandbox: dict) -> dict:
    """
    Update risk_score, verdict, final_assessment, and mitre_attack
    based on sandbox results. NEVER lowers risk_score.

    Args:
        doc_fields: Current document fields:
            - risk_score: int (0-100)
            - verdict: str
            - final_assessment: dict
            - mitre_attack: list
        sandbox: The sandbox_analysis document.

    Returns:
        dict with updated fields to $set in MongoDB.
    """
    current_score = doc_fields.get("risk_score") or 0
    current_verdict = doc_fields.get("verdict") or ""
    current_assessment = doc_fields.get("final_assessment") or {}
    current_mitre = list(doc_fields.get("mitre_attack") or [])

    items = sandbox.get("items") or []
    if not items:
        return {}

    # Collect all rule matches across all items
    all_matches = []
    for item in items:
        for match in item.get("matches") or []:
            all_matches.append(match)

    if not all_matches:
        # No rules matched — mark as inconclusive, don't change score
        logger.info("Sandbox: no rule matches; score unchanged at %d", current_score)
        return {
            "sandbox_analysis": {**sandbox, "verdict": (
                "inspection_incomplete" if sandbox.get("status") in {"error", "partial"}
                else "no_behavior_observed_inconclusive"
            )},
        }

    # Determine new score floor
    has_prevention = any(m.get("prevention_grade") for m in all_matches)
    if has_prevention:
        new_floor = 85
    else:
        new_floor = 65

    new_score = max(current_score, new_floor)

    # Build evidence lines
    evidence_lines = []
    new_mitre = list(current_mitre)
    seen_techniques = {m.get("technique") for m in current_mitre}

    for match in all_matches:
        rule_name = match.get("rule", "Unknown Rule")
        rule_id = match.get("rule_id", "")
        mitre_list = match.get("mitre") or []
        prevention = " [PREVENTION-GRADE]" if match.get("prevention_grade") else ""

        tech_ids = []
        for m in mitre_list:
            tech = m.get("technique", "")
            tech_ids.append(tech)
            if tech and tech not in seen_techniques:
                new_mitre.append({
                    "tactic": m.get("tactic", ""),
                    "technique": tech,
                    "name": m.get("name", ""),
                    "source": "sandbox",
                })
                seen_techniques.add(tech)

        evidence_lines.append(
            f"Sandbox rule triggered: {rule_name} ({rule_id}){prevention}"
            + (f" — MITRE {', '.join(tech_ids)}" if tech_ids else "")
        )

    # Canonical label: the more severe of the existing label and the raised
    # score (verdicts.finalize_verdict), so the label can only go up too.
    from verdicts import finalize_verdict
    decision = finalize_verdict(current_verdict or None, new_score)
    new_verdict = decision["verdict"]

    # Build updated final_assessment
    existing_evidence = list(current_assessment.get("supporting_evidence") or [])
    updated_assessment = {
        **current_assessment,
        "supporting_evidence": existing_evidence + evidence_lines,
    }
    if new_score > current_score:
        updated_assessment["risk_score"] = new_score
    if new_verdict != current_verdict:
        updated_assessment["verdict"] = new_verdict

    # Build recommended action
    if has_prevention:
        action = "Treat the attachment as malicious; purge the message and block the sender."
    else:
        action = "Review the attachment behavior; consider quarantining the message."

    updated_assessment["recommended_actions"] = (
        list(current_assessment.get("recommended_actions") or []) + [action]
    )

    logger.info("Sandbox scoring: score %d -> %d, verdict: %s -> %s, %d rule matches",
                current_score, new_score, current_verdict, new_verdict, len(all_matches))

    result = {
        "risk_score": new_score,
        "verdict": new_verdict,
        "verdict_band": decision["verdict_band"],
        "final_assessment": updated_assessment,
        "mitre_attack": new_mitre,
        "sandbox_analysis": {**sandbox, "verdict": "behavior_observed"},
    }

    return result
