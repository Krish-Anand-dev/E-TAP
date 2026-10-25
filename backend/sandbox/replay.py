"""
sandbox.replay — Recorded-trace backend for demo/testing.
==========================================================
Loads a pre-recorded Sysmon XML trace and evaluates rules against it.
Results are labeled mode="replay" so the UI shows a "RECORDED TRACE" badge.
"""

from __future__ import annotations

import os
import uuid
import logging
from datetime import datetime, timezone
from pathlib import Path

from .rule_engine import load_rules, evaluate
from .ecs_convert import sample_tree_events
from .scoring import apply_sandbox
from .config import rules_path

logger = logging.getLogger("E-TAP.sandbox.replay")

# Rules (loaded once)
_rules = []
_rules_skipped = {}
_rules_loaded = False


def _ensure_rules():
    global _rules, _rules_skipped, _rules_loaded
    if _rules_loaded:
        return
    rules_dir = str(rules_path())
    if os.path.isdir(rules_dir):
        _rules, _rules_skipped = load_rules(rules_dir, "windows")
        logger.info("Replay: loaded %d rules, %d skipped", len(_rules), len(_rules_skipped))
    if not _rules:
        raise ValueError(f"No evaluable Windows sandbox rules found in {rules_dir}")
    _rules_loaded = True


def submit_replay(email_id: str, attachments_with_bytes: list[dict],
                  attachment_analysis: dict) -> dict:
    """
    Submit attachments for replay-mode analysis.
    Looks for recorded Sysmon traces in backend/sandbox/replays/.
    """
    _ensure_rules()

    replays_dir = Path(os.path.dirname(__file__)) / "replays"
    if not replays_dir.is_dir():
        return {
            "status": "unavailable",
            "email_id": email_id,
            "mode": "replay",
            "message": "Replay directory not found."
        }

    att_results = (attachment_analysis.get("attachments") or [])
    if not att_results:
        return {
            "status": "not_applicable",
            "email_id": email_id,
            "mode": "replay",
            "message": "No attachments to analyze."
        }

    job_id = f"replay_{uuid.uuid4().hex[:12]}"
    items = []

    for att in att_results:
        filename = att.get("filename", "unknown")
        sha256 = att.get("sha256", "")

        # Look for replay file by sha256 or filename
        replay_file = None
        for candidate in [f"{sha256}.xml", f"{filename}.xml",
                          f"{sha256}", f"{filename}"]:
            p = replays_dir / candidate
            if p.exists():
                replay_file = p
                break

        if replay_file is None:
            items.append({
                "filename": filename,
                "sha256": sha256,
                "verdict": "inspection_incomplete",
                "matches": [],
                "process_tree": [],
                "event_count": 0,
                "note": "No recorded trace available for this attachment.",
            })
            continue

        # Load and evaluate the trace
        try:
            xml_text = replay_file.read_text(encoding="utf-8-sig")
            marker = filename.rsplit(".", 1)[0] if "." in filename else filename
            events = sample_tree_events(xml_text, marker)
            hits = evaluate(_rules, events)

            items.append({
                "filename": filename,
                "sha256": sha256,
                "verdict": "behavior_observed" if hits else "no_behavior_observed_inconclusive",
                "matches": [{
                    "rule_id": h["rule_id"],
                    "rule": h["rule"],
                    "prevention_grade": h["prevention_grade"],
                    "mitre": h["mitre"],
                } for h in hits],
                "process_tree": [],
                "event_count": len(events),
            })

        except Exception as exc:
            logger.error("Replay failed for %s: %s", filename, exc)
            items.append({
                "filename": filename,
                "sha256": sha256,
                "verdict": "error",
                "matches": [],
                "error": str(exc)[:300],
            })

    # Build result
    rules_loaded = len(_rules)
    rules_total = rules_loaded + len(_rules_skipped)

    sandbox_doc = {
        "status": "done",
        "mode": "replay",
        "job_id": job_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "finished_at": datetime.now(timezone.utc).isoformat(),
        "coverage": {
            "rules_loaded": rules_loaded,
            "rules_total_unique_windows": rules_total,
            "skipped_rules": len(_rules_skipped),
            "note": "RECORDED TRACE — not live detonation",
        },
        "items": items,
    }

    # Store in DB
    try:
        from db.connection import get_db
        from db import repository

        db = get_db()
        repository.update_analysis_fields(db, email_id, {
            "sandbox_analysis": sandbox_doc,
        })

        # Update risk score
        all_hits = []
        for item in items:
            all_hits.extend(item.get("matches") or [])

        if all_hits:
            doc = repository.get_analysis(db, email_id)
            if doc:
                updated = apply_sandbox(
                    {
                        "risk_score": doc.get("risk_score", 0),
                        "verdict": doc.get("verdict", ""),
                        "final_assessment": doc.get("final_assessment", {}),
                        "mitre_attack": doc.get("mitre_attack", []),
                    },
                    sandbox_doc,
                )
                repository.update_analysis_fields(db, email_id, updated)

    except Exception as exc:
        logger.exception("Replay: failed to store results: %s", exc)

    return {
        "status": "done",
        "email_id": email_id,
        "job_id": job_id,
        "mode": "replay",
        "items": len(items),
    }
