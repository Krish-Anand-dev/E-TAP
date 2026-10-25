"""
sandbox.analysis -- turn a recorded sandbox run into findings and a score.
==========================================================================
Every provider (the local worker, a paired agent, replay) hands over the
same raw record: per-sample items plus the Sysmon XML and Defender events
from the run. This module evaluates the behavioural rules against each
sample's process tree, sets item verdicts and the job status, and stores
the result on the investigation (raising the score, never lowering it).
"""

from __future__ import annotations

import logging
import os
import threading

from .config import rules_path
from .ecs_convert import sample_tree_events
from .rule_engine import load_rules, evaluate
from .scoring import apply_sandbox

logger = logging.getLogger("E-TAP.sandbox.analysis")

ACTIVE_STATUSES = frozenset({"queued", "starting", "interacting", "collecting", "evaluating", "restoring"})

_rules: list = []
_rules_skipped: dict = {}
_rules_loaded = False
_rules_lock = threading.Lock()


def ensure_rules() -> tuple[list, dict]:
    global _rules, _rules_skipped, _rules_loaded
    with _rules_lock:
        if not _rules_loaded:
            rules_dir = str(rules_path())
            if os.path.isdir(rules_dir):
                _rules, _rules_skipped = load_rules(rules_dir, "windows")
                logger.info("Loaded %d rules, %d skipped", len(_rules), len(_rules_skipped))
            if not _rules:
                raise ValueError(f"No evaluable Windows sandbox rules found in {rules_dir}")
            _rules_loaded = True
    return _rules, _rules_skipped


def coverage(note: str = "behavioral rules only; browser-based and in-memory attacks may not be visible") -> dict | None:
    if not _rules_loaded:
        return None
    return {
        "rules_loaded": len(_rules),
        "rules_total_unique_windows": len(_rules) + len(_rules_skipped),
        "skipped_rules": len(_rules_skipped),
        "note": note,
    }


def evaluate_items(items: list[dict], sysmon_xml: str, security_events: list[dict]) -> None:
    """Match rules per sample and set each item's verdict (in place)."""
    rules, _ = ensure_rules()
    single = sum(bool(i.get("launched")) for i in items) == 1
    for item in items:
        if not (item.get("sample_marker") and item.get("launched")):
            continue
        events = sample_tree_events(sysmon_xml or "<Events></Events>", item["sample_marker"])
        item["event_count"] = len(events)
        item["process_tree"] = [
            sanitize_event(e)["process"] for e in events if e.get("_category") == "process"
        ]
        hits = evaluate(rules, events)
        item["matches"] = [{
            "rule_id": h["rule_id"],
            "rule": h["rule"],
            "prevention_grade": h["prevention_grade"],
            "mitre": h["mitre"],
            "event": sanitize_event(h.get("event")),
        } for h in hits]

        blocked = security_blocks(item, security_events, single)
        if item["matches"]:
            item["verdict"] = "behavior_observed"
        elif item.get("launch_error"):
            item["verdict"] = "error"
        elif not events:
            item["verdict"] = "inspection_incomplete"
            item["note"] = "No sample process telemetry found; execution could not be confirmed."
        else:
            item["verdict"] = "no_behavior_observed_inconclusive"
        if blocked:
            item["security_events"] = blocked
            item["verdict"] = "blocked_by_security_control"
            item["note"] = "Windows security blocked sample activity. See security events and observed processes."
            item["execution_error"] = item.get("launch_error")
            item["launch_error"] = None


def final_status(items: list[dict], error: str | None) -> str:
    failed = [i for i in items if i.get("launch_error") or i.get("verdict") in {"error", "inspection_incomplete", "unsupported"}]
    if error:
        return "error"
    if failed:
        return "error" if len(failed) == len(items) else "partial"
    return "done"


def security_blocks(item: dict, events: list[dict], single_sample: bool) -> list[dict]:
    matched = []
    for event in events or []:
        if event.get("event_id") not in {1121, 1116, 1117}:
            continue
        message = (event.get("message") or "").lower()
        if item["sample_marker"].lower() in message:
            matched.append(event)
        elif single_sample:
            process_match = any(p["executable"].lower() in message for p in item.get("process_tree") or [])
            # Defender can block a command before a child process exists and
            # report Process Name: Unknown. A new command-line alert plus the
            # only sample's runtime denial provides job-scoped evidence.
            denied = any(word in (item.get("launch_error") or "").lower()
                         for word in ("permission denied", "access is denied"))
            if process_match or (denied and "cmdline:_" in message):
                matched.append(event)
    return matched


def sanitize_event(event: dict | None) -> dict:
    """Remove large/unwanted fields from event for storage."""
    if not event:
        return {}
    clean = {}
    for k, v in event.items():
        if k.startswith("_"):
            continue
        if isinstance(v, dict):
            clean[k] = {kk: vv for kk, vv in v.items()
                        if not kk.startswith("_") and kk != "CallTrace"}
        else:
            clean[k] = v
    return clean


def persist_status(email_id: str, sandbox_doc: dict) -> None:
    from db.connection import get_db
    from db import repository
    if not repository.update_analysis_fields(get_db(), email_id, {"sandbox_analysis": sandbox_doc}):
        raise RuntimeError(f"Investigation {email_id} no longer exists")


def store_results(email_id: str, sandbox_doc: dict) -> None:
    """Store a finished run and raise the investigation's score from its findings."""
    from db.connection import get_db
    from db import repository

    db = get_db()
    doc = repository.get_analysis(db, email_id)
    if not doc:
        raise RuntimeError(f"Investigation {email_id} no longer exists")
    updated = apply_sandbox(
        {
            "risk_score": doc.get("risk_score", 0),
            "verdict": doc.get("verdict", ""),
            "final_assessment": doc.get("final_assessment", {}),
            "mitre_attack": doc.get("mitre_attack", []),
        },
        sandbox_doc,
    )
    repository.update_analysis_fields(db, email_id, {"sandbox_analysis": sandbox_doc, **updated})
