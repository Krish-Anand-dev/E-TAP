"""
sandbox.worker — Single-threaded job queue for VM detonation.
=============================================================
Serializes access to the single VM. One job at a time.
Handles the full lifecycle: queue -> prepare -> detonate -> collect -> evaluate -> store.
"""

from __future__ import annotations

import os
import uuid
import time
import base64
import hashlib
import logging
import threading
import queue
import json
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from .vbox import VBox, VBoxError, GuestProcessTimeout
from .policy import get_detonation_candidates, launcher_for
from .rule_engine import load_rules, evaluate
from .ecs_convert import sample_tree_events, win_split
from .scoring import apply_sandbox
from .config import sandbox_path, rules_path
from .archives import expand_candidate

logger = logging.getLogger("E-TAP.sandbox.worker")

# Global lock: only one VM job at a time
_vm_lock = threading.Lock()
_worker_started = False
_worker_start_lock = threading.Lock()

# Job queue
_job_queue: queue.Queue = queue.Queue()
_jobs: dict[str, dict] = {}  # job_id -> job state

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
        logger.info("Loaded %d rules, %d skipped", len(_rules), len(_rules_skipped))
    else:
        logger.warning("Rules directory not found: %s", rules_dir)
    if not _rules:
        raise ValueError(f"No evaluable Windows sandbox rules found in {rules_dir}")
    _rules_loaded = True


def _get_work_dir() -> Path:
    p = sandbox_path("SANDBOX_WORK_DIR", "work")
    p.mkdir(parents=True, exist_ok=True)
    return p


def enqueue_job(email_id: str, attachments_with_bytes: list[dict],
                attachment_analysis: dict) -> dict:
    """
    Enqueue a new sandbox job. Returns immediately with job status.
    The actual work happens in the background worker thread.
    """
    global _worker_started

    # Filter to detonation candidates
    att_results = (attachment_analysis.get("attachments") or [])
    candidates = get_detonation_candidates(att_results)

    if not candidates:
        return {
            "status": "not_applicable",
            "email_id": email_id,
            "mode": "virtualbox",
            "message": "No attachments eligible for sandbox detonation."
        }

    job_id = f"job_{uuid.uuid4().hex[:12]}"
    job = {
        "job_id": job_id,
        "email_id": email_id,
        "status": "queued",
        "mode": "virtualbox",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "started_at": None,
        "finished_at": None,
        "candidates": [],
        "items": [],
        "error": None,
    }

    # Build candidate list with attachment bytes
    bytes_map = {}
    for att in attachments_with_bytes:
        b64 = att.get("content_bytes_b64") or att.get("bytes_b64") or ""
        if b64:
            digest = hashlib.sha256(base64.b64decode(b64)).hexdigest()
            bytes_map[(att.get("filename", ""), digest)] = b64

    for c in candidates:
        fname = c.get("filename", "unknown")
        b64 = bytes_map.get((fname, c.get("sha256")), "")
        job["candidates"].append({
            "filename": fname,
            "sha256": c.get("sha256"),
            "size_bytes": c.get("size_bytes", 0),
            "actual_type": c.get("actual_type", ""),
            "declared_type": c.get("declared_type", ""),
            "content_b64": b64,
        })

    _jobs[job_id] = job
    # Persist before making the job runnable; a fast worker must not have its
    # final result overwritten by a late queued status.
    try:
        _persist_status(job)
    except Exception:
        _jobs.pop(job_id, None)
        raise
    _job_queue.put(job)

    # Start worker thread if not already running
    with _worker_start_lock:
        if not _worker_started:
            t = threading.Thread(target=_worker_loop, daemon=True)
            t.start()
            _worker_started = True

    logger.info("Enqueued sandbox job %s for email %s (%d candidates)",
                job_id, email_id, len(candidates))

    return {
        "status": "queued",
        "email_id": email_id,
        "job_id": job_id,
        "mode": "virtualbox",
        "candidates": len(candidates),
    }


def get_job_status(job_id: str) -> dict | None:
    """Get current status of a job."""
    job = _jobs.get(job_id)
    return _public_job(job) if job else None


def get_jobs_for_email(email_id: str) -> list[dict]:
    """Get all jobs for a given email_id."""
    return [_public_job(j) for j in list(_jobs.values()) if j.get("email_id") == email_id]


def _public_job(job: dict) -> dict:
    """Never return attachment payloads from status APIs or store them in Mongo."""
    result = deepcopy({k: v for k, v in job.items() if k != "candidates"})
    result["candidates"] = len(job.get("candidates", []))
    if _rules_loaded:
        result["coverage"] = {
            "rules_loaded": len(_rules),
            "rules_total_unique_windows": len(_rules) + len(_rules_skipped),
            "skipped_rules": len(_rules_skipped),
            "note": "behavioral rules only; browser-based and in-memory attacks may not be visible",
        }
    return result


def current_analysis(email_id: str, stored: dict | None) -> dict:
    """Shared by both report/status endpoints, including every active phase."""
    jobs = get_jobs_for_email(email_id)
    if jobs:
        latest = jobs[-1]
        return {**(stored or {}), **latest}
    stored = stored or {}
    if stored.get("status") in {"queued", "starting", "interacting", "collecting", "evaluating", "restoring"}:
        return {**stored, "status": "error", "error": "Sandbox worker was interrupted. Upload the email again to retry."}
    return stored


def _persist_status(job: dict):
    from db.connection import get_db
    from db import repository
    if not repository.update_analysis_fields(get_db(), job["email_id"], {
        "sandbox_analysis": _public_job(job),
    }):
        raise RuntimeError(f"Investigation {job['email_id']} no longer exists")


def _worker_loop():
    """Background worker: process jobs one at a time."""
    global _worker_started
    logger.info("Sandbox worker thread started")
    while True:
        job = _job_queue.get()
        try:
            _process_job(job)
        except Exception as exc:
            logger.exception("Job %s failed: %s", job.get("job_id"), exc)
            job["status"] = "error"
            job["error"] = str(exc)[:500]
            job["finished_at"] = datetime.now(timezone.utc).isoformat()
            _update_db_on_error(job)
        finally:
            # Payloads are needed only until this VM job finishes.
            for candidate in job.get("candidates", []):
                candidate.pop("content_b64", None)
            _job_queue.task_done()


def _process_job(job: dict):
    """Process a single sandbox job through its full lifecycle."""
    job_id = job["job_id"]
    work_dir = _get_work_dir() / job_id
    work_dir.mkdir(parents=True, exist_ok=True)

    logger.info("Processing job %s", job_id)
    job["status"] = "starting"
    job["started_at"] = datetime.now(timezone.utc).isoformat()

    _ensure_rules()

    vbox = VBox()

    with _vm_lock:
        try:
            # Phase 1: Restore and start VM
            logger.info("Job %s: restoring VM", job_id)
            vbox.restore()
            vbox.start()
            vbox.wait_ready()
            vbox._gc("mkdir", "--parents", r"C:\sandbox\in", r"C:\sandbox\out")

            # Clear Sysmon log for clean baseline
            vbox.clear_sysmon()
            security_baseline = _security_record_id(vbox)
            time.sleep(1)

            # Phase 2: Process each candidate
            job["status"] = "interacting"
            for candidate in job["candidates"]:
                for sample in expand_candidate(candidate):
                    item = _detonate_single(vbox, job_id, sample, work_dir)
                    job["items"].append(item)

            # Phase 3: Collect telemetry
            job["status"] = "collecting"
            sysmon_xml = _collect_sysmon(vbox, work_dir)
            security_events = _collect_security_events(vbox, security_baseline)
            job["security_events"] = security_events

            # Phase 4: Evaluate rules
            job["status"] = "evaluating"
            for item in job["items"]:
                if item.get("sample_marker") and item.get("launched"):
                    events = sample_tree_events(sysmon_xml, item["sample_marker"])
                    item["event_count"] = len(events)
                    item["process_tree"] = [
                        _sanitize_event(e)["process"] for e in events if e.get("_category") == "process"
                    ]
                    hits = evaluate(_rules, events)
                    item["matches"] = [{
                        "rule_id": h["rule_id"],
                        "rule": h["rule"],
                        "prevention_grade": h["prevention_grade"],
                        "mitre": h["mitre"],
                        "event": _sanitize_event(h.get("event")),
                    } for h in hits]

                    # Set verdict
                    blocked = _security_blocks(item, security_events,
                                               sum(bool(i.get("launched")) for i in job["items"]) == 1)
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

        except Exception as exc:
            logger.exception("Job %s failed: %s", job_id, exc)
            job["error"] = str(exc)[:500]
        finally:
            # Hold the VM lock through recovery. Publish a terminal result only
            # after restoring the baseline, with the actual completion time.
            job["status"] = "restoring"
            try:
                vbox.restore()
            except Exception as exc:
                job["cleanup_error"] = f"Failed to restore clean VM: {exc}"[:500]
                job["error"] = job.get("error") or job["cleanup_error"]
            failed = [i for i in job["items"] if i.get("launch_error") or i["verdict"] in {"error", "inspection_incomplete", "unsupported"}]
            if job.get("error"):
                job["status"] = "error"
            elif failed:
                job["status"] = "error" if len(failed) == len(job["items"]) else "partial"
            else:
                job["status"] = "done"
            job["finished_at"] = datetime.now(timezone.utc).isoformat()
            _cleanup_work_dir(work_dir)
            _store_results(job)


def _detonate_single(vbox: VBox, job_id: str, candidate: dict,
                     work_dir: Path) -> dict:
    """Detonate a single attachment in the VM."""
    filename = candidate["filename"]
    sha256 = candidate.get("sha256", "unknown")
    b64_data = candidate.get("content_b64", "")

    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    safe_name = f"sample_{job_id}_{uuid.uuid4().hex[:8]}{ext}"
    sample_marker = safe_name.rsplit(".", 1)[0]  # e.g., "sample_job_ab12"

    item = {
        "filename": filename,
        "sample": safe_name,
        "sha256": sha256,
        "verdict": "no_behavior_observed_inconclusive",
        "matches": [],
        "process_tree": [],
        "sample_marker": sample_marker,
        "launch_error": None,
        "event_count": 0,
        "interaction_log": [],
        "launched": False,
    }

    for key in ("archive", "archive_member"):
        if key in candidate:
            item[key] = candidate[key]
    if candidate.get("inspection_error"):
        item["verdict"] = "inspection_incomplete"
        item["note"] = candidate["inspection_error"]
        return item

    if not b64_data:
        item["verdict"] = "error"
        item["launch_error"] = "No attachment data available"
        return item

    # Write sample to host work directory
    sample_path = work_dir / safe_name
    try:
        raw_bytes = base64.b64decode(b64_data, validate=True)
        sample_path.write_bytes(raw_bytes)
    except Exception as exc:
        item["verdict"] = "error"
        item["launch_error"] = f"Failed to write sample: {exc}"
        return item

    # Copy to VM
    try:
        vbox.copy_to(str(sample_path), r"C:\sandbox\in")
    except VBoxError as exc:
        item["verdict"] = "error"
        item["launch_error"] = f"Failed to copy to VM: {exc}"
        return item

    # Launch
    guest_path = f"C:\\sandbox\\in\\{safe_name}"
    exe, args_template = launcher_for(filename)

    launch_started = time.monotonic()
    try:
        if args_template is None and exe is None:
            # No launcher configured (needs application not available)
            item["verdict"] = "inspection_incomplete"
            item["launch_error"] = f"No application configured for {ext}"
            item["interaction_log"].append({
                "action": "skip", "reason": f"application_not_installed for {ext}"
            })
            return item

        if exe is None:
            # Run directly
            cmd = args_template.replace("{file}", guest_path)
        else:
            args = args_template.replace("{file}", guest_path)
            cmd = f'"{exe}" {args}'

        logger.info("Job %s: launching %s", job_id, cmd)
        item["interaction_log"].append({"action": "launch", "command": cmd})

        # Track attempted launches even if a later timeout/error is reported;
        # Sysmon may still contain useful evidence from the process tree.
        item["launched"] = True
        if exe is None:
            result = vbox.run_exe(guest_path, timeout_s=vbox.dwell)
        else:
            result = vbox.run_exe(exe, *win_split(args), timeout_s=vbox.dwell)
        item["interaction_log"].append({
            "action": "launch_complete",
            "stdout": (result.stdout or "")[:500],
            "stderr": (result.stderr or "")[:500],
        })
        # VBoxManage's own exit code can be zero even if cscript reports a
        # guest runtime error. Surface it rather than claiming full execution.
        if "runtime error" in (result.stderr or "").lower() or "compilation error" in (result.stderr or "").lower():
            item["launch_error"] = (result.stderr or "").strip()[:500]

    except GuestProcessTimeout:
        item["interaction_log"].append({"action": "observation_limit", "seconds": vbox.dwell})
    except Exception as exc:
        item["launch_error"] = str(exc)[:300]
        item["interaction_log"].append({
            "action": "launch_failed", "error": str(exc)[:300]
        })
        logger.warning("Job %s: launch failed for %s: %s", job_id, filename, exc)

    # Dwell time
    time.sleep(max(0, vbox.dwell - (time.monotonic() - launch_started)))

    return item


def _security_blocks(item: dict, events: list[dict], single_sample: bool) -> list[dict]:
    matched = []
    for event in events:
        if event.get("event_id") not in {1121, 1116, 1117}:
            continue
        message = event.get("message", "").lower()
        if item["sample_marker"].lower() in message:
            matched.append(event)
        elif single_sample:
            process_match = any(p["executable"].lower() in message for p in item["process_tree"])
            # Defender can block a command before a child process exists and
            # report Process Name: Unknown. A new command-line alert plus the
            # only sample's runtime denial provides job-scoped evidence.
            denied = any(word in (item.get("launch_error") or "").lower()
                         for word in ("permission denied", "access is denied"))
            if process_match or (denied and "cmdline:_" in message):
                matched.append(event)
    return matched


def _security_record_id(vbox: VBox) -> int:
    """Checkpoint Defender so snapshot-era alerts cannot taint a new run."""
    try:
        result = vbox.run_cmd_ps(
            "$e = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' "
            "-MaxEvents 1 -ErrorAction SilentlyContinue; if ($e) { $e.RecordId } else { 0 }",
            timeout_s=15,
        )
        return int(result.stdout.strip())
    except Exception:
        logger.warning("Defender log checkpoint unavailable; security block attribution disabled")
        return -1


def _collect_security_events(vbox: VBox, baseline: int) -> list[dict]:
    if baseline < 0:
        return []
    try:
        result = vbox.run_cmd_ps(
            "$events = @(Get-WinEvent -FilterHashtable @{"
            "LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1121,1116,1117,1122} "
            "-MaxEvents 50 -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.RecordId -gt {baseline} }} | "
            "ForEach-Object { @{event_id=$_.Id; record_id=$_.RecordId; message=$_.Message} }); "
            "ConvertTo-Json -InputObject $events -Depth 3 -Compress",
            timeout_s=30,
        )
        events = json.loads(result.stdout.strip() or "[]")
        return events if isinstance(events, list) else [events]
    except Exception as exc:
        logger.warning("Could not collect guest security events: %s", exc)
        return []


def _collect_sysmon(vbox: VBox, work_dir: Path) -> str:
    """Export Sysmon log from VM and return the XML content."""
    guest_xml = r"C:\sandbox\out\sysmon.xml"
    host_xml = str(work_dir / "sysmon.xml")

    vbox.export_sysmon(guest_xml)

    # Copy to host
    vbox.copy_from(guest_xml, host_xml)

    # Read
    try:
        with open(host_xml, "r", encoding="utf-8-sig") as f:
            return f.read()
    except UnicodeDecodeError:
        with open(host_xml, "r", encoding="utf-8") as f:
            return f.read()


def _store_results(job: dict):
    """Store sandbox analysis results in MongoDB."""
    from db.connection import get_db
    from db import repository

    _ensure_rules()

    sandbox_doc = _public_job(job)

    try:
        db = get_db()
        # Update risk score (never lower)
        doc = repository.get_analysis(db, job["email_id"])
        if not doc:
            raise RuntimeError(f"Investigation {job['email_id']} no longer exists")
        updated = apply_sandbox(
                {
                    "risk_score": doc.get("risk_score", 0),
                    "verdict": doc.get("verdict", ""),
                    "final_assessment": doc.get("final_assessment", {}),
                    "mitre_attack": doc.get("mitre_attack", []),
                },
                sandbox_doc,
            )
        repository.update_analysis_fields(db, job["email_id"], {
            "sandbox_analysis": sandbox_doc, **updated,
        })

        logger.info("Job %s: results stored for email %s", job["job_id"], job["email_id"])

    except Exception as exc:
        logger.exception("Job %s: failed to store results: %s", job["job_id"], exc)
        job["status"] = "error"
        job["error"] = f"DB store failed: {exc}"
        _update_db_on_error(job)


def _update_db_on_error(job: dict):
    """Store error status in DB."""
    try:
        _persist_status(job)
    except Exception:
        logger.exception("Failed to update DB with error status")


def _sanitize_event(event: dict | None) -> dict:
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


def _cleanup_work_dir(work_dir: Path):
    """Remove sample files from work directory, keep metadata."""
    try:
        for f in work_dir.iterdir():
            if f.name.startswith("sample_") and f.is_file():
                f.unlink()
    except Exception:
        pass
