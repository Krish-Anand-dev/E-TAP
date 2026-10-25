"""
sandbox.worker -- in-process job queue for a VM on the server's own machine.
============================================================================
SANDBOX_BACKEND=virtualbox: the E-TAP backend and the VirtualBox VM run on
the same computer. One job at a time; the VM run itself is the shared
`sandbox_agent.runner` (the same code the paired agent uses), and the
findings come from `sandbox.analysis`.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import queue
import threading
import uuid
from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path

from sandbox_agent import runner
from .policy import get_detonation_candidates
from .config import sandbox_path
from .archives import expand_candidate
from . import analysis

logger = logging.getLogger("E-TAP.sandbox.worker")

# Global lock: only one VM job at a time
_vm_lock = threading.Lock()
_worker_started = False
_worker_start_lock = threading.Lock()

# Job queue
_job_queue: queue.Queue = queue.Queue()
_jobs: dict[str, dict] = {}  # job_id -> job state


def _get_work_dir() -> Path:
    p = sandbox_path("SANDBOX_WORK_DIR", "work")
    p.mkdir(parents=True, exist_ok=True)
    return p


def build_candidates(attachments_with_bytes: list[dict], attachment_analysis: dict) -> list[dict]:
    """Eligible attachments with their bytes (base64), in policy priority order."""
    candidates = get_detonation_candidates(attachment_analysis.get("attachments") or [])
    bytes_map = {}
    for att in attachments_with_bytes:
        b64 = att.get("content_bytes_b64") or att.get("bytes_b64") or ""
        if b64:
            digest = hashlib.sha256(base64.b64decode(b64)).hexdigest()
            bytes_map[(att.get("filename", ""), digest)] = b64
    return [{
        "filename": c.get("filename", "unknown"),
        "sha256": c.get("sha256"),
        "size_bytes": c.get("size_bytes", 0),
        "actual_type": c.get("actual_type", ""),
        "declared_type": c.get("declared_type", ""),
        "content_b64": bytes_map.get((c.get("filename", "unknown"), c.get("sha256")), ""),
    } for c in candidates]


def enqueue_job(email_id: str, attachments_with_bytes: list[dict],
                attachment_analysis: dict) -> dict:
    """
    Enqueue a new sandbox job. Returns immediately with job status.
    The actual work happens in the background worker thread.
    """
    global _worker_started

    candidates = build_candidates(attachments_with_bytes, attachment_analysis)
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
        "candidates": candidates,
        "items": [],
        "error": None,
    }

    _jobs[job_id] = job
    # Persist before making the job runnable; a fast worker must not have its
    # final result overwritten by a late queued status.
    try:
        analysis.persist_status(email_id, _public_job(job))
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
    cov = analysis.coverage()
    if cov:
        result["coverage"] = cov
    return result


def current_analysis(email_id: str, stored: dict | None) -> dict:
    """Shared by both report/status endpoints, including every active phase."""
    jobs = get_jobs_for_email(email_id)
    if jobs:
        latest = jobs[-1]
        return {**(stored or {}), **latest}
    stored = stored or {}
    if stored.get("mode") == "virtualbox" and stored.get("status") in analysis.ACTIVE_STATUSES:
        return {**stored, "status": "error", "error": "Sandbox worker was interrupted. Upload the email again to retry."}
    return stored


def _worker_loop():
    """Background worker: process jobs one at a time."""
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
    """Run one job in the VM, then evaluate and store its findings."""
    job_id = job["job_id"]
    work_dir = _get_work_dir() / job_id
    logger.info("Processing job %s", job_id)
    job["started_at"] = datetime.now(timezone.utc).isoformat()
    analysis.ensure_rules()

    samples = [s for c in job["candidates"] for s in expand_candidate(c)]

    def on_status(status: str) -> None:
        job["status"] = status

    with _vm_lock:
        record = runner.run_job(job_id, samples, work_dir, vbox=runner.VBox(), on_status=on_status)

    job["items"] = record["items"]
    job["security_events"] = record["security_events"]
    job["defender_checked"] = not record.get("defender_checkpoint_error")
    if record.get("defender_checkpoint_error"):
        job["defender_note"] = "Windows Defender events could not be read in this run, so blocks by Defender were not checked."
    job["error"] = record["error"]
    if record["cleanup_error"]:
        job["cleanup_error"] = record["cleanup_error"]
        job["error"] = job["error"] or record["cleanup_error"]
    if not record["error"]:
        job["status"] = "evaluating"
        analysis.evaluate_items(job["items"], record["sysmon_xml"], record["security_events"])
    job["status"] = analysis.final_status(job["items"], job["error"])
    job["finished_at"] = datetime.now(timezone.utc).isoformat()
    _store_results(job)


def _store_results(job: dict):
    """Store sandbox analysis results in MongoDB."""
    try:
        analysis.store_results(job["email_id"], _public_job(job))
        logger.info("Job %s: results stored for email %s", job["job_id"], job["email_id"])
    except Exception as exc:
        logger.exception("Job %s: failed to store results: %s", job["job_id"], exc)
        job["status"] = "error"
        job["error"] = f"DB store failed: {exc}"
        _update_db_on_error(job)


def _update_db_on_error(job: dict):
    """Store error status in DB."""
    try:
        analysis.persist_status(job["email_id"], _public_job(job))
    except Exception:
        logger.exception("Failed to update DB with error status")
