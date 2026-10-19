"""
Background analysis jobs with live stage progress.

`POST /analyze/jobs` starts an analysis and returns a job id at once; the
dashboard polls `GET /analyze/jobs/{id}` and lights up each stage as the
pipeline reports it. `POST /analyze` (used by the Gmail extension and CLI-style
clients) is unchanged and still returns the report in one response.

Jobs live in process memory only and expire after JOB_TTL_SECONDS. Run one
Uvicorn worker, as for the other in-process state in this backend.
"""
from __future__ import annotations

import logging
import threading
import time
import uuid
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Optional

logger = logging.getLogger("E-TAP.jobs")

JOB_TTL_SECONDS = 3600
MAX_CONCURRENT_JOBS = 2

# Order and plain-language names shown on the Analyze page timeline.
STAGES: tuple[tuple[str, str], ...] = (
    ("parse", "Reading the email"),
    ("headers", "Checking sender & headers"),
    ("static_attachments", "Static attachment analysis"),
    ("sandbox", "Dynamic attachment analysis"),
    ("indicators", "Extracting links & indicators"),
    ("reputation", "Threat reputation lookups"),
    ("history", "Comparing with past emails"),
    ("ai", "AI threat assessment"),
    ("verdict", "Final verdict"),
)
_STAGE_KEYS = {key for key, _ in STAGES}
_STATES = {"pending", "running", "done", "skipped", "not_available", "error"}

_jobs: dict[str, dict[str, Any]] = {}
_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=MAX_CONCURRENT_JOBS, thread_name_prefix="etap-analysis")


def _now() -> float:
    return time.time()


def _purge_expired() -> None:
    cutoff = _now() - JOB_TTL_SECONDS
    with _lock:
        for job_id in [j for j, job in _jobs.items() if job["updated_at"] < cutoff]:
            _jobs.pop(job_id, None)


def _public(job: dict) -> dict:
    with _lock:
        return {
            "job_id": job["job_id"],
            "status": job["status"],
            "stages": [dict(s) for s in job["stages"]],
            "error": job.get("error"),
            "report": job.get("report"),
            "created_at": job["created_at"],
            "updated_at": job["updated_at"],
        }


def _set_stage(job: dict, stage: str, state: str, detail: Optional[str] = None) -> None:
    if stage not in _STAGE_KEYS or state not in _STATES:
        return
    with _lock:
        for s in job["stages"]:
            if s["key"] == stage:
                s["state"] = state
                if detail is not None:
                    s["detail"] = detail
                if state == "running":
                    s["started_at"] = _now()
                elif state in {"done", "skipped", "not_available", "error"}:
                    s["finished_at"] = _now()
        job["updated_at"] = _now()


def _run(job: dict, filename: str, raw_bytes: bytes, source: Optional[str]) -> None:
    from email_parser.unified_parser import UnsupportedFileTypeError
    from pipeline import analyze_email_upload
    from workflow_c import finish_analysis

    def progress(stage: str, state: str, detail: Optional[str] = None) -> None:
        _set_stage(job, stage, state, detail)

    try:
        report = analyze_email_upload(filename, raw_bytes, source, progress=progress)
        report = finish_analysis(report)
        # finish_analysis may apply verified trusted-sender context, so the
        # verdict line reflects the final, stored decision.
        _set_stage(job, "verdict", "done", f"{report.get('verdict')} ({report.get('risk_score')}/100)")
        with _lock:
            job["report"] = report
            job["status"] = "done"
            job["updated_at"] = _now()
    except UnsupportedFileTypeError as exc:
        _fail(job, str(exc))
    except Exception as exc:
        logger.warning("Analysis job failed (%s)", type(exc).__name__)
        _fail(job, "An error occurred while analyzing the email artifact. Verify the file is an undamaged RFC 822 (.eml) or Outlook (.msg) file.")


def _fail(job: dict, message: str) -> None:
    with _lock:
        for s in job["stages"]:
            if s["state"] == "running":
                s["state"] = "error"
        job["status"] = "error"
        job["error"] = message
        job["updated_at"] = _now()


def start_job(filename: str, raw_bytes: bytes, source: Optional[str] = None) -> dict:
    _purge_expired()
    job_id = uuid.uuid4().hex
    job = {
        "job_id": job_id,
        "status": "running",
        "stages": [{"key": k, "label": label, "state": "pending", "detail": None} for k, label in STAGES],
        "error": None,
        "report": None,
        "created_at": _now(),
        "updated_at": _now(),
    }
    with _lock:
        _jobs[job_id] = job
    _executor.submit(_run, job, filename, raw_bytes, source)
    return _public(job)


def get_job(job_id: str) -> Optional[dict]:
    _purge_expired()
    with _lock:
        job = _jobs.get(job_id)
    return _public(job) if job else None
