"""
E-TAP Sandbox Module
====================
Orchestrates attachment detonation in a VirtualBox Windows 11 VM,
collects Sysmon telemetry, evaluates detection rules, and integrates
results into the existing E-TAP investigation pipeline.

Backend modes (set via SANDBOX_BACKEND env var):
  - virtualbox : live detonation in a local VirtualBox VM
  - replay     : evaluate a recorded Sysmon trace (labeled mode="replay")
  - none       : sandbox unavailable (hosted deployment)
"""

from __future__ import annotations

import os
import logging

logger = logging.getLogger("E-TAP.sandbox")


def get_backend() -> str:
    """Return the configured sandbox backend: 'virtualbox', 'replay', or 'none'."""
    return os.getenv("SANDBOX_BACKEND", "none").strip().lower()


def submit(email_id: str, attachments_with_bytes: list[dict],
           attachment_analysis: dict) -> dict:
    """
    Submit attachments for sandbox analysis.
    Returns a status dict immediately (async processing happens in background).

    Args:
        email_id: The MongoDB document ID for this email analysis.
        attachments_with_bytes: List of attachment dicts with content_bytes_b64.
        attachment_analysis: The B2 forensic analysis result.

    Returns:
        dict with 'status', 'email_id', and optionally 'job_id'.
    """
    backend = get_backend()

    if backend == "none":
        return {"status": "unavailable", "email_id": email_id,
                "mode": "none", "message": "Sandbox is not configured for this deployment."}

    if backend == "replay":
        from .replay import submit_replay
        return submit_replay(email_id, attachments_with_bytes, attachment_analysis)

    if backend == "virtualbox":
        from .worker import enqueue_job
        return enqueue_job(email_id, attachments_with_bytes, attachment_analysis)

    return {"status": "error", "email_id": email_id,
            "mode": "none", "message": f"Unknown sandbox backend: {backend}"}