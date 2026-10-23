"""
E-TAP Sandbox Module
====================
Dynamic attachment analysis: eligible attachments are opened in an isolated
Windows VM, Sysmon records what they do, and behavioural rules raise the
investigation's score (never lower it).

Backend modes (set via SANDBOX_BACKEND env var):
  - agent      : the user's own VM, reached through a paired E-TAP Sandbox
                 Agent (hosted deployments; opt-in per analysis)
  - virtualbox : a VM on the same machine as this server (local runs)
  - replay     : evaluate a recorded Sysmon trace (labeled mode="replay")
  - none       : sandbox unavailable
"""

from __future__ import annotations

import os
import logging

logger = logging.getLogger("E-TAP.sandbox")

BACKENDS = ("agent", "virtualbox", "replay", "none")


def get_backend() -> str:
    """Return the configured sandbox backend (see BACKENDS)."""
    backend = os.getenv("SANDBOX_BACKEND", "none").strip().lower()
    return backend if backend in BACKENDS else "none"


def submit(email_id: str, attachments_with_bytes: list[dict],
           attachment_analysis: dict, agent: dict | None = None) -> dict:
    """
    Submit attachments for sandbox analysis.
    Returns a status dict immediately (async processing happens in background).

    Args:
        email_id: The MongoDB document ID for this email analysis.
        attachments_with_bytes: List of attachment dicts with content_bytes_b64.
        attachment_analysis: The B2 forensic analysis result.
        agent: The paired agent record (agent backend only).

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

    if backend == "agent":
        if agent is None:
            return {"status": "not_requested", "email_id": email_id, "mode": "agent",
                    "message": "Deeper attachment analysis was not requested."}
        from .worker import build_candidates
        from .agent_queue import enqueue
        candidates = build_candidates(attachments_with_bytes, attachment_analysis)
        if not candidates:
            return {"status": "not_applicable", "email_id": email_id, "mode": "agent",
                    "message": "No attachments eligible for sandbox detonation."}
        return enqueue(email_id, agent, candidates)

    return {"status": "error", "email_id": email_id,
            "mode": "none", "message": f"Unknown sandbox backend: {backend}"}


def current_analysis(email_id: str, stored: dict | None) -> dict:
    """The investigation's live sandbox state for the report and status endpoints."""
    mode = (stored or {}).get("mode")
    if mode == "agent":
        from .agent_queue import current_analysis as agent_current
        return agent_current(email_id, stored)
    if mode == "virtualbox" or get_backend() == "virtualbox":
        from .worker import current_analysis as worker_current
        return worker_current(email_id, stored)
    return stored or {}
