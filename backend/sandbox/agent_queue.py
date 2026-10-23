"""
sandbox.agent_queue -- jobs for paired E-TAP Sandbox Agents (SANDBOX_BACKEND=agent).
====================================================================================
The agent runs on the user's computer next to their VM and only makes
outbound requests:

  1. register      -> agent token (kept by the agent) + a short pairing code
  2. the user enters the code in the extension or dashboard -> sandbox token
  3. an analysis sent with that sandbox token and "deeper analysis" queues
     the eligible attachments here, for that agent only
  4. the agent polls for the next job, downloads each sample, runs them in
     its clean VM and uploads the raw record (items, Sysmon XML, Defender
     events)
  5. the server evaluates the rules and raises the investigation's score

Only token hashes are stored. Jobs and samples live in MongoDB so they
survive a server restart; samples are deleted as soon as a job finishes or
expires. Times are epoch seconds so the in-memory test database can compare
them.
"""

from __future__ import annotations

import base64
import gzip
import hashlib
import io
import logging
import os
import re
import secrets
import time
import uuid
from datetime import datetime, timezone
from typing import Any, Optional

from . import analysis
from .archives import expand_candidate

logger = logging.getLogger("E-TAP.sandbox.agent")

AGENTS = "sandbox_agents"
JOBS = "sandbox_jobs"
FILES = "sandbox_job_files"

PAIRING_CODE_TTL = 10 * 60
ONLINE_WINDOW = 30          # seconds since the last poll that still count as online
MAX_CLIENT_TOKENS = 5       # extension + dashboard + a few re-pairings
MAX_ITEMS = 20
MAX_SYSMON_BYTES = 64 * 1024 * 1024
MAX_SECURITY_EVENTS = 100
CODE_ALPHABET = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789"


class AgentError(Exception):
    """A request the agent API rejects; `status` is the HTTP status to return."""

    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _queued_ttl() -> int:
    return int(os.getenv("SANDBOX_AGENT_JOB_TTL_SECONDS", "1800"))


def _running_ttl() -> int:
    return int(os.getenv("SANDBOX_AGENT_RUN_TIMEOUT_SECONDS", "900"))


def _db():
    from db.connection import get_db
    return get_db()


def _now() -> float:
    return time.time()


def _iso(ts: float | None) -> str | None:
    return datetime.fromtimestamp(ts, timezone.utc).isoformat() if ts else None


def _hash(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def _clean(value: Any, limit: int = 300) -> str:
    return str(value or "").strip()[:limit]


def normalize_code(code: str) -> str:
    raw = re.sub(r"[^A-Za-z0-9]", "", code or "").upper()
    return f"{raw[:4]}-{raw[4:8]}" if len(raw) == 8 else raw


def _new_code() -> str:
    raw = "".join(secrets.choice(CODE_ALPHABET) for _ in range(8))
    return f"{raw[:4]}-{raw[4:]}"


# -- agent identity and pairing ------------------------------------------

def register_agent(name: str, version: str, vm: dict | None) -> dict:
    """A new agent install: returns its secret token and a first pairing code."""
    agent_id = f"agt_{uuid.uuid4().hex[:16]}"
    token = f"eta_{secrets.token_urlsafe(32)}"
    code = _new_code()
    now = _now()
    _db()[AGENTS].insert_one({
        "agent_id": agent_id,
        "agent_token_hash": _hash(token),
        "client_token_hashes": [],
        "pairing_code": code,
        "pairing_expires_ts": now + PAIRING_CODE_TTL,
        "name": _clean(name, 80) or "My sandbox",
        "version": _clean(version, 20),
        "vm": _vm_info(vm),
        "created_ts": now,
        "last_seen_ts": now,
        "paired_ts": None,
    })
    logger.info("Sandbox agent %s registered", agent_id)
    return {"agent_id": agent_id, "agent_token": token, "pairing_code": code,
            "pairing_expires_in": PAIRING_CODE_TTL}


def _vm_info(vm: dict | None) -> dict:
    vm = vm or {}
    return {"name": _clean(vm.get("name"), 120), "snapshot": _clean(vm.get("snapshot"), 120),
            "provider": _clean(vm.get("provider") or "virtualbox", 30),
            "provider_version": _clean(vm.get("provider_version"), 40)}


def authenticate_agent(token: str | None) -> dict:
    if not token or not token.startswith("eta_"):
        raise AgentError("Missing or invalid agent token.", 401)
    agent = _db()[AGENTS].find_one({"agent_token_hash": _hash(token)})
    if not agent:
        raise AgentError("Unknown agent token. Run the agent's setup again.", 401)
    return agent


def touch_agent(agent: dict, vm: dict | None = None) -> None:
    fields: dict = {"last_seen_ts": _now()}
    if vm:
        fields["vm"] = _vm_info(vm)
    _db()[AGENTS].update_one({"agent_id": agent["agent_id"]}, {"$set": fields})


def new_pairing_code(agent: dict) -> dict:
    code = _new_code()
    _db()[AGENTS].update_one({"agent_id": agent["agent_id"]}, {"$set": {
        "pairing_code": code, "pairing_expires_ts": _now() + PAIRING_CODE_TTL, "last_seen_ts": _now()}})
    return {"pairing_code": code, "pairing_expires_in": PAIRING_CODE_TTL}


def agent_self(agent: dict) -> dict:
    """What the agent is told about itself (it polls this while showing its code)."""
    touch_agent(agent)
    return {"agent_id": agent["agent_id"], "paired": bool(agent.get("client_token_hashes")),
            "name": agent.get("name"), "pairing_code_active": bool(
                agent.get("pairing_code") and (agent.get("pairing_expires_ts") or 0) > _now())}


def claim_pairing_code(code: str) -> dict:
    """The user typed the agent's code into a client: returns that client's sandbox token."""
    code = normalize_code(code)
    if not re.fullmatch(r"[A-Z0-9]{4}-[A-Z0-9]{4}", code):
        raise AgentError("Pairing codes look like ABCD-1234.")
    agents = _db()[AGENTS]
    agent = agents.find_one({"pairing_code": code})
    if not agent or (agent.get("pairing_expires_ts") or 0) < _now():
        raise AgentError("That pairing code is wrong or has expired. Ask the agent for a new one.", 404)
    token = f"ets_{secrets.token_urlsafe(32)}"
    hashes = (list(agent.get("client_token_hashes") or []) + [_hash(token)])[-MAX_CLIENT_TOKENS:]
    # Single use: the code is cleared in the same update that adds the token.
    agents.update_one({"agent_id": agent["agent_id"], "pairing_code": code}, {"$set": {
        "client_token_hashes": hashes, "pairing_code": None, "pairing_expires_ts": None,
        "paired_ts": agent.get("paired_ts") or _now()}})
    logger.info("Sandbox agent %s paired with a client", agent["agent_id"])
    return {"sandbox_token": token, **public_agent(agent)}


def agent_for_client(sandbox_token: str | None) -> Optional[dict]:
    if not sandbox_token or not sandbox_token.startswith("ets_"):
        return None
    return _db()[AGENTS].find_one({"client_token_hashes": _hash(sandbox_token)})


def unpair_client(sandbox_token: str) -> bool:
    agent = agent_for_client(sandbox_token)
    if not agent:
        return False
    hashes = [h for h in agent.get("client_token_hashes") or [] if h != _hash(sandbox_token)]
    _db()[AGENTS].update_one({"agent_id": agent["agent_id"]}, {"$set": {"client_token_hashes": hashes}})
    return True


def is_online(agent: dict) -> bool:
    return _now() - (agent.get("last_seen_ts") or 0) <= ONLINE_WINDOW


def public_agent(agent: dict) -> dict:
    vm = agent.get("vm") or {}
    last = agent.get("last_seen_ts")
    return {
        "name": agent.get("name"),
        "online": is_online(agent),
        "last_seen_at": _iso(last),
        "last_seen_seconds": int(_now() - last) if last else None,
        "vm_name": vm.get("name"),
        "provider": vm.get("provider"),
    }


def client_status(sandbox_token: str | None) -> dict:
    agent = agent_for_client(sandbox_token)
    if not agent:
        return {"paired": False, "online": False}
    _expire_jobs()
    queued = _db()[JOBS].count_documents({"agent_id": agent["agent_id"], "status": "queued"})
    return {"paired": True, **public_agent(agent), "queued_jobs": queued}


# -- jobs ------------------------------------------------------------------

def enqueue(email_id: str, agent: dict, candidates: list[dict]) -> dict:
    """Queue an investigation's eligible attachments for one paired agent."""
    analysis.ensure_rules()
    now = _now()
    job_id = f"job_{uuid.uuid4().hex[:12]}"
    samples = [s for c in candidates for s in expand_candidate(c)]
    db = _db()
    public_samples = []
    for index, sample in enumerate(samples):
        content = sample.get("content_b64") or ""
        if content and not sample.get("inspection_error"):
            db[FILES].insert_one({"job_id": job_id, "index": index, "content_b64": content})
        public_samples.append({
            "index": index,
            "filename": sample.get("filename", "unknown"),
            "sha256": sample.get("sha256"),
            "size_bytes": sample.get("size_bytes", 0),
            "has_file": bool(content) and not sample.get("inspection_error"),
            **{k: sample[k] for k in ("archive", "archive_member", "inspection_error") if sample.get(k)},
        })
    job = {
        "job_id": job_id,
        "agent_id": agent["agent_id"],
        "email_id": email_id,
        "status": "queued",
        "samples": public_samples,
        "candidates": len(candidates),
        "created_ts": now,
        "expires_ts": now + _queued_ttl(),
        "claimed_ts": None,
        "finished_ts": None,
        "error": None,
    }
    db[JOBS].insert_one(job)
    analysis.persist_status(email_id, _sandbox_doc(job, agent))
    logger.info("Queued agent job %s for email %s (%d samples)", job_id, email_id, len(public_samples))
    return {"status": "queued", "email_id": email_id, "job_id": job_id, "mode": "agent",
            "candidates": len(candidates), "agent_online": is_online(agent)}


def _sandbox_doc(job: dict, agent: dict | None, **extra) -> dict:
    """The `sandbox_analysis` shape stored on the investigation and shown in the report."""
    doc = {
        "job_id": job["job_id"],
        "status": job["status"],
        "mode": "agent",
        "created_at": _iso(job.get("created_ts")),
        "started_at": _iso(job.get("claimed_ts")),
        "finished_at": _iso(job.get("finished_ts")),
        "expires_at": _iso(job.get("expires_ts")) if job["status"] == "queued" else None,
        "candidates": job.get("candidates", 0),
        "items": extra.pop("items", []),
        "error": job.get("error"),
    }
    if agent:
        doc["agent"] = {"name": agent.get("name"), "vm_name": (agent.get("vm") or {}).get("name")}
    cov = analysis.coverage()
    if cov:
        doc["coverage"] = cov
    doc.update(extra)
    return doc


def _expire_jobs() -> None:
    """Fail jobs nobody picked up in time, or whose agent never reported back."""
    db = _db()
    now = _now()
    stale = list(db[JOBS].find({"status": "queued", "expires_ts": {"$lte": now}}))
    stale += [j for j in db[JOBS].find({"status": {"$in": ["starting", "interacting", "collecting", "restoring"]}})
              if (j.get("claimed_ts") or now) + _running_ttl() <= now]
    for job in stale:
        message = ("Your sandbox did not pick this up in time. Check that the agent is running, then analyze the email again."
                   if job["status"] == "queued" else "Your sandbox stopped reporting during the run.")
        db[JOBS].update_one({"job_id": job["job_id"]}, {"$set": {"status": "error", "error": message, "finished_ts": now}})
        db[FILES].delete_many({"job_id": job["job_id"]})
        job.update(status="error", error=message, finished_ts=now)
        try:
            analysis.persist_status(job["email_id"], _sandbox_doc(job, None))
        except Exception:
            logger.warning("Could not mark expired sandbox job %s on its investigation", job["job_id"])


def next_job(agent: dict) -> Optional[dict]:
    """Claim the agent's oldest queued job (also its heartbeat)."""
    touch_agent(agent)
    _expire_jobs()
    db = _db()
    for job in db[JOBS].find({"agent_id": agent["agent_id"], "status": "queued"}).sort("created_ts", 1).limit(3):
        now = _now()
        claimed = db[JOBS].find_one_and_update(
            {"job_id": job["job_id"], "status": "queued"},
            {"$set": {"status": "starting", "claimed_ts": now}},
        )
        if claimed is None:
            continue
        job.update(status="starting", claimed_ts=now)
        analysis.persist_status(job["email_id"], _sandbox_doc(job, agent))
        return {"job_id": job["job_id"], "samples": job["samples"],
                "dwell_seconds": int(os.getenv("SANDBOX_DWELL_SECONDS", "30"))}
    return None


def _agent_job(agent: dict, job_id: str) -> dict:
    job = _db()[JOBS].find_one({"job_id": job_id, "agent_id": agent["agent_id"]})
    if not job:
        raise AgentError("Job not found.", 404)
    return job


def sample_bytes(agent: dict, job_id: str, index: int) -> bytes:
    job = _agent_job(agent, job_id)
    if job["status"] in {"queued", "done", "partial", "error"}:
        raise AgentError("This job is not running.", 409)
    stored = _db()[FILES].find_one({"job_id": job_id, "index": index})
    if not stored:
        raise AgentError("Sample not found.", 404)
    return base64.b64decode(stored["content_b64"])


def report_progress(agent: dict, job_id: str, status: str) -> dict:
    if status not in {"starting", "interacting", "collecting", "restoring"}:
        raise AgentError("Unknown job status.")
    touch_agent(agent)
    job = _agent_job(agent, job_id)
    if job["status"] not in {"starting", "interacting", "collecting", "restoring"}:
        raise AgentError("This job is not running.", 409)
    _db()[JOBS].update_one({"job_id": job_id}, {"$set": {"status": status}})
    job["status"] = status
    analysis.persist_status(job["email_id"], _sandbox_doc(job, agent))
    return {"ok": True}


_ITEM_FIELDS = {"filename": 400, "sample": 120, "sha256": 64, "verdict": 40, "sample_marker": 120,
                "launch_error": 500, "note": 300, "archive": 400, "archive_member": 400}


def _clean_item(raw: dict, issued: dict) -> dict:
    item = {k: _clean(raw.get(k), n) or None for k, n in _ITEM_FIELDS.items()}
    item["launched"] = bool(raw.get("launched"))
    item["matches"], item["process_tree"], item["event_count"] = [], [], 0
    item["interaction_log"] = [
        {k: _clean(v, 500) if isinstance(v, str) else v for k, v in entry.items()
         if k in {"action", "command", "stdout", "stderr", "reason", "error", "seconds"}}
        for entry in (raw.get("interaction_log") or [])[:20] if isinstance(entry, dict)
    ]
    if item["verdict"] not in {"no_behavior_observed_inconclusive", "inspection_incomplete", "error"}:
        item["verdict"] = "no_behavior_observed_inconclusive"
    # The issued sample is the source of truth for names and hashes.
    for key in ("filename", "sha256", "archive", "archive_member"):
        if issued.get(key):
            item[key] = issued[key]
    if item["launched"] and not (item["sample_marker"] and re.fullmatch(r"sample_[\w-]+", item["sample_marker"])):
        item["launched"] = False
        item["verdict"], item["note"] = "inspection_incomplete", "The agent did not report a usable sample marker."
    return {k: v for k, v in item.items() if v is not None}


def _sysmon_text(payload: dict) -> str:
    encoded = payload.get("sysmon_xml_gz_b64") or ""
    if not encoded:
        return "<Events></Events>"
    raw = base64.b64decode(encoded)
    with gzip.GzipFile(fileobj=io.BytesIO(raw)) as stream:
        data = stream.read(MAX_SYSMON_BYTES + 1)
    if len(data) > MAX_SYSMON_BYTES:
        raise AgentError("Sysmon export is too large.", 413)
    text = data.decode("utf-8-sig", errors="replace")
    # Sysmon exports never declare entities; refuse any that do.
    if "<!DOCTYPE" in text[:4096].upper() or "<!ENTITY" in text.upper():
        raise AgentError("Sysmon export contains a DTD.")
    return text


def submit_result(agent: dict, job_id: str, payload: dict) -> dict:
    """The agent's raw record for a job: evaluate, score and store it."""
    touch_agent(agent, payload.get("vm"))
    job = _agent_job(agent, job_id)
    if job["status"] not in {"starting", "interacting", "collecting", "restoring"}:
        raise AgentError("This job is not running.", 409)
    analysis.ensure_rules()

    issued = {s["index"]: s for s in job.get("samples") or []}
    raw_items = payload.get("items") or []
    if not isinstance(raw_items, list) or len(raw_items) > MAX_ITEMS:
        raise AgentError("Invalid items.")
    items = []
    for position, raw in enumerate(raw_items):
        if not isinstance(raw, dict):
            raise AgentError("Invalid items.")
        index = raw.get("index", position)
        items.append(_clean_item(raw, issued.get(index, {})))
    events = [e for e in (payload.get("security_events") or [])[:MAX_SECURITY_EVENTS] if isinstance(e, dict)]
    events = [{"event_id": e.get("event_id"), "record_id": e.get("record_id"), "message": _clean(e.get("message"), 4000)}
              for e in events]
    error = _clean(payload.get("error"), 500) or None
    cleanup_error = _clean(payload.get("cleanup_error"), 500) or None

    if not error:
        analysis.evaluate_items(items, _sysmon_text(payload), events)
    job["error"] = error or cleanup_error
    job["status"] = analysis.final_status(items, job["error"])
    job["finished_ts"] = _now()

    db = _db()
    db[JOBS].update_one({"job_id": job_id}, {"$set": {
        "status": job["status"], "error": job["error"], "finished_ts": job["finished_ts"]}})
    db[FILES].delete_many({"job_id": job_id})
    extra = {"security_events": events, "defender_checked": not payload.get("defender_checkpoint_error")}
    if payload.get("defender_checkpoint_error"):
        extra["defender_note"] = "Windows Defender events could not be read in this run, so blocks by Defender were not checked."
        logger.warning("Agent job %s: Defender checkpoint failed on the agent (%s)", job_id,
                       _clean(payload.get("defender_checkpoint_error"), 200))
    if cleanup_error:
        extra["cleanup_error"] = cleanup_error
    analysis.store_results(job["email_id"], _sandbox_doc(job, agent, items=items, **extra))
    logger.info("Agent job %s finished: %s", job_id, job["status"])
    return {"ok": True, "status": job["status"]}


def current_analysis(email_id: str, stored: dict | None) -> dict:
    """The investigation's sandbox doc, after failing any job that timed out."""
    if (stored or {}).get("mode") == "agent" and stored.get("status") in analysis.ACTIVE_STATUSES:
        _expire_jobs()
        from db.connection import get_db
        from db import repository
        doc = repository.get_analysis(get_db(), email_id) or {}
        return doc.get("sandbox_analysis") or stored
    return stored or {}
