"""
Sandbox HTTP API: per-email sandbox status, pairing, and the agent's job endpoints.

Clients (the Gmail extension, the dashboard) send the sandbox token they
got from pairing in `X-ETAP-Sandbox-Token`. The agent sends its own token
as `Authorization: Bearer ...`. See sandbox/agent_queue.py for the flow.
"""

from __future__ import annotations

import io
import logging
import zipfile
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response
from pydantic import BaseModel, Field
from slowapi import Limiter
from slowapi.util import get_remote_address

from verdicts import finalize_verdict

logger = logging.getLogger("E-TAP.sandbox.api")

router = APIRouter()
limiter = Limiter(key_func=get_remote_address)

MAX_RESULT_BYTES = 48 * 1024 * 1024
AGENT_DIR = Path(__file__).resolve().parent / "sandbox_agent"


class RegisterRequest(BaseModel):
    name: str = Field("", max_length=80)
    version: str = Field("", max_length=20)
    vm: Optional[dict[str, Any]] = None


class PairRequest(BaseModel):
    code: str = Field(..., min_length=4, max_length=20)


class ProgressRequest(BaseModel):
    status: str = Field(..., max_length=20)


def _agent_backend():
    from sandbox import get_backend
    if get_backend() != "agent":
        raise HTTPException(status_code=404, detail="This server does not use paired sandboxes (SANDBOX_BACKEND is not 'agent').")
    from sandbox import agent_queue
    return agent_queue


def _agent(request: Request):
    queue = _agent_backend()
    header = request.headers.get("authorization") or ""
    token = header[7:].strip() if header.lower().startswith("bearer ") else None
    try:
        return queue, queue.authenticate_agent(token)
    except queue.AgentError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from None


def _call(queue, fn, *args):
    try:
        return fn(*args)
    except queue.AgentError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from None


# -- clients: pairing and status -------------------------------------------

@router.post("/sandbox/pair")
@limiter.limit("10/minute")
async def pair(request: Request, payload: PairRequest) -> dict:
    """Exchange the code the agent shows for this client's sandbox token."""
    queue = _agent_backend()
    return _call(queue, queue.claim_pairing_code, payload.code)


@router.get("/sandbox/pairing")
@limiter.limit("120/minute")
async def pairing_status(request: Request) -> dict:
    """Is this client's sandbox paired, and is its agent online?"""
    import os
    from sandbox import get_backend
    backend = get_backend()
    if backend in {"virtualbox", "replay"}:
        # The VM (or recorded traces) sits with this server: nothing to pair.
        return {"available": True, "mode": backend, "paired": True, "online": True,
                "name": "This computer", "vm_name": os.getenv("SANDBOX_VM_NAME") if backend == "virtualbox" else "recorded traces"}
    if backend != "agent":
        return {"available": False, "paired": False, "online": False}
    from sandbox import agent_queue
    return {"available": True, "mode": "agent", **agent_queue.client_status(request.headers.get("x-etap-sandbox-token"))}


@router.delete("/sandbox/pairing")
@limiter.limit("10/minute")
async def unpair(request: Request) -> dict:
    queue = _agent_backend()
    return {"unpaired": queue.unpair_client(request.headers.get("x-etap-sandbox-token") or "")}


@router.get("/sandbox/agent/download")
@limiter.limit("10/minute")
async def download_agent(request: Request) -> Response:
    """The agent as a zip: the sandbox_agent package plus its launcher and guide."""
    if not (AGENT_DIR / "__main__.py").exists():
        raise HTTPException(status_code=404, detail="The agent is not bundled with this server.")
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        for path in sorted(AGENT_DIR.rglob("*")):
            if path.is_file() and "__pycache__" not in path.parts and path.suffix in {".py", ".md", ".cmd"}:
                relative = path.relative_to(AGENT_DIR)
                # The launcher and guide sit next to the package folder.
                if relative.parent == Path(".") and path.suffix in {".md", ".cmd"}:
                    archive.write(path, f"E-TAP Sandbox Agent/{relative}")
                else:
                    archive.write(path, f"E-TAP Sandbox Agent/sandbox_agent/{relative.as_posix()}")
    return Response(buffer.getvalue(), media_type="application/zip",
                    headers={"Content-Disposition": 'attachment; filename="etap-sandbox-agent.zip"'})


# -- the agent ----------------------------------------------------------------

@router.post("/sandbox/agent/register")
@limiter.limit("5/minute")
async def register_agent(request: Request, payload: RegisterRequest) -> dict:
    queue = _agent_backend()
    return queue.register_agent(payload.name, payload.version, payload.vm)


@router.get("/sandbox/agent/me")
@limiter.limit("60/minute")
async def agent_me(request: Request) -> dict:
    queue, agent = _agent(request)
    return queue.agent_self(agent)


@router.post("/sandbox/agent/pairing-code")
@limiter.limit("10/minute")
async def agent_pairing_code(request: Request) -> dict:
    queue, agent = _agent(request)
    return queue.new_pairing_code(agent)


@router.post("/sandbox/agent/jobs/next")
@limiter.limit("60/minute")
async def agent_next_job(request: Request) -> dict:
    queue, agent = _agent(request)
    try:
        body = await request.json()
    except ValueError:
        body = {}
    health = body.get("health") if isinstance(body, dict) else None
    return {"job": _call(queue, queue.next_job, agent, health)}


@router.get("/sandbox/agent/jobs/{job_id}/samples/{index}")
@limiter.limit("60/minute")
async def agent_sample(request: Request, job_id: str, index: int) -> Response:
    queue, agent = _agent(request)
    data = _call(queue, queue.sample_bytes, agent, job_id, index)
    return Response(data, media_type="application/octet-stream")


@router.post("/sandbox/agent/jobs/{job_id}/progress")
@limiter.limit("60/minute")
async def agent_progress(request: Request, job_id: str, payload: ProgressRequest) -> dict:
    queue, agent = _agent(request)
    return _call(queue, queue.report_progress, agent, job_id, payload.status)


@router.post("/sandbox/agent/jobs/{job_id}/result")
@limiter.limit("20/minute")
async def agent_result(request: Request, job_id: str) -> dict:
    queue, agent = _agent(request)
    if int(request.headers.get("content-length") or 0) > MAX_RESULT_BYTES:
        raise HTTPException(status_code=413, detail="Result upload is too large.")
    body = await request.body()
    if len(body) > MAX_RESULT_BYTES:
        raise HTTPException(status_code=413, detail="Result upload is too large.")
    try:
        import json
        payload = json.loads(body)
        if not isinstance(payload, dict):
            raise ValueError
    except ValueError:
        raise HTTPException(status_code=400, detail="Result must be a JSON object.") from None
    try:
        return queue.submit_result(agent, job_id, payload)
    except queue.AgentError as exc:
        raise HTTPException(status_code=exc.status, detail=str(exc)) from None
    except Exception as exc:
        logger.warning("Agent result for %s failed (%s)", job_id, type(exc).__name__)
        raise HTTPException(status_code=500, detail="The sandbox result could not be processed.") from None


# -- per-email status (declared last: /sandbox/{email_id} would shadow the routes above) --

@router.get("/sandbox/{email_id}")
@limiter.limit("120/minute")
async def get_sandbox_status(request: Request, email_id: str) -> dict:
    """Current sandbox status and results for an email."""
    from db.connection import get_db
    from db.repository import get_analysis
    from sandbox import current_analysis
    try:
        doc = get_analysis(get_db(), email_id)
        if not doc:
            raise HTTPException(status_code=404, detail="Investigation not found")
        sandbox = current_analysis(email_id, doc.get("sandbox_analysis"))
        doc = get_analysis(get_db(), email_id) or doc
        decision = finalize_verdict(doc.get("verdict"), doc.get("risk_score") or 0)
        return {
            "email_id": email_id,
            "sandbox": sandbox or {"status": "not_applicable", "mode": "none"},
            "risk_score": decision["risk_score"],
            "verdict": decision["verdict"],
            "verdict_band": decision["verdict_band"],
        }
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Sandbox status read failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Failed to retrieve sandbox status")
