"""HTTP API for the Threat Email Analysis Platform."""

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv(override=False)

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
try:
    import torch
except ImportError:
    pass

import logging
import asyncio
from typing import Any, Optional

from fastapi import FastAPI, File, Form, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from email_parser.unified_parser import UnsupportedFileTypeError
from pipeline import analyze_email_upload, VALID_SOURCES
from verdicts import finalize_verdict
from evidence import build_for_stored_record

logger = logging.getLogger("E-TAP.api")

# Rate limiting: 30 requests per minute per IP address on /analyze (generous for demo/analyst)
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])

app = FastAPI(title="Threat Email Analysis Platform")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS uses explicit origins in both local development and production.
allowed_origins_raw = os.environ.get("ALLOWED_ORIGINS", "http://127.0.0.1:5173,http://localhost:5173")
allowed_origins = [o.strip() for o in allowed_origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_methods=["*"],
    allow_headers=["*"],
)

MAX_UPLOAD_SIZE = 25 * 1024 * 1024  # 25 MB max upload limit


@app.on_event("startup")
def startup_event():
    from db.connection import get_db

    uri = os.environ.get("MONGODB_URI", "")
    is_atlas = "mongodb+srv" in uri or ".mongodb.net" in uri
    is_fake = os.environ.get("USE_FAKE_DB") == "1"

    print("\n" + "=" * 68)
    print("  E-TAP // FORENSIC EMAIL INVESTIGATION CONSOLE (BACKEND)")
    print("=" * 68)
    if is_fake:
        print("  [DB STATUS] IN-MEMORY FAKE MONGO (USE_FAKE_DB=1)")
    elif is_atlas:
        host = uri.split("@")[-1].split("/")[0] if "@" in uri else "Atlas Cluster"
        print(f"  [DB STATUS] MONGODB ATLAS CLUSTER (Cloud): {host}")
    else:
        print("  [DB STATUS] LOCAL MONGODB")

    try:
        db = get_db()
        print(f"  [DATABASE]  Active Database: '{db.name}'")
        print(f"  [SECURITY]  Rate limiter configured (per-endpoint limits apply)")
        print(f"  [SECURITY]  Upload Limit: 25 MB | XSS Iframe Isolation active")
        print(f"  [STATUS]    Ready to receive forensic email artifacts on port {os.environ.get('PORT', '5000')}")
    except Exception as exc:
        print(f"  [DB ERROR]  Connection failed ({type(exc).__name__})")
    print("=" * 68 + "\n")


@app.api_route("/", methods=["GET", "HEAD"])
@limiter.exempt
def root() -> dict:
    """Small service index; the root URL is not an analysis endpoint."""
    return {"service": "E-TAP API", "status": "online", "health": "/health", "readiness": "/ready", "docs": "/docs"}


@app.get("/health")
@limiter.exempt
def health() -> dict:
    """Liveness probe: confirms the web process can answer requests."""
    return {"status": "ok", "check": "liveness"}


@app.get("/ready")
@limiter.exempt
def ready() -> Any:
    """Readiness probe: checks that the configured database is reachable."""
    from db.connection import get_db
    from fastapi.responses import JSONResponse
    try:
        db = get_db()
        if os.environ.get("USE_FAKE_DB") == "1":
            database_status = "in_memory_fake"
        else:
            # MongoDB Database.command performs a real round-trip ping.
            db.command("ping")
            database_status = "ok"
        return {"status": "ready", "checks": {"database": database_status}}
    except Exception as exc:
        logger.warning("Readiness check failed (%s)", type(exc).__name__)
        return JSONResponse(
            status_code=503,
            content={"status": "not_ready", "checks": {"database": "unavailable"}},
        )


@app.post("/analyze", response_model=None)
@limiter.limit("10/minute")
async def analyze(
    request: Request,
    file: UploadFile = File(...),
    source: str | None = Form(None),
) -> dict:
    """
    `source` is optional. Send "quick_content_check" when the .eml was rebuilt
    from visible mail-client text (e.g. the Gmail extension) so the backend
    does not pretend to have original headers. Omitted/unknown = full message.
    """
    filename = file.filename or "uploaded_email.eml"
    if source is not None and source not in VALID_SOURCES:
        raise HTTPException(status_code=400, detail="Unsupported analysis source.")
    try:
        # Enforce streaming read with hard maximum size limit (25MB)
        raw_bytes = bytearray()
        chunk_size = 64 * 1024
        while True:
            chunk = await file.read(chunk_size)
            if not chunk:
                break
            raw_bytes.extend(chunk)
            if len(raw_bytes) > MAX_UPLOAD_SIZE:
                raise HTTPException(
                    status_code=413,
                    detail=f"Uploaded artifact exceeds maximum size limit of {MAX_UPLOAD_SIZE // (1024 * 1024)}MB."
                )

        if not raw_bytes:
            raise HTTPException(status_code=400, detail="Uploaded file is empty.")

        # Run heavy synchronous pipeline (WHOIS, VirusTotal, Gemini, DB) in worker thread
        # to ensure the main asyncio event loop never freezes during /health checks
        report = await asyncio.to_thread(analyze_email_upload, filename, bytes(raw_bytes), source)
        from workflow_c import finish_analysis
        return await asyncio.to_thread(finish_analysis, report)

    except UnsupportedFileTypeError as exc:
        # Clean 400 with descriptive client error
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except HTTPException:
        raise
    except Exception as exc:
        # Prevent stack trace and filesystem path leakage
        logger.warning("Analysis failed (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=500,
            detail="An error occurred while analyzing the email artifact. Verify the file is an undamaged RFC 822 (.eml) or Outlook (.msg) file."
        ) from None


from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)
    email_id: Optional[str] = Field(None, description="Scope query strictly to the currently opened email artifact")
    email_context: Optional[dict[str, Any]] = Field(None, description="Active email dossier data from frontend")


@app.get('/investigations')
async def investigations(request: Request, offset: int = 0, limit: int = 50):
    from db.connection import get_db
    if offset < 0 or offset > 5000 or not 1 <= limit <= 100:
        raise HTTPException(400, 'Invalid page')
    docs = list(get_db()['analyzed_emails'].find({}, {'subject': 1, 'verdict': 1, 'analyzed_at': 1, 'workflow.state':1}).sort('analyzed_at', -1))
    return [{'email_id': str(d['_id']), 'subject': d.get('subject'), 'verdict': d.get('verdict'), 'review_state': (d.get('workflow') or {}).get('state', d.get('workflow.state', 'unrecorded'))} for d in docs[offset:offset+limit]]


@app.get('/campaigns')
async def campaigns(request: Request):
    from correlation.queries import list_campaigns
    return list_campaigns()


@app.post("/chat")
@limiter.limit("30/minute")
async def chat(request: Request, payload: ChatRequest) -> dict:
    """SOC Analyst Assistant: queries active opened investigation or historical RAG database."""
    from db.connection import get_db
    from rag.chat import answer_query
    try:
        db = get_db()
        if payload.email_context is not None:
            raise HTTPException(400, "Client-supplied investigation context is not accepted; use email_id.")
        if payload.email_id:
            from db.repository import get_analysis
            if get_analysis(db, payload.email_id) is None:
                raise HTTPException(404, "Investigation not found")
        return await asyncio.to_thread(
            answer_query,
            payload.question,
            db,
            payload.email_id,
            None,
        )
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Chat failed (%s)", type(exc).__name__)
        raise HTTPException(
            status_code=500,
            detail="An error occurred while answering the query against historical investigations."
        ) from None


@app.get("/investigations/{email_id}")
@limiter.limit("60/minute")
async def get_investigation(request: Request, email_id: str) -> dict:
    """Retrieve a specific investigation dossier by ID."""
    from db.connection import get_db
    try:
        db = get_db()
        
        from db.repository import get_analysis
        doc = get_analysis(db, email_id)
        
        if not doc:
            raise HTTPException(status_code=404, detail="Investigation not found")
            
        # Build the exact same shape that pipeline.py returns to the frontend.
        # DB keys (from correlation/engine.py insert):
        #   subject, from_email, to_email, email_date, source_format,
        #   header_analysis, attachment_analysis, threat_intel_analysis,
        #   content_analysis, ioc_analysis, campaign_id
        # DB keys (from pipeline.py update_analysis_fields):
        #   final_assessment, mitre_attack, risk_score, verdict,
        #   triage, graph_diffusion
        
        fa = doc.get("final_assessment") or {}

        # Same verdict/band logic as live analyses, so records saved before
        # verdict normalization existed render consistently.
        decision = finalize_verdict(
            doc.get("verdict") or fa.get("verdict"),
            doc.get("risk_score") if doc.get("risk_score") is not None else fa.get("risk_score", 0),
        )

        mapped_doc = {
            "email_id": str(doc["_id"]),
            "risk_score": decision["risk_score"],
            "verdict": decision["verdict"],
            "verdict_band": decision["verdict_band"],
            "analysis_provenance": doc.get("analysis_provenance"),
            # Stored with the record when available; older records are rebuilt
            # from what they kept and marked `reconstructed`.
            "evidence_report": doc.get("evidence_report") if (doc.get("evidence_report") or {}).get("schema_version") == 2 else build_for_stored_record(doc, decision),
            # B5/B6/B10: absent on records saved before these existed (not rebuilt:
            # the stored record never kept the HTML or the images).
            "link_analysis": doc.get("link_analysis"),
            "qr_trace": doc.get("qr_trace"),
            "privacy_report": doc.get("privacy_report"),
            "baseline_context": doc.get("baseline_context"),
            "case": doc.get("case"),
            "retention": {"days": doc.get("retention_days", 30), "expires_at": doc.get("expires_at")},
            "provider_status": doc.get("provider_status"),
            "email": {
                "subject": doc.get("subject", "(No Subject Header)"),
                "from_raw": doc.get("from_email", ""),
                "from_email": doc.get("from_email", "N/A"),
                "to": doc.get("to_email", "Undisclosed Recipients"),
                "date": doc.get("email_date", ""),
                "source_format": doc.get("source_format", "eml"),
                "message_id": doc.get("message_id", ""),
            },
            "headers": doc.get("header_analysis") or {},
            "attachments": (doc.get("attachment_analysis") or {}).get("attachments", []),
            "iocs": doc.get("ioc_analysis") or {},
            "threat_intel": doc.get("threat_intel_analysis") or {},
            "correlation": {
                "email_id": str(doc["_id"]),
                "campaign_id": doc.get("campaign_id", ""),
            },
            "graph_diffusion": doc.get("graph_diffusion") or {},
            "ai_analysis": {
                "content_classification": doc.get("content_analysis") or {},
                "final_assessment": fa,
            },
            "mitre_attack": doc.get("mitre_attack") or [],
            "triage": doc.get("triage") or {},
            # Older records predate stored stage_status; report "unknown" rather
            # than inventing "live"/"gemini" for stages we cannot vouch for.
            "stage_status": doc.get("stage_status") or {"E": "unknown", "G": "unknown"},
        }
        return mapped_doc
    except HTTPException:
        raise
    except Exception as exc:
        logger.warning("Investigation read failed (%s)", type(exc).__name__)
        raise HTTPException(status_code=500, detail="Database query failed")


from workflow_c import router as workflow_router
app.include_router(workflow_router)
