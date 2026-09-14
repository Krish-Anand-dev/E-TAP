"""HTTP API for the Threat Email Analysis Platform."""

try:
    from dotenv import load_dotenv
except ImportError:  # pragma: no cover
    load_dotenv = None

if load_dotenv is not None:
    load_dotenv(override=True)

import os
os.environ["KMP_DUPLICATE_LIB_OK"] = "TRUE"
try:
    import torch
except ImportError:
    pass

import logging
import asyncio

from fastapi import FastAPI, File, HTTPException, UploadFile, Request
from fastapi.middleware.cors import CORSMiddleware
from slowapi import Limiter, _rate_limit_exceeded_handler
from slowapi.util import get_remote_address
from slowapi.errors import RateLimitExceeded

from email_parser.unified_parser import UnsupportedFileTypeError
from pipeline import analyze_email_upload

logger = logging.getLogger("phishguard.api")

# Rate limiting: 30 requests per minute per IP address on /analyze (generous for demo/analyst)
limiter = Limiter(key_func=get_remote_address, default_limits=["120/minute"])

app = FastAPI(title="Threat Email Analysis Platform")
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# CORS configuration: default to * in dev, configure ALLOWED_ORIGINS in production
allowed_origins_raw = os.environ.get("ALLOWED_ORIGINS", "*")
allowed_origins = [o.strip() for o in allowed_origins_raw.split(",") if o.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=allowed_origins,
    allow_origin_regex=r"https://.*\.onrender\.com|https://.*\.vercel\.app|http://localhost(:\d+)?|http://127\.0\.0\.1(:\d+)?",
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
    print("  PHISHGUARD // FORENSIC EMAIL INVESTIGATION CONSOLE (BACKEND)")
    print("=" * 68)
    if is_fake:
        print("  [DB STATUS] IN-MEMORY FAKE MONGO (USE_FAKE_DB=1)")
    elif is_atlas:
        host = uri.split("@")[-1].split("/")[0] if "@" in uri else "Atlas Cluster"
        print(f"  [DB STATUS] MONGODB ATLAS CLUSTER (Cloud): {host}")
    else:
        print(f"  [DB STATUS] LOCAL MONGODB: {uri.split('?')[0]}")

    try:
        db = get_db()
        print(f"  [DATABASE]  Active Database: '{db.name}'")
        print(f"  [SECURITY]  Rate Limiter active: 10 req/min per IP (VT internal throttle: 4 req/min)")
        print(f"  [SECURITY]  Upload Limit: 25 MB | XSS Iframe Isolation active")
        print(f"  [STATUS]    Ready to receive forensic email artifacts on port 5000")
    except Exception as exc:
        print(f"  [DB ERROR]  Connection failed: {exc}")
    print("=" * 68 + "\n")


@app.get("/health")
@limiter.exempt
def health() -> dict:
    return {"status": "ok"}


@app.post("/analyze", response_model=None)
@limiter.limit("10/minute")
async def analyze(request: Request, file: UploadFile = File(...)) -> dict:
    filename = file.filename or "uploaded_email.eml"
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
        return await asyncio.to_thread(analyze_email_upload, filename, bytes(raw_bytes))

    except UnsupportedFileTypeError as exc:
        # Clean 400 with descriptive client error
        raise HTTPException(status_code=400, detail=str(exc)) from None
    except HTTPException:
        raise
    except Exception as exc:
        # Prevent stack trace and filesystem path leakage
        logger.exception(f"Unhandled error analyzing {filename}: {exc}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while analyzing the email artifact. Verify the file is an undamaged RFC 822 (.eml) or Outlook (.msg) file."
        ) from None


from typing import Optional, Any
from pydantic import BaseModel, Field


class ChatRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=2000)
    email_id: Optional[str] = Field(None, description="Scope query strictly to the currently opened email artifact")
    email_context: Optional[dict[str, Any]] = Field(None, description="Active email dossier data from frontend")


@app.post("/chat")
@limiter.limit("30/minute")
async def chat(request: Request, payload: ChatRequest) -> dict:
    """SOC Analyst Assistant: queries active opened investigation or historical RAG database."""
    from db.connection import get_db
    from rag.chat import answer_query
    try:
        db = get_db()
        return await asyncio.to_thread(
            answer_query,
            payload.question,
            db,
            payload.email_id,
            payload.email_context,
        )
    except Exception as exc:
        logger.exception(f"Error during RAG chat query: {exc}")
        raise HTTPException(
            status_code=500,
            detail="An error occurred while answering the query against historical investigations."
        ) from None


@app.get("/investigations/{email_id}")
@limiter.limit("60/minute")
async def get_investigation(request: Request, email_id: str) -> dict:
    """Retrieve a specific investigation dossier by ID."""
    from db.connection import get_db
    from db.schema import ANALYSES_COLLECTION
    from bson import ObjectId
    try:
        db = get_db()
        
        # Determine if email_id is a valid ObjectId, otherwise try string search
        query = {"_id": ObjectId(email_id)} if ObjectId.is_valid(email_id) else {"email_id": email_id}
        
        doc = db[ANALYSES_COLLECTION].find_one(query)
        
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
        
        mapped_doc = {
            "email_id": str(doc["_id"]),
            "risk_score": doc.get("risk_score") or fa.get("risk_score", 0),
            "verdict": doc.get("verdict") or fa.get("verdict", "UNKNOWN"),
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
            "stage_status": doc.get("stage_status") or {
                "A": "complete", "B": "complete", "B2": "complete",
                "D": "complete", "E": "live", "F": "complete",
                "G": "gemini", "H": "complete",
            },
        }
        return mapped_doc
    except HTTPException:
        raise
    except Exception as exc:
        logger.exception(f"Error fetching investigation {email_id}: {exc}")
        raise HTTPException(status_code=500, detail="Database query failed")

