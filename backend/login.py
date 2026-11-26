"""
Optional email sign-in (one-time code, no passwords).

Anonymous use is unchanged: every analysis route still works without signing
in. Signing in only adds an owner to the reports you create so you can list
"my reports" (`GET /investigations?mine=1`).

Flow
  POST /auth/request-code {email}        -> emails a 6-digit code (valid 10 minutes)
  POST /auth/verify-code  {email, code}  -> {token, email, expires_at}
  GET  /auth/me           (Bearer token) -> {email}
  POST /auth/logout       (Bearer token) -> {ok}

Design notes
  * Codes are stored only as an HMAC with a server secret; five wrong tries burn the code.
  * Session tokens are random and opaque; only their SHA-256 is stored, so a database leak
    cannot be replayed and a session can be revoked by deleting its row.
  * Free email delivery goes over an HTTPS API (Brevo or Resend). Render's free tier blocks
    outbound SMTP, so plain SMTP would not work there.
  * Nothing here raises on the anonymous path: `current_user` returns None on any problem.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
import threading
import time
from datetime import datetime, timedelta, timezone
from typing import Optional

import requests
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

logger = logging.getLogger("E-TAP.login")

CODES = "login_codes"
SESSIONS = "login_sessions"

CODE_TTL = timedelta(minutes=10)
SESSION_TTL = timedelta(days=30)
MAX_ATTEMPTS = 5
RESEND_COOLDOWN_SECONDS = 60
MAX_CODES_PER_HOUR = 5
IP_MAX_REQUESTS_PER_HOUR = 10

_EMAIL_RE = re.compile(r"^[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}$")
_FALLBACK_SECRET = secrets.token_bytes(32)  # per-process; set AUTH_SECRET so codes survive a restart
_ip_hits: dict[str, list[float]] = {}
_ip_lock = threading.Lock()

router = APIRouter(prefix="/auth", tags=["auth"])


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _aware(value: datetime) -> datetime:
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


def _db():
    from db.connection import get_db
    return get_db()


def _secret() -> bytes:
    configured = os.environ.get("AUTH_SECRET", "")
    return configured.encode() if configured else _FALLBACK_SECRET


def normalize_email(raw: str) -> str:
    email = (raw or "").strip().lower()
    if len(email) > 254 or not _EMAIL_RE.match(email):
        raise HTTPException(status_code=400, detail="Enter a valid email address.")
    return email


def _code_hash(email: str, code: str) -> str:
    return hmac.new(_secret(), f"{email}:{code}".encode(), hashlib.sha256).hexdigest()


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _ip_allowed(ip: str) -> bool:
    now = time.time()
    with _ip_lock:
        hits = [t for t in _ip_hits.get(ip, []) if now - t < 3600]
        if len(hits) >= IP_MAX_REQUESTS_PER_HOUR:
            _ip_hits[ip] = hits
            return False
        hits.append(now)
        _ip_hits[ip] = hits
        if len(_ip_hits) > 5000:  # keep memory bounded
            for key in [k for k, v in _ip_hits.items() if not v or now - v[-1] > 3600]:
                _ip_hits.pop(key, None)
        return True


# --- delivery ---------------------------------------------------------------

def _message(code: str) -> tuple[str, str]:
    subject = "Your E-TAP sign-in code"
    body = (f"Your E-TAP sign-in code is {code}.\n\n"
            "It works for 10 minutes. If you did not ask for it, ignore this email.")
    return subject, body


def delivery_configured() -> bool:
    return bool(os.environ.get("BREVO_API_KEY") or os.environ.get("RESEND_API_KEY"))


def send_code_email(email: str, code: str) -> None:
    """Send the code through Brevo or Resend. Raises RuntimeError on failure."""
    subject, body = _message(code)
    sender = os.environ.get("LOGIN_FROM_EMAIL", "").strip()
    name = os.environ.get("LOGIN_FROM_NAME", "E-TAP").strip() or "E-TAP"
    if os.environ.get("BREVO_API_KEY"):
        if not sender:
            raise RuntimeError("LOGIN_FROM_EMAIL is not set")
        response = requests.post(
            "https://api.brevo.com/v3/smtp/email",
            headers={"api-key": os.environ["BREVO_API_KEY"], "accept": "application/json"},
            json={"sender": {"email": sender, "name": name}, "to": [{"email": email}],
                  "subject": subject, "textContent": body},
            timeout=10,
        )
    elif os.environ.get("RESEND_API_KEY"):
        response = requests.post(
            "https://api.resend.com/emails",
            headers={"Authorization": f"Bearer {os.environ['RESEND_API_KEY']}"},
            json={"from": f"{name} <{sender or 'onboarding@resend.dev'}>", "to": [email],
                  "subject": subject, "text": body},
            timeout=10,
        )
    else:
        raise RuntimeError("no email provider configured")
    if response.status_code >= 300:
        raise RuntimeError(f"email provider returned {response.status_code}")


# --- sessions ---------------------------------------------------------------

def _bearer(request: Request) -> Optional[str]:
    header = request.headers.get("authorization", "")
    scheme, _, token = header.partition(" ")
    if scheme.lower() != "bearer" or not token.strip():
        return None
    return token.strip()


def current_user(request: Request) -> Optional[str]:
    """The signed-in email, or None. Never raises, so anonymous use cannot break."""
    token = _bearer(request)
    if not token:
        return None
    try:
        session = _db()[SESSIONS].find_one({"token_hash": _token_hash(token)})
        if not session or _aware(session["expires_at"]) <= _now():
            return None
        return session["email"]
    except Exception as exc:
        logger.warning("Session lookup failed (%s)", type(exc).__name__)
        return None


def tag_owner(email_id: Optional[str], owner: Optional[str]) -> None:
    """Record who created a report. A failure must never break an analysis."""
    if not email_id or not owner:
        return
    try:
        from db.repository import update_analysis_fields
        update_analysis_fields(_db(), str(email_id), {"owner_email": owner})
    except Exception as exc:
        logger.warning("Could not tag report owner (%s)", type(exc).__name__)


def _ensure_ttl_indexes(db) -> None:
    try:
        db[CODES].create_index("expires_at", expireAfterSeconds=0)
        db[SESSIONS].create_index("expires_at", expireAfterSeconds=0)
        db[SESSIONS].create_index("token_hash", unique=True)
    except Exception:
        pass  # indexes are housekeeping; expiry is also enforced on every read


# --- routes -----------------------------------------------------------------

class CodeRequest(BaseModel):
    email: str = Field(..., max_length=254)


class CodeVerify(BaseModel):
    email: str = Field(..., max_length=254)
    code: str = Field(..., min_length=4, max_length=12)


@router.get("/status")
def status() -> dict:
    """Lets the UI hide sign-in when email delivery is not configured."""
    return {"enabled": delivery_configured() or os.environ.get("AUTH_DEV_ECHO") == "1"}


@router.post("/request-code")
def request_code(body: CodeRequest, request: Request) -> dict:
    email = normalize_email(body.email)
    ip = request.client.host if request.client else "unknown"
    if not _ip_allowed(ip):
        raise HTTPException(status_code=429, detail="Too many sign-in requests. Try again later.")
    dev_echo = os.environ.get("AUTH_DEV_ECHO") == "1" and not delivery_configured()
    if not delivery_configured() and not dev_echo:
        raise HTTPException(status_code=503, detail="Email sign-in is not set up on this server.")

    db = _db()
    _ensure_ttl_indexes(db)
    now = _now()
    previous = db[CODES].find_one({"email": email})
    sent_in_hour = 0
    hour_start = now
    if previous:
        last_sent = _aware(previous["last_sent_at"])
        if (now - last_sent).total_seconds() < RESEND_COOLDOWN_SECONDS:
            raise HTTPException(status_code=429, detail="Wait a minute before asking for another code.")
        hour_start = _aware(previous["hour_start"])
        sent_in_hour = previous["sent_in_hour"]
        if now - hour_start >= timedelta(hours=1):
            hour_start, sent_in_hour = now, 0
        if sent_in_hour >= MAX_CODES_PER_HOUR:
            raise HTTPException(status_code=429, detail="Too many codes requested for this email. Try again later.")

    code = f"{secrets.randbelow(1_000_000):06d}"
    db[CODES].delete_many({"email": email})
    db[CODES].insert_one({
        "email": email, "code_hash": _code_hash(email, code), "attempts": 0,
        "expires_at": now + CODE_TTL, "last_sent_at": now,
        "hour_start": hour_start, "sent_in_hour": sent_in_hour + 1,
    })
    if dev_echo:
        return {"ok": True, "dev_code": code}
    try:
        send_code_email(email, code)
    except Exception as exc:
        logger.warning("Sign-in email failed (%s)", type(exc).__name__)
        db[CODES].delete_many({"email": email})
        raise HTTPException(status_code=503, detail="Could not send the code. Try again in a moment.") from None
    return {"ok": True}


@router.post("/verify-code")
def verify_code(body: CodeVerify) -> dict:
    email = normalize_email(body.email)
    db = _db()
    entry = db[CODES].find_one({"email": email})
    if not entry or _aware(entry["expires_at"]) <= _now():
        db[CODES].delete_many({"email": email})
        raise HTTPException(status_code=400, detail="That code has expired. Ask for a new one.")
    # Count the try in the same step that allows it, so guesses sent at the same
    # moment cannot all slip in under the limit.
    allowed = db[CODES].find_one_and_update(
        {"email": email, "attempts": {"$lt": MAX_ATTEMPTS}}, {"$inc": {"attempts": 1}})
    if not allowed:
        db[CODES].delete_many({"email": email})
        raise HTTPException(status_code=429, detail="Too many wrong tries. Ask for a new code.")
    if not hmac.compare_digest(entry["code_hash"], _code_hash(email, body.code.strip())):
        raise HTTPException(status_code=400, detail="That code is not right.")

    db[CODES].delete_many({"email": email})
    token = secrets.token_urlsafe(32)
    expires = _now() + SESSION_TTL
    db[SESSIONS].insert_one({"token_hash": _token_hash(token), "email": email,
                             "created_at": _now(), "expires_at": expires})
    return {"token": token, "email": email, "expires_at": expires.isoformat()}


@router.get("/me")
def me(request: Request) -> dict:
    email = current_user(request)
    if not email:
        raise HTTPException(status_code=401, detail="Not signed in.")
    return {"email": email}


@router.post("/logout")
def logout(request: Request) -> dict:
    token = _bearer(request)
    if token:
        try:
            _db()[SESSIONS].delete_many({"token_hash": _token_hash(token)})
        except Exception as exc:
            logger.warning("Logout cleanup failed (%s)", type(exc).__name__)
    return {"ok": True}
