"""Link a WhatsApp number to a signed-in E-TAP account, without ever messaging the number.

Replies can be blocked by Meta (account locks, expired tokens), so the link does not rely on them and
is proven in the direction that always works: the signed-in person asks the website for a short code, then sends that code
to the bot from their WhatsApp. When the bot receives it, the number belongs to that account, and
anything the number forwards afterwards is saved as that account's report ("My reports").

The phone number is stored only as a keyed hash (HMAC), never as plain text.
"""
from __future__ import annotations

import hashlib
import hmac
import logging
import os
import re
import secrets
from datetime import datetime, timedelta, timezone
from typing import Optional

from fastapi import APIRouter, HTTPException, Request

logger = logging.getLogger(__name__)

CODES = "whatsapp_link_codes"
LINKS = "whatsapp_links"
CODE_TTL = timedelta(minutes=15)

router = APIRouter(prefix="/whatsapp/link", tags=["whatsapp"])

_CODE_MESSAGE = re.compile(r"^\s*etap[\s-]?(\d{6})\s*[.!]?\s*$", re.IGNORECASE)


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _db():
    from db.connection import get_db
    return get_db()


def _secret() -> bytes:
    from login import _secret as login_secret
    return login_secret()


def normalize_phone(raw: str) -> str:
    """Digits only: Meta sends '918595710385', Twilio sends 'whatsapp:+918595710385'."""
    return re.sub(r"\D", "", str(raw or ""))


def phone_hash(raw: str) -> str:
    return hmac.new(_secret(), f"phone:{normalize_phone(raw)}".encode(), hashlib.sha256).hexdigest()


def _code_hash(code: str) -> str:
    return hmac.new(_secret(), f"link:{code}".encode(), hashlib.sha256).hexdigest()


def extract_code(text: str) -> Optional[str]:
    """The six digits when the whole message is a link code like 'ETAP-123456', else None."""
    match = _CODE_MESSAGE.match(text or "")
    return match.group(1) if match else None


def bot_number() -> str:
    return os.getenv("WHATSAPP_BOT_NUMBER", "").strip()


def issue_code(owner: str) -> str:
    """A fresh code for this account; any earlier unused code of theirs stops working."""
    db = _db()
    db[CODES].delete_many({"owner": owner})
    code = f"{secrets.randbelow(10 ** 6):06d}"
    db[CODES].insert_one({
        "code_hash": _code_hash(code), "owner": owner, "used": False,
        "created_at": _now(), "expires_at": _now() + CODE_TTL,
    })
    try:
        db[CODES].create_index("expires_at", expireAfterSeconds=0)
    except Exception:
        pass
    return code


def claim_code(sender: str, code: str) -> Optional[str]:
    """Take the code atomically and link the sender to its account. Returns the account email."""
    try:
        db = _db()
        doc = db[CODES].find_one_and_update(
            {"code_hash": _code_hash(code), "used": False, "expires_at": {"$gt": _now()}},
            {"$set": {"used": True}},
        )
        if not doc:
            return None
        owner = doc["owner"]
        digest = phone_hash(sender)
        db[LINKS].delete_many({"$or": [{"owner": owner}, {"phone_hash": digest}]})  # one number per account
        db[LINKS].insert_one({"owner": owner, "phone_hash": digest, "linked_at": _now()})
        return owner
    except Exception as exc:
        logger.warning("WhatsApp link failed (%s)", type(exc).__name__)
        return None


def owner_for(sender: str) -> Optional[str]:
    """The account a number is linked to, or None. Never raises."""
    try:
        doc = _db()[LINKS].find_one({"phone_hash": phone_hash(sender)})
        return doc["owner"] if doc else None
    except Exception as exc:
        logger.warning("WhatsApp link lookup failed (%s)", type(exc).__name__)
        return None


def _user(request: Request) -> str:
    from login import current_user
    owner = current_user(request)
    if not owner:
        raise HTTPException(status_code=401, detail="Sign in first.")
    return owner


@router.get("")
def link_status(request: Request) -> dict:
    owner = _user(request)
    doc = _db()[LINKS].find_one({"owner": owner})
    return {"linked": bool(doc), "linked_at": doc["linked_at"].isoformat() if doc else None,
            "bot_number": bot_number()}


@router.post("/code")
def link_code(request: Request) -> dict:
    owner = _user(request)
    return {"code": f"ETAP-{issue_code(owner)}", "expires_in_minutes": int(CODE_TTL.total_seconds() // 60),
            "bot_number": bot_number()}


@router.delete("")
def unlink(request: Request) -> dict:
    owner = _user(request)
    _db()[LINKS].delete_many({"owner": owner})
    _db()[CODES].delete_many({"owner": owner})
    return {"linked": False}
