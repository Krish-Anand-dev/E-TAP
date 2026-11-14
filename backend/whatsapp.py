"""
WhatsApp bot (Twilio sandbox).

Forward a suspicious message or file to the bot's WhatsApp number. It answers at once
("checking"), runs the normal static analysis in the background, then sends the verdict, the
main reasons, what to do next and a link to the full report.

  * Same pipeline as the website's "pasted message" path: the text and files are packaged into
    an .eml with no sender headers and analysed with source "forwarded_message", so sender checks
    are skipped and links, QR codes, OCR, reputation and AI still run.
  * Static analysis only. The sandbox is never requested, and files are never opened.
  * Twilio gives up on a webhook after about 15 seconds, so the webhook only validates and
    acknowledges; the analysis and the real reply happen on a worker thread.
  * Every request must carry a valid X-Twilio-Signature. Without TWILIO_AUTH_TOKEN the route is off.

Configuration (all environment variables)
  TWILIO_ACCOUNT_SID, TWILIO_AUTH_TOKEN   from the Twilio console
  TWILIO_WHATSAPP_FROM                    the sandbox number, e.g. whatsapp:+14155238886
  PUBLIC_API_URL                          this server's public address (used to check signatures)
  PUBLIC_FRONTEND_URL                     the website address used in report links
  WHATSAPP_MAX_PER_HOUR                   messages one number may send per hour (default 10)
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import html
import logging
import mimetypes
import os
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from email.message import EmailMessage
from typing import Optional
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

logger = logging.getLogger("E-TAP.whatsapp")

router = APIRouter(prefix="/whatsapp", tags=["whatsapp"])

MAX_FILES = 3
MAX_FILE_BYTES = 10 * 1024 * 1024
MAX_TOTAL_BYTES = 15 * 1024 * 1024
MAX_REPLY_CHARS = 1500  # WhatsApp via Twilio accepts 1600
DEFAULT_FRONTEND = "https://e-tap-clean.vercel.app"
HELP_WORDS = {"hi", "hello", "hey", "help", "start", "menu"}
_URL_PATTERN = re.compile(r"\bhttps?://[^\s<>\"')]+|\bwww\.[^\s<>\"')]+", re.IGNORECASE)

_seen: dict[str, float] = {}
_sender_hits: dict[str, list[float]] = {}
_lock = threading.Lock()
_executor = ThreadPoolExecutor(max_workers=2, thread_name_prefix="etap-whatsapp")


def _submit(task, *args) -> None:
    """Run a task off the request thread (tests replace this to run inline)."""
    _executor.submit(task, *args)


# --- Twilio plumbing --------------------------------------------------------

def twilio_signature(url: str, params: dict, auth_token: str) -> str:
    """Twilio's request signature: HMAC-SHA1 over the URL plus every field name and value, sorted."""
    payload = url + "".join(f"{key}{params[key]}" for key in sorted(params))
    digest = hmac.new(auth_token.encode(), payload.encode(), hashlib.sha1).digest()
    return base64.b64encode(digest).decode()


def _webhook_url(request: Request) -> str:
    """The exact address Twilio called, rebuilt from PUBLIC_API_URL or the proxy headers."""
    configured = os.getenv("PUBLIC_API_URL", "").strip().rstrip("/")
    if configured.startswith(("http://", "https://")):
        base = configured
    else:
        proto = (request.headers.get("x-forwarded-proto") or request.url.scheme).split(",")[0].strip()
        host = (request.headers.get("x-forwarded-host") or request.headers.get("host")
                or request.url.netloc).split(",")[0].strip()
        base = f"{proto}://{host}"
    query = f"?{request.url.query}" if request.url.query else ""
    return f"{base}{request.url.path}{query}"


def _twiml(message: Optional[str] = None) -> Response:
    body = f"<Response><Message>{html.escape(message)}</Message></Response>" if message else "<Response/>"
    return Response(content=body, media_type="application/xml")


def _allowed_media_host(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and (host == "twilio.com" or host.endswith(".twilio.com")
                                         or host.endswith(".twiliocdn.com"))


def send_whatsapp(to: str, body: str) -> bool:
    """Send one message. Never raises: a failed reply must not crash the worker."""
    sid = os.getenv("TWILIO_ACCOUNT_SID", "")
    token = os.getenv("TWILIO_AUTH_TOKEN", "")
    sender = os.getenv("TWILIO_WHATSAPP_FROM", "")
    if not (sid and token and sender):
        logger.warning("WhatsApp reply not sent: Twilio sender is not configured")
        return False
    try:
        response = requests.post(
            f"https://api.twilio.com/2010-04-01/Accounts/{sid}/Messages.json",
            auth=(sid, token), data={"From": sender, "To": to, "Body": body[:1600]}, timeout=15)
        if response.status_code >= 300:
            logger.warning("WhatsApp reply refused (status %s)", response.status_code)
            return False
        return True
    except Exception as exc:
        logger.warning("WhatsApp reply failed (%s)", type(exc).__name__)
        return False


def fetch_media(url: str) -> Optional[bytes]:
    """Download one forwarded file from Twilio. None if it is not allowed, too big or unreachable."""
    if not _allowed_media_host(url):
        return None
    try:
        response = requests.get(url, auth=(os.getenv("TWILIO_ACCOUNT_SID", ""), os.getenv("TWILIO_AUTH_TOKEN", "")),
                                timeout=20, stream=True)
        if response.status_code >= 300:
            return None
        data = bytearray()
        for chunk in response.iter_content(64 * 1024):
            data.extend(chunk)
            if len(data) > MAX_FILE_BYTES:
                return None
        return bytes(data) or None
    except Exception as exc:
        logger.warning("Media download failed (%s)", type(exc).__name__)
        return None


# --- the message as an .eml -------------------------------------------------

def linkify(text: str) -> str:
    """The text as simple HTML with every link clickable, so link checks see them like in an email."""
    out, last = "", 0
    for match in _URL_PATTERN.finditer(text):
        url = match.group(0).rstrip(".,;:!?")
        href = "http://" + url if url.lower().startswith("www.") else url
        out += html.escape(text[last:match.start()])
        out += f'<a href="{html.escape(href)}">{html.escape(url)}</a>'
        last = match.start() + len(url)
    out += html.escape(text[last:])
    return f"<html><body><p>{out.replace(chr(10), '<br>' + chr(10))}</p></body></html>"


def build_eml(text: str, files: list[tuple[str, str, bytes]], message_sid: str) -> bytes:
    """text + [(filename, content_type, bytes)] -> an .eml with no From, To or Date lines."""
    body = (text or "").replace("\r\n", "\n").strip()
    first_line = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")
    first_line = re.sub(r"\s+", " ", re.sub(r"[^\x20-\x7e]+", " ", first_line)).strip()[:60]
    msg = EmailMessage()
    msg["Subject"] = f"WhatsApp message: {first_line}" if first_line else "WhatsApp message"
    msg["Message-ID"] = f"<whatsapp-{re.sub(r'[^A-Za-z0-9]', '', message_sid) or int(time.time())}@etap.local>"
    msg.set_content(body or "(no text, files only)")
    msg.add_alternative(linkify(body), subtype="html")
    for name, content_type, data in files:
        maintype, _, subtype = (content_type or "application/octet-stream").partition("/")
        msg.add_attachment(data, maintype=maintype or "application", subtype=subtype or "octet-stream",
                           filename=name)
    return bytes(msg)


# --- the reply --------------------------------------------------------------

def frontend_url() -> str:
    return (os.getenv("PUBLIC_FRONTEND_URL", "").strip().rstrip("/") or DEFAULT_FRONTEND)


def reply_text(report: dict, skipped_files: int = 0) -> str:
    """Plain-language result. It reuses the share card's wording so the two always agree."""
    import share_card
    from verdicts import finalize_verdict
    decision = finalize_verdict(report.get("verdict"), report.get("risk_score"))
    evidence = report.get("evidence_report") or {}
    conclusion = evidence.get("conclusion") or {}
    key = share_card.card_key(decision["verdict_band"], conclusion.get("limitations"))
    headline = share_card.HEADLINES.get(key) or str(decision["verdict"]).upper()
    lines = [f"E-TAP result: {headline}", f"Risk score {int(round(decision['risk_score']))} of 100", "Why:"]
    lines += [f"- {reason}" for reason in share_card.reasons_for(key, evidence.get("top_reasons"))]
    lines.append(f"What to do: {share_card.NEXT_STEP[key]}")
    if skipped_files:
        lines.append(f"Note: {skipped_files} file(s) could not be checked (too large or unreachable).")
    if report.get("email_id"):
        lines.append(f"Full report: {frontend_url()}/?dossier={report['email_id']}")
    return "\n".join(lines)[:MAX_REPLY_CHARS]


HELP_TEXT = ("Hi, I'm E-TAP. Forward me a suspicious message, link or file and I will check it "
             "and send back a plain-language result with a link to the full report. "
             "Checks run on the content only; a report is saved on the E-TAP site, where you can delete it.")
BUSY_TEXT = "You have sent a lot of messages in the last hour. Please try again a little later."
ACK_TEXT = "Got it. Checking now. This can take up to a minute."
FAILED_TEXT = "Sorry, I could not check that message. Please try again, or upload it on the E-TAP site."


# --- background work --------------------------------------------------------

def _process(sender: str, text: str, media: list[tuple[str, str]], message_sid: str) -> None:
    """Download files, analyse, and send the answer. Runs on a worker thread; never raises."""
    try:
        from pipeline import SOURCE_FORWARDED, analyze_email_upload
        from workflow_c import finish_analysis

        files: list[tuple[str, str, bytes]] = []
        total, skipped = 0, 0
        for index, (url, content_type) in enumerate(media[:MAX_FILES], start=1):
            data = fetch_media(url)
            if data is None or total + len(data) > MAX_TOTAL_BYTES:
                skipped += 1
                continue
            total += len(data)
            extension = mimetypes.guess_extension((content_type or "").split(";")[0].strip()) or ".bin"
            files.append((f"whatsapp-file-{index}{extension}", content_type, data))
        skipped += max(0, len(media) - MAX_FILES)

        if not text.strip() and not files:
            send_whatsapp(sender, FAILED_TEXT)
            return
        eml = build_eml(text, files, message_sid)
        report = analyze_email_upload("whatsapp-message.eml", eml, SOURCE_FORWARDED, None,
                                      {"requested": False, "token": None})
        report = finish_analysis(report)
        send_whatsapp(sender, reply_text(report, skipped))
    except Exception as exc:
        logger.warning("WhatsApp analysis failed (%s)", type(exc).__name__)
        send_whatsapp(sender, FAILED_TEXT)


def _first_time(message_sid: str) -> bool:
    """False when Twilio retries a message we already took."""
    now = time.time()
    with _lock:
        for key in [k for k, t in _seen.items() if now - t > 3600]:
            _seen.pop(key, None)
        if message_sid in _seen:
            return False
        _seen[message_sid] = now
        return True


def _within_limit(sender: str) -> bool:
    try:
        limit = max(1, int(os.getenv("WHATSAPP_MAX_PER_HOUR", "10")))
    except ValueError:
        limit = 10
    now = time.time()
    with _lock:
        hits = [t for t in _sender_hits.get(sender, []) if now - t < 3600]
        if len(hits) >= limit:
            _sender_hits[sender] = hits
            return False
        hits.append(now)
        _sender_hits[sender] = hits
        return True


@router.post("/twilio")
async def twilio_webhook(request: Request) -> Response:
    token = os.getenv("TWILIO_AUTH_TOKEN", "")
    if not token:
        raise HTTPException(status_code=503, detail="The WhatsApp bot is not set up on this server.")
    form = await request.form()
    params = {key: str(value) for key, value in form.items()}
    expected = twilio_signature(_webhook_url(request), params, token)
    if not hmac.compare_digest(expected, request.headers.get("x-twilio-signature", "")):
        raise HTTPException(status_code=403, detail="Invalid signature.")

    sender = params.get("From", "")
    message_sid = params.get("MessageSid") or params.get("SmsMessageSid") or ""
    text = params.get("Body", "").strip()
    try:
        count = max(0, min(int(params.get("NumMedia", "0")), 10))
    except ValueError:
        count = 0
    media = [(params[f"MediaUrl{i}"], params.get(f"MediaContentType{i}", ""))
             for i in range(count) if params.get(f"MediaUrl{i}")]

    if not sender:
        raise HTTPException(status_code=400, detail="Missing sender.")
    if message_sid and not _first_time(message_sid):
        return _twiml()
    if not media and (not text or text.lower() in HELP_WORDS):
        return _twiml(HELP_TEXT)
    if not _within_limit(sender):
        return _twiml(BUSY_TEXT)

    _submit(_process, sender, text, media, message_sid)
    return _twiml(ACK_TEXT)
