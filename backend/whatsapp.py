"""
WhatsApp bot. Two providers share one worker: Meta's WhatsApp Cloud API (free test number,
webhook set in the Meta developer dashboard: /whatsapp/meta) and the Twilio sandbox
(/whatsapp/twilio, which needs a paid Twilio account to set its webhook). Each is off unless
its own secret is configured.

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
  Meta Cloud API:
    META_ACCESS_TOKEN       token that may send WhatsApp messages (a permanent system-user token;
                            the dashboard's temporary token lasts about a day)
    META_PHONE_NUMBER_ID    the sending number's id, from the dashboard's API Setup page
    META_VERIFY_TOKEN       any secret string you choose; typed into the webhook form too
    META_APP_SECRET         the app's secret (App settings > Basic); used to check signatures
    META_GRAPH_VERSION      optional, defaults to v23.0
  Twilio:
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
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Optional
from urllib.parse import urlparse

import requests
from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import Response

logger = logging.getLogger("E-TAP.whatsapp")

router = APIRouter(prefix="/whatsapp", tags=["whatsapp"])

MAX_FILES = 5                        # the website's pasted-message form also takes 5
MAX_FILE_BYTES = 25 * 1024 * 1024    # same ceiling as an upload on the website
MAX_TOTAL_BYTES = 25 * 1024 * 1024
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


_CRLF = b"\r\n"
_B64_STEP = 57 * 1024  # a whole number of 76-character base64 lines (57 raw bytes each)
_CONTENT_TYPE = re.compile(r"^[A-Za-z0-9][\w.+-]*/[A-Za-z0-9][\w.+-]*$")


def _base64_lines(data) -> list[bytes]:
    """base64 in 76-character lines, made in small pieces so a 25 MB file never costs several copies."""
    view = memoryview(data)
    parts = []
    for start in range(0, len(view), _B64_STEP):
        encoded = base64.b64encode(view[start:start + _B64_STEP])
        parts.append(_CRLF.join(encoded[i:i + 76] for i in range(0, len(encoded), 76)) + _CRLF)
    return parts


def build_eml(text: str, files: list[tuple[str, str, bytes]], message_sid: str) -> bytes:
    """text + [(filename, content_type, bytes)] -> an .eml with no From, To or Date lines.

    Written by hand (like the website's pasted-message form) rather than with the email library,
    which makes several full copies of every attachment and would exhaust a small server."""
    body = (text or "").replace("\r\n", "\n").strip()
    first_line = next((ln.strip() for ln in body.splitlines() if ln.strip()), "")
    first_line = re.sub(r"\s+", " ", re.sub(r"[^\x20-\x7e]+", " ", first_line)).strip()[:60]
    subject = f"WhatsApp message: {first_line}" if first_line else "WhatsApp message"
    token = secrets.token_hex(6)
    outer, inner = f"----=_etap_mixed_{token}", f"----=_etap_alt_{token}"
    message_id = re.sub(r"[^A-Za-z0-9]", "", message_sid) or str(int(time.time()))

    head = "\r\n".join([
        "MIME-Version: 1.0",
        f"Subject: {subject}",
        f"Message-ID: <whatsapp-{message_id}@etap.local>",
        f'Content-Type: multipart/mixed; boundary="{outer}"',
        "", f"--{outer}",
        f'Content-Type: multipart/alternative; boundary="{inner}"',
        "", f"--{inner}",
        'Content-Type: text/plain; charset="utf-8"',
        "Content-Transfer-Encoding: base64", "", ""]).encode("ascii")
    plain = (body or "(no text, files only)").encode("utf-8")
    middle = "\r\n".join([f"--{inner}", 'Content-Type: text/html; charset="utf-8"',
                          "Content-Transfer-Encoding: base64", "", ""]).encode("ascii")
    parts = [head, *_base64_lines(plain), middle, *_base64_lines(linkify(body).encode("utf-8")),
             f"--{inner}--\r\n".encode("ascii")]
    for name, content_type, data in files:
        kind = (content_type or "").split(";")[0].strip().lower()
        kind = kind if _CONTENT_TYPE.match(kind) else "application/octet-stream"
        safe = _safe_filename(name) or "attachment"
        parts.append("\r\n".join([f"--{outer}", f'Content-Type: {kind}; name="{safe}"',
                                  "Content-Transfer-Encoding: base64",
                                  f'Content-Disposition: attachment; filename="{safe}"', "", ""]).encode("ascii"))
        parts.extend(_base64_lines(data))
    parts.append(f"--{outer}--\r\n".encode("ascii"))
    return b"".join(parts)


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
        lines.append(f"Note: {skipped_files} file(s) could not be checked (over 25 MB, or could not be downloaded).")
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

def _safe_filename(name: Optional[str]) -> str:
    return re.sub(r"[^A-Za-z0-9._ -]", "_", str(name or "")).strip(" .")[:80]


def _check_and_reply(text: str, items: list, fetch_one, send, message_sid: str) -> None:
    """The provider-neutral worker: fetch files, analyse, answer. Never raises.

    items: [(reference, content_type, filename_hint)]; fetch_one(reference) -> bytes or None;
    send(body) delivers one reply to the person who wrote."""
    try:
        from pipeline import SOURCE_FORWARDED, analyze_email_upload
        from workflow_c import finish_analysis

        files: list[tuple[str, str, bytes]] = []
        total, skipped = 0, 0
        for index, (reference, content_type, hint) in enumerate(items[:MAX_FILES], start=1):
            data = fetch_one(reference)
            if data is None or total + len(data) > MAX_TOTAL_BYTES:
                skipped += 1
                continue
            total += len(data)
            extension = mimetypes.guess_extension((content_type or "").split(";")[0].strip()) or ".bin"
            files.append((_safe_filename(hint) or f"whatsapp-file-{index}{extension}", content_type, data))
        skipped += max(0, len(items) - MAX_FILES)

        if not text.strip() and not files:
            send(FAILED_TEXT)
            return
        from heavy_gate import heavy_analysis
        eml = build_eml(text, files, message_sid)
        files.clear()  # the raw files are inside the .eml now; free them before the heavy part
        with heavy_analysis(len(eml)):  # big messages take turns, shared with the website
            report = analyze_email_upload("whatsapp-message.eml", eml, SOURCE_FORWARDED, None,
                                          {"requested": False, "token": None})
            report = finish_analysis(report)
        del eml
        send(reply_text(report, skipped))
    except Exception as exc:
        logger.warning("WhatsApp analysis failed (%s)", type(exc).__name__)
        send(FAILED_TEXT)


def _process(sender: str, text: str, media: list[tuple[str, str]], message_sid: str) -> None:
    """Twilio: files arrive as URLs, and the instant acknowledgement was already sent as TwiML."""
    _check_and_reply(text, [(url, ctype, None) for url, ctype in media], fetch_media,
                     lambda body: send_whatsapp(sender, body), message_sid)


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


# --- Meta WhatsApp Cloud API ------------------------------------------------

UNSUPPORTED_TEXT = ("I can check text, links, images and documents. "
                    "Please send the message as text, or a screenshot or document of it.")
_META_MEDIA_HOSTS = (".fbsbx.com", ".facebook.com", ".fbcdn.net")


def _graph_base() -> str:
    return f"https://graph.facebook.com/{os.getenv('META_GRAPH_VERSION', '').strip() or 'v23.0'}"


def _meta_headers() -> dict:
    return {"Authorization": f"Bearer {os.getenv('META_ACCESS_TOKEN', '')}"}


def send_meta(to: str, body: str) -> bool:
    """Send one WhatsApp text through the Cloud API. Never raises."""
    phone_id = os.getenv("META_PHONE_NUMBER_ID", "").strip()
    if not (phone_id and os.getenv("META_ACCESS_TOKEN")):
        logger.warning("WhatsApp reply not sent: Meta sender is not configured")
        return False
    try:
        response = requests.post(
            f"{_graph_base()}/{phone_id}/messages", headers=_meta_headers(), timeout=15,
            json={"messaging_product": "whatsapp", "to": to, "type": "text",
                  "text": {"body": body[:4000], "preview_url": False}})
        if response.status_code >= 300:
            logger.warning("WhatsApp reply refused (status %s)", response.status_code)
            return False
        return True
    except Exception as exc:
        logger.warning("WhatsApp reply failed (%s)", type(exc).__name__)
        return False


def _allowed_meta_host(url: str) -> bool:
    parsed = urlparse(url)
    host = (parsed.hostname or "").lower()
    return parsed.scheme == "https" and any(host == s[1:] or host.endswith(s) for s in _META_MEDIA_HOSTS)


def fetch_meta_media(media_id: str) -> Optional[bytes]:
    """Two steps, as Meta requires: look the file up by id, then download it. None on any problem."""
    if not re.fullmatch(r"\d{1,30}", str(media_id or "")):
        return None
    try:
        lookup = requests.get(f"{_graph_base()}/{media_id}", headers=_meta_headers(), timeout=15)
        if lookup.status_code >= 300:
            return None
        url = (lookup.json() or {}).get("url", "")
        if not _allowed_meta_host(url):
            return None
        response = requests.get(url, headers=_meta_headers(), timeout=20, stream=True)
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


def _process_meta(sender: str, text: str, items: list, message_id: str) -> None:
    """Meta has no TwiML, so the acknowledgement is an ordinary message sent first."""
    send_meta(sender, ACK_TEXT)
    _check_and_reply(text, items, fetch_meta_media, lambda body: send_meta(sender, body), message_id)


def _meta_messages(payload: dict):
    """Every incoming message in a webhook payload (status updates and other events are skipped)."""
    for entry in payload.get("entry") or []:
        for change in entry.get("changes") or []:
            if change.get("field") != "messages":
                continue
            for message in (change.get("value") or {}).get("messages") or []:
                if isinstance(message, dict):
                    yield message


def _handle_meta_message(message: dict) -> None:
    sender = str(message.get("from") or "")
    message_id = str(message.get("id") or "")
    if not sender or (message_id and not _first_time(message_id)):
        return
    kind = message.get("type")
    text, items = "", []
    if kind == "text":
        text = str((message.get("text") or {}).get("body") or "")
    elif kind in ("image", "document"):
        part = message.get(kind) or {}
        text = str(part.get("caption") or "")
        media_id = str(part.get("id") or "")
        if re.fullmatch(r"\d{1,30}", media_id):
            items.append((media_id, str(part.get("mime_type") or ""), part.get("filename")))
    else:
        _submit(send_meta, sender, UNSUPPORTED_TEXT)
        return
    text = text.strip()
    if not items and (not text or text.lower() in HELP_WORDS):
        _submit(send_meta, sender, HELP_TEXT)
        return
    if not _within_limit(f"meta:{sender}"):
        _submit(send_meta, sender, BUSY_TEXT)
        return
    _submit(_process_meta, sender, text, items, message_id)


@router.get("/meta")
async def meta_verify(request: Request) -> Response:
    """Meta's one-time handshake when the webhook is saved: echo the challenge if the token matches."""
    expected = os.getenv("META_VERIFY_TOKEN", "")
    if not expected:
        raise HTTPException(status_code=503, detail="The WhatsApp bot is not set up on this server.")
    query = request.query_params
    if query.get("hub.mode") == "subscribe" and hmac.compare_digest(query.get("hub.verify_token", ""), expected):
        return Response(content=query.get("hub.challenge", ""), media_type="text/plain")
    raise HTTPException(status_code=403, detail="Verification failed.")


@router.post("/meta")
async def meta_webhook(request: Request) -> dict:
    secret = os.getenv("META_APP_SECRET", "")
    if not secret:
        raise HTTPException(status_code=503, detail="The WhatsApp bot is not set up on this server.")
    raw = await request.body()
    expected = "sha256=" + hmac.new(secret.encode(), raw, hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expected, request.headers.get("x-hub-signature-256", "")):
        raise HTTPException(status_code=403, detail="Invalid signature.")
    try:
        import json
        payload = json.loads(raw)
    except ValueError:
        raise HTTPException(status_code=400, detail="Invalid body.") from None
    for message in _meta_messages(payload if isinstance(payload, dict) else {}):
        _handle_meta_message(message)
    return {"status": "ok"}
