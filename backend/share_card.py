"""
Shareable result card (optional, needs Cloudinary).
===================================================
A small picture of the verdict that a person can send to someone who asked
"is this real?". Cloudinary draws it: we keep one plain coloured base image per
result colour (etap/templates/card_<key>), and each card is a delivery URL that
writes the verdict, score, reasons and date onto that base image.

Rules this module keeps:
  * The card holds no message content: no subject, sender, links, file names or
    quoted text. The reasons are fixed sentences chosen by evidence type.
  * Nothing is stored per email. A card is only a URL, so there is nothing extra
    to delete when a report is deleted.
  * "No problems found" is never "safe", and it turns into a grey "Limited
    check" card whenever a check could not run.
  * Off (None) unless Cloudinary is configured. Never raises.
"""

from __future__ import annotations

import io
import logging
import re
import struct
import zlib
from datetime import datetime, timezone
from urllib.parse import quote

import cloudinary_store

logger = logging.getLogger(__name__)

WIDTH, HEIGHT = 1200, 630
TEMPLATE_FOLDER = f"{cloudinary_store.FOLDER}/templates"

# result colour -> (background, darker footer strip)
COLOURS = {
    "danger": ((180, 35, 24), (122, 22, 15)),
    "caution": ((180, 83, 9), (124, 55, 6)),
    "safe": ((15, 118, 110), (10, 80, 75)),
    "limited": ((71, 85, 105), (45, 55, 72)),
}

HEADLINES = {"safe": "NO PROBLEMS FOUND", "limited": "LIMITED CHECK"}

NEXT_STEP = {
    "danger": "Do not click, open or reply. Report it, then delete it.",
    "caution": "Do not act yet. Confirm using a number you already have.",
    "safe": "Still be careful with unexpected requests for money or codes.",
    "limited": "This was a partial check. Confirm before you act on it.",
}

# Fixed, privacy-safe sentences, picked by the kind of evidence (most specific prefix first).
REASONS = (
    ("hdr.flag.reply_to_domain_mismatch", "Replies would go to a different domain"),
    ("hdr.", "The sender could not be trusted"),
    ("att.", "An attachment looks dangerous"),
    ("qr.", "A QR code leads to a risky page"),
    ("link.", "A link in the message looks risky"),
    ("rep.", "Trusted sources have flagged it"),
    ("corr.", "It matches earlier suspicious emails"),
    ("ai.", "The wording looks like a scam"),
)

_ensured: set[str] = set()


def _clean(text: str) -> str:
    """Keep only characters that are safe inside a Cloudinary text layer."""
    return re.sub(r"\s+", " ", re.sub(r"[^A-Za-z0-9 .\-]", " ", str(text or ""))).strip()


def card_key(band: str, limitations: list | None) -> str:
    """Which base image: a good result with missing checks becomes the grey 'limited' card."""
    if band == "safe" and limitations:
        return "limited"
    return band if band in COLOURS else "caution"


def reasons_for(key: str, top_reason_ids: list | None) -> list[str]:
    if key == "safe":
        return ["No high-risk signs in the checks that ran"]
    if key == "limited":
        return ["Some checks could not run", "No high-risk signs in the ones that did"]
    out: list[str] = []
    for item_id in top_reason_ids or []:
        for prefix, sentence in REASONS:
            if str(item_id).startswith(prefix):
                if sentence not in out:
                    out.append(sentence)
                break
    return out[:3] or ["The overall risk score is high" if key == "danger" else "The overall risk score is raised"]


def template_png(key: str) -> bytes:
    """A plain 1200x630 PNG: coloured background with a darker footer strip."""
    background, strip = COLOURS[key]
    try:
        from PIL import Image, ImageDraw
        image = Image.new("RGB", (WIDTH, HEIGHT), background)
        ImageDraw.Draw(image).rectangle([0, 510, WIDTH, HEIGHT], fill=strip)
        buffer = io.BytesIO()
        image.save(buffer, "PNG", optimize=True)
        return buffer.getvalue()
    except Exception:  # Pillow missing: a solid colour still works
        row = b"\x00" + bytes(background) * WIDTH

        def chunk(tag: bytes, data: bytes) -> bytes:
            return struct.pack(">I", len(data)) + tag + data + struct.pack(">I", zlib.crc32(tag + data) & 0xFFFFFFFF)

        return (b"\x89PNG\r\n\x1a\n"
                + chunk(b"IHDR", struct.pack(">IIBBBBB", WIDTH, HEIGHT, 8, 2, 0, 0, 0))
                + chunk(b"IDAT", zlib.compress(row * HEIGHT, 9)) + chunk(b"IEND", b""))


def ensure_template(key: str) -> bool:
    """Make sure the base image exists in Cloudinary (once per process and colour)."""
    if key in _ensured:
        return True
    if cloudinary_store.upload_shared_png(f"{TEMPLATE_FOLDER}/card_{key}", template_png(key), "etap,template"):
        _ensured.add(key)
        return True
    return False


def _layer(text: str, size: int, x: int, y: int, bold: bool = False) -> str:
    font = f"Arial_{size}" + ("_bold" if bold else "")
    return f"l_text:{font}:{quote(_clean(text), safe='')},co_white/fl_layer_apply,g_north_west,x_{x},y_{y}"


def build_url(key: str, *, headline: str, score: int, reasons: list[str], next_step: str,
              date_text: str, download: bool = False) -> str | None:
    cloud = cloudinary_store.cloud_name()
    if not cloud:
        return None
    layers = [
        _layer("E-TAP CHECK", 30, 80, 60, bold=True),
        _layer(headline, 76 if len(headline) <= 20 else 64, 80, 120, bold=True),
        _layer(f"Risk score {score} of 100", 44, 80, 235),
    ]
    for i, reason in enumerate(reasons):
        layers.append(_layer(f"- {reason}", 36, 80, 320 + i * 62))
    layers.append(_layer(next_step, 32, 80, 530))
    layers.append(_layer(f"Checked with E-TAP on {date_text}", 26, 80, 580))
    transform = "/".join(layers)
    if download:
        transform = "fl_attachment:etap-result/" + transform
    return (f"https://res.cloudinary.com/{cloud}/image/upload/{transform}/"
            f"{TEMPLATE_FOLDER}/card_{key}.png")


def for_report(*, label: str | None, band: str | None, score, evidence_report: dict | None,
               analyzed_at: datetime | None = None, ensure: bool = False) -> dict | None:
    """The card for one report, or None when Cloudinary is off or the card cannot be made."""
    if not cloudinary_store.enabled():
        return None
    try:
        report = evidence_report or {}
        conclusion = report.get("conclusion") or {}
        key = card_key(band or conclusion.get("band") or "caution", conclusion.get("limitations"))
        if ensure and not ensure_template(key):
            return None
        try:
            points = max(0, min(100, int(round(float(score)))))
        except (TypeError, ValueError):
            points = 0
        headline = HEADLINES.get(key) or _clean(label or "SUSPICIOUS").upper() or "SUSPICIOUS"
        reasons = reasons_for(key, report.get("top_reasons"))
        when = analyzed_at if isinstance(analyzed_at, datetime) else datetime.now(timezone.utc)
        args = dict(headline=headline, score=points, reasons=reasons, next_step=NEXT_STEP[key],
                    date_text=when.strftime("%d %b %Y"))
        url = build_url(key, **args)
        if not url:
            return None
        return {
            "url": url,
            "download_url": build_url(key, download=True, **args),
            "key": key,
            "headline": headline,
            "score": points,
            "reasons": reasons,
            "next_step": NEXT_STEP[key],
            "alt": f"E-TAP result card: {headline.lower()}, risk score {points} of 100",
        }
    except Exception as exc:  # a card must never break a report
        logger.warning("Share card failed (%s)", type(exc).__name__)
        return None
