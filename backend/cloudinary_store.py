"""
Cloudinary evidence store (optional).
=====================================
Image attachments (screenshots, QR codes, scanned "invoices") are saved to the
owner's Cloudinary account so the report can show them without keeping image
bytes in MongoDB. Cloudinary also makes the blurred and small preview versions
and, when the add-on is installed, reads the text in the image a second time.

Rules this module keeps:
  * Off unless credentials are set (CLOUDINARY_URL, or CLOUDINARY_CLOUD_NAME +
    CLOUDINARY_API_KEY + CLOUDINARY_API_SECRET). CLOUDINARY_ENABLED=0 turns it off.
  * Never breaks an analysis: every call has a short timeout and swallows errors.
  * Only images are uploaded, at most MAX_IMAGES per email, never other file types.
  * The public id is random, so a link cannot be guessed. Deleting a report
    deletes its images (see delete_assets).
  * The paid-or-quota add-ons (OCR, moderation) are separate switches, off by
    default: CLOUDINARY_OCR=1, CLOUDINARY_MODERATION=1.
"""

from __future__ import annotations

import base64
import hashlib
import logging
import os
import secrets
import time
from concurrent.futures import ThreadPoolExecutor
from urllib.parse import unquote, urlparse

import requests

logger = logging.getLogger(__name__)

MAX_IMAGES = 3
MAX_BYTES = 8 * 1024 * 1024          # the free plan accepts images up to 10 MB
TIMEOUT_S = 8
FOLDER = "etap"
PREVIEW = "c_fill,w_360,h_240,q_auto,f_auto"
BLURRED = PREVIEW + ",e_blur:1500"


def _truthy(name: str, default: str = "0") -> bool:
    return os.getenv(name, default).strip().lower() in {"1", "true", "yes", "on"}


def _credentials() -> tuple[str, str, str] | None:
    url = os.getenv("CLOUDINARY_URL", "").strip()
    if url.startswith("cloudinary://"):
        parsed = urlparse(url)
        if parsed.username and parsed.password and parsed.hostname:
            return parsed.hostname, unquote(parsed.username), unquote(parsed.password)
    cloud = os.getenv("CLOUDINARY_CLOUD_NAME", "").strip()
    key = os.getenv("CLOUDINARY_API_KEY", "").strip()
    secret = os.getenv("CLOUDINARY_API_SECRET", "").strip()
    return (cloud, key, secret) if cloud and key and secret else None


def enabled() -> bool:
    return _credentials() is not None and _truthy("CLOUDINARY_ENABLED", "1")


def _sign(params: dict, secret: str) -> str:
    body = "&".join(f"{k}={v}" for k, v in sorted(params.items()) if v not in (None, ""))
    return hashlib.sha1((body + secret).encode("utf-8")).hexdigest()


def transformed(url: str, transformation: str) -> str:
    """Insert a transformation into a Cloudinary delivery URL."""
    marker = "/image/upload/"
    return url.replace(marker, f"{marker}{transformation}/", 1) if marker in url else url


def upload_image(raw: bytes, filename: str) -> dict | None:
    """Upload one image. Returns a small summary, or None when it could not be saved."""
    creds = _credentials()
    if not creds or not raw or len(raw) > MAX_BYTES:
        return None
    cloud, key, secret = creds
    use_ocr, use_moderation = _truthy("CLOUDINARY_OCR"), _truthy("CLOUDINARY_MODERATION")
    base = {"public_id": f"{FOLDER}/{secrets.token_hex(10)}", "tags": "etap,evidence"}

    def attempt(with_addons: bool):
        params = dict(base, timestamp=int(time.time()))
        if with_addons and use_ocr:
            params["ocr"] = "adv_ocr"
        if with_addons and use_moderation:
            params["moderation"] = "aws_rek"
        data = dict(params, api_key=key, signature=_sign(params, secret))
        return requests.post(f"https://api.cloudinary.com/v1_1/{cloud}/image/upload",
                             data=data, files={"file": (filename or "image", raw)}, timeout=TIMEOUT_S)

    try:
        response = attempt(True)
        if response.status_code >= 400 and (use_ocr or use_moderation):
            # An add-on that is not installed or out of quota must not lose the upload itself.
            logger.info("Cloudinary add-on upload failed (%s); retrying without add-ons", response.status_code)
            response = attempt(False)
        if response.status_code >= 400:
            logger.warning("Cloudinary upload failed: %s", response.text[:200])
            return None
        body = response.json()
    except (requests.RequestException, ValueError) as exc:
        logger.warning("Cloudinary upload error: %s", exc)
        return None

    url = body.get("secure_url") or ""
    if not url:
        return None
    summary = {
        "public_id": body.get("public_id"),
        "url": url,
        "preview_url": transformed(url, PREVIEW),
        "blurred_url": transformed(url, BLURRED),
        "width": body.get("width"),
        "height": body.get("height"),
        "bytes": body.get("bytes"),
        "format": body.get("format"),
    }
    ocr = ((body.get("info") or {}).get("ocr") or {}).get("adv_ocr") or {}
    texts = [d.get("description", "") for d in (ocr.get("data") or []) if isinstance(d, dict)]
    if any(texts):
        summary["ocr_text"] = "\n".join(t.strip() for t in texts if t.strip())
    moderation = [m for m in (body.get("moderation") or []) if isinstance(m, dict)]
    if moderation:
        first = moderation[0]
        labels = [l.get("name") for l in ((first.get("response") or {}).get("moderation_labels") or []) if l.get("name")]
        summary["moderation"] = {"status": first.get("status"), "labels": labels}
    return summary


def cloud_name() -> str | None:
    creds = _credentials()
    return creds[0] if creds else None


def upload_shared_png(public_id: str, png: bytes, tags: str = "etap") -> bool:
    """
    Save one fixed, non-private image (a share-card template) under a known id.
    overwrite=false makes this a cheap no-op when the image is already there.
    """
    creds = _credentials()
    if not creds or not png:
        return False
    cloud, key, secret = creds
    params = {"public_id": public_id, "overwrite": "false", "tags": tags, "timestamp": int(time.time())}
    data = dict(params, api_key=key, signature=_sign(params, secret))
    try:
        response = requests.post(f"https://api.cloudinary.com/v1_1/{cloud}/image/upload",
                                 data=data, files={"file": (public_id.rsplit("/", 1)[-1] + ".png", png)}, timeout=TIMEOUT_S)
    except requests.RequestException as exc:
        logger.warning("Cloudinary template upload error: %s", exc)
        return False
    if response.status_code >= 400:
        logger.warning("Cloudinary template upload failed: %s", response.text[:200])
        return False
    return True


def upload_attachment_images(raw_attachments: list, results: list) -> dict:
    """
    Save the image attachments and add a `cloudinary` entry to their result dicts
    (results are in the same order as raw_attachments). Returns counts for the
    progress line and the privacy report.
    """
    summary = {"enabled": enabled(), "attempted": 0, "uploaded": 0, "failed": 0}
    if not summary["enabled"]:
        return summary

    jobs = []
    for raw, res in zip(raw_attachments or [], results or []):
        if not res.get("is_image") or not str(res.get("actual_type") or "").startswith("image/"):
            continue
        b64 = raw.get("content_bytes_b64") or raw.get("bytes_b64") or ""
        try:
            data = base64.b64decode(b64, validate=False) if b64 else b""
        except Exception:
            continue
        if data and len(jobs) < MAX_IMAGES:
            jobs.append((res, data))

    summary["attempted"] = len(jobs)
    if not jobs:
        return summary

    with ThreadPoolExecutor(max_workers=len(jobs)) as pool:
        stored = list(pool.map(lambda job: upload_image(job[1], job[0].get("filename") or "image"), jobs))

    for (res, _), info in zip(jobs, stored):
        if not info:
            summary["failed"] += 1
            continue
        summary["uploaded"] += 1
        res["cloudinary"] = info
        if info.get("ocr_text") and not res.get("ocr_text"):
            res["ocr_text"] = info["ocr_text"]
            res["flags"].append(f"text extracted from image by Cloudinary OCR ({len(info['ocr_text'])} chars)")
        mod = info.get("moderation") or {}
        if mod.get("status") == "rejected":
            res["flags"].append("Cloudinary moderation rejected this image: " + (", ".join(mod.get("labels") or []) or "unsafe content"))
    return summary


def delete_assets(public_ids: list[str]) -> int:
    """Delete saved images (best effort). Returns how many were removed."""
    creds = _credentials()
    ids = [p for p in public_ids if p]
    if not creds or not ids:
        return 0
    cloud, key, secret = creds

    def destroy(public_id: str) -> bool:
        params = {"public_id": public_id, "timestamp": int(time.time())}
        data = dict(params, api_key=key, signature=_sign(params, secret))
        try:
            response = requests.post(f"https://api.cloudinary.com/v1_1/{cloud}/image/destroy", data=data, timeout=TIMEOUT_S)
            return response.status_code < 400 and response.json().get("result") == "ok"
        except (requests.RequestException, ValueError):
            return False

    with ThreadPoolExecutor(max_workers=min(len(ids), 4)) as pool:
        return sum(pool.map(destroy, ids))


def public_ids_of(analysis_doc: dict) -> list[str]:
    """The Cloudinary ids saved for one stored analysis."""
    attachments = ((analysis_doc or {}).get("attachment_analysis") or {}).get("attachments") or []
    return [a["cloudinary"]["public_id"] for a in attachments
            if isinstance(a, dict) and isinstance(a.get("cloudinary"), dict) and a["cloudinary"].get("public_id")]
