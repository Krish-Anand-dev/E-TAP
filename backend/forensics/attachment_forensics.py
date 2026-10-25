"""
Stage B2 -- Attachment Forensics
Owner: the team

Input:  Stage A's EmailObject["attachments"] list.
Output: {"attachments": [ {...per-file forensic result...}, ... ]}

Per Krish's finalized Stage A doc, each attachment entry coming in is
expected to look roughly like:
    {
        "filename": "invoice.pdf",
        "content_type": "application/pdf",   # declared type from the email itself
        "bytes_b64": "..."                    # base64-encoded raw file bytes
    }

Exact key names can vary slightly by parser version (e.g. "content_type"
vs "declared_type", "bytes_b64" vs "data_b64") -- get_* helpers below check
a few common aliases so this module doesn't break on a minor naming
mismatch upstream. If Stage A's real output uses different keys entirely,
update the alias lists in _get_filename/_get_declared_type/_get_b64_bytes.
"""

from __future__ import annotations
import base64
import hashlib
from typing import Any

from .file_signatures import detect_actual_type, types_conflict
from .macro_scan import analyze_macro_behavior, is_office_document


def _get(attachment: dict, *keys: str, default: Any = None) -> Any:
    for k in keys:
        if k in attachment and attachment[k] is not None:
            return attachment[k]
    return default


def _get_filename(a: dict) -> str:
    return _get(a, "filename", "name", "file_name", default="unknown")


def _get_declared_type(a: dict) -> str:
    return _get(a, "content_type", "declared_type", "mime_type", default="")


def _get_b64_bytes(a: dict) -> str:
    # "content_bytes_b64" is Stage A's actual key (confirmed against
    # docs/parser_fixtures/double_extension_attachment.json and against a
    # real .eml with a real attachment). Older aliases kept as fallback only.
    return _get(a, "content_bytes_b64", "bytes_b64", "data_b64", "content_b64", "base64_data", default="")


def analyze_attachment(raw_attachment: dict) -> dict:
    """Run full forensic analysis on a single attachment entry."""
    filename = _get_filename(raw_attachment)
    declared_type = _get_declared_type(raw_attachment)
    b64_data = _get_b64_bytes(raw_attachment)

    result = {
        "filename": filename,
        "declared_type": declared_type,
        "sha256": None,
        "size_bytes": 0,
        "actual_type": "application/x-empty",
        "type_mismatch": False,
        "has_macro": False,
        "macro_behavior": None,  # populated only for Office docs with a macro -- see analyze_macro_behavior()
        "suspicious": False,
        "flags": [],
        "ocr_text": "",
        "qr_urls": [],
        "qr_payloads": [],
        "qr_status": None,   # only set for images: decoded / no_qr_found / decoder_unavailable / image_unreadable
        "is_image": False,
    }

    if not b64_data:
        result["flags"].append("no attachment data present -- could not analyze")
        return result

    try:
        raw_bytes = base64.b64decode(b64_data, validate=False)
    except Exception:
        result["flags"].append("base64 decode failed -- malformed attachment data")
        result["suspicious"] = True
        return result

    result["size_bytes"] = len(raw_bytes)
    result["sha256"] = hashlib.sha256(raw_bytes).hexdigest()

    actual_type = detect_actual_type(raw_bytes)
    result["actual_type"] = actual_type

    mismatch = types_conflict(declared_type, actual_type)
    result["type_mismatch"] = mismatch
    if mismatch:
        result["flags"].append(
            "declared type '%s' does not match actual content ('%s')" % (declared_type, actual_type)
        )

    lowered_name = filename.lower()
    suspicious_double_ext = any(
        lowered_name.endswith(ext) and lowered_name.count(".") >= 2
        and any(mid in lowered_name for mid in (".pdf.", ".doc.", ".jpg.", ".png.", ".txt."))
        for ext in (".exe", ".scr", ".bat", ".cmd", ".js", ".vbs", ".msi", ".ps1")
    )
    if suspicious_double_ext:
        result["flags"].append("filename has a suspicious double extension")

    if is_office_document(filename, actual_type):
        macro_result = analyze_macro_behavior(raw_bytes, filename)
        result["has_macro"] = macro_result["has_macro"]
        if macro_result["has_macro"]:
            result["macro_behavior"] = macro_result
            # Preserve prior sensitivity: presence of a macro at all is still
            # flagged (macros are rare and inherently notable in received
            # attachments) -- the behavioral detail is added evidence on top,
            # not a narrowing of what counts as suspicious.
            result["flags"].append("Office document contains a macro")
            result["flags"].extend(macro_result["flags"])
        elif macro_result.get("parse_failed"):
            # Password-protected or corrupt Office doc -- cannot inspect
            # macros, which is itself suspicious. Treat as a red flag.
            result["suspicious"] = True
            result["flags"].append(
                "Office document could not be parsed (possibly password-protected or corrupt) -- macro inspection failed"
            )

    # Image attachment decomposition (QR Code URLs + OCR text)
    is_image = (
        actual_type.startswith("image/")
        or declared_type.startswith("image/")
        or any(lowered_name.endswith(ext) for ext in (".png", ".jpg", ".jpeg", ".gif", ".bmp", ".webp", ".tiff"))
    )
    result["is_image"] = bool(is_image)
    if is_image:
        try:
            from .image_forensics import scan_image_attachment
            scan_res = scan_image_attachment(raw_bytes, filename)
            result["ocr_text"] = scan_res.get("ocr_text", "")
            result["qr_urls"] = scan_res.get("qr_urls", [])
            result["qr_payloads"] = scan_res.get("qr_payloads", [])
            result["qr_status"] = scan_res.get("qr_status")
            if result["qr_urls"]:
                result["flags"].append(f"hidden QR code containing {len(result['qr_urls'])} URL(s) detected")
            if result["ocr_text"]:
                result["flags"].append(f"text extracted from image via OCR ({len(result['ocr_text'])} chars)")
        except Exception as img_exc:
            # Must never crash attachment forensics
            result["qr_status"] = "scan_failed"

    executable_types = {"application/x-msdownload", "application/x-elf"}
    disguised_executable = (
        actual_type in executable_types
        and not lowered_name.endswith((".exe", ".dll", ".scr", ".msi"))
    )

    result["suspicious"] = bool(
        mismatch
        or result["has_macro"]
        or suspicious_double_ext
        or disguised_executable
        or bool(result["qr_urls"])
    )
    if disguised_executable:
        result["flags"].append("executable content disguised with a non-executable filename")

    return result


def analyze_attachments(attachments: list[dict]) -> dict:
    """Stage B2 entry point. Call this with EmailObject['attachments']."""
    if not attachments:
        return {"attachments": []}

    return {"attachments": [analyze_attachment(a) for a in attachments]}
