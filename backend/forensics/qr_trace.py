"""
B6: QR-code trace.

For every image attachment: which image, what the decoder found, and what the
decoded destination looks like under the same static link checks as any other
link. A QR code is not treated as bad because it is a QR code; invoices and
tickets use them. Only what the destination shows is evidence.

Nothing is fetched: redirects are not followed, so the final destination is
unknown and the trace says so.
"""
from __future__ import annotations

from typing import Any

from privacy import personalised_url
from .link_analysis import analyze_url

# image attachments whose scan did not produce an answer
_NOT_CHECKED = {"decoder_unavailable", "image_unreadable", "scan_failed"}


def build_qr_trace(attachments: list | None) -> dict[str, Any]:
    entries: list[dict[str, Any]] = []
    for att in attachments or []:
        if not isinstance(att, dict) or not att.get("is_image"):
            continue
        status = att.get("qr_status") or "scan_failed"
        entry: dict[str, Any] = {
            "source_attachment": att.get("filename") or "unnamed image",
            "status": status,
            "checked": status not in _NOT_CHECKED,
            "decoded": [],
        }
        for payload in att.get("qr_payloads") or []:
            if payload.get("kind") == "url":
                link = analyze_url(payload["text"])
                link["personalised"] = personalised_url(payload["text"])
                entry["decoded"].append({"kind": "url", "link": link})
            else:
                entry["decoded"].append({"kind": "other", "text": payload.get("text", "")[:200]})
        entries.append(entry)
    return {
        "images_scanned": len(entries),
        "qr_found": sum(1 for e in entries if e["decoded"]),
        "entries": entries,
        "resolution": "not_performed",
    }
