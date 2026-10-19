"""
eml_parser.py

Parses .eml files (raw RFC 822 / MIME format — this is what Gmail, Outlook web,
and most mail clients export to). Uses Python's built-in `email` library, so
no extra install needed for this part.

Usage:
    from email_parser.eml_parser import parse_eml
    result = parse_eml("/path/to/sample.eml")
"""

import base64
from email import message_from_bytes, policy
from email.utils import parseaddr

from .models import ParsedEmail, Attachment
from .pii_masker import redact_sensitive_data


def _get_text_content(part, warnings: list, description: str) -> str | None:
    """Decode a MIME text part even when its declared charset is invalid.

    Email datasets and malformed phish samples sometimes declare a bogus
    charset such as ``DEFAULT``. The email package's get_content() correctly
    refuses an unknown codec; for analysis we fall back to UTF-8 with
    replacement characters and record a warning instead of silently losing
    the message body (or treating an empty body as clean).
    """
    try:
        content = part.get_content()
        if isinstance(content, str):
            return content
    except (LookupError, UnicodeError, ValueError):
        pass
    except Exception:
        # Malformed MIME bodies are handled with a bounded raw-payload fallback.
        pass

    payload = part.get_payload(decode=True)
    if payload is None:
        raw_payload = part.get_payload()
        if isinstance(raw_payload, str):
            warnings.append(f"{description} used raw text fallback because its declared encoding could not be decoded.")
            return raw_payload
        warnings.append(f"{description} could not be decoded; no text payload was available.")
        return None

    charset = part.get_content_charset() or "utf-8"
    try:
        decoded = payload.decode(charset, errors="replace")
    except (LookupError, UnicodeError, ValueError):
        decoded = payload.decode("utf-8", errors="replace")
        warnings.append(f"{description} declared an unsupported charset; UTF-8 replacement decoding was used.")
    else:
        warnings.append(f"{description} required a raw-payload decoding fallback.")
    return decoded


def parse_eml(file_path: str) -> ParsedEmail:
    with open(file_path, "rb") as f:
        raw_bytes = f.read()
    return parse_eml_bytes(raw_bytes)


def parse_eml_bytes(raw_bytes: bytes) -> ParsedEmail:
    """Same as parse_eml but takes raw bytes directly — useful when the file
    comes from an HTTP upload rather than disk."""

    warnings = []

    # policy.default gives us a much more modern, easier-to-use API
    # than the legacy email.message.Message
    msg = message_from_bytes(raw_bytes, policy=policy.default)

    result = ParsedEmail(source_format="eml")

    # ---- core headers ----
    result.subject = msg.get("Subject")
    result.from_raw = msg.get("From")
    result.to = msg.get("To")
    result.reply_to = msg.get("Reply-To")
    result.date = msg.get("Date")
    result.message_id = msg.get("Message-ID")

    # split "Bank Support <fake@evil.com>" into name + email separately
    display_name, email_addr = parseaddr(result.from_raw or "")
    result.from_display_name = display_name or None
    result.from_email = email_addr or None

    # ---- capture ALL headers, including repeated ones like "Received" ----
    all_headers = {}
    for key in msg.keys():
        values = msg.get_all(key, [])
        all_headers[key] = [str(v) for v in values]
    result.all_headers = all_headers

    # ---- body: walk the MIME tree for text/plain and text/html parts ----
    body_text_parts = []
    body_html_parts = []
    attachments = []

    if msg.is_multipart():
        for part in msg.walk():
            content_disposition = part.get_content_disposition()  # "attachment", "inline", or None
            content_type = part.get_content_type()

            # skip container parts (multipart/*), we only want leaf parts
            if part.is_multipart():
                continue

            if content_disposition == "attachment" or (
                content_disposition == "inline" and part.get_filename()
            ) or (
                content_disposition is None and part.get_filename()
            ):
                # this is a file attachment
                try:
                    payload = part.get_payload(decode=True)  # returns raw bytes, already decoded from base64/etc
                    if payload is None:
                        warnings.append(f"Attachment '{part.get_filename()}' had no payload")
                        continue
                    attachments.append(Attachment(
                        filename=part.get_filename() or "unknown_filename",
                        content_type=content_type,
                        size_bytes=len(payload),
                        content_bytes_b64=base64.b64encode(payload).decode("ascii"),
                    ))
                except Exception as e:
                    warnings.append(f"Failed to decode attachment: {e}")

            elif content_type == "text/plain":
                content = _get_text_content(part, warnings, "text/plain part")
                if content is not None:
                    body_text_parts.append(content)

            elif content_type == "text/html":
                content = _get_text_content(part, warnings, "text/html part")
                if content is not None:
                    body_html_parts.append(content)

    else:
        # not multipart — the whole message body IS the content, no attachments
        content_type = msg.get_content_type()
        content = _get_text_content(msg, warnings, "single-part body")
        if content is not None:
            if content_type == "text/html":
                body_html_parts.append(content)
            else:
                body_text_parts.append(content)

    # ---- Apply PII Masking before returning ----
    result.subject = redact_sensitive_data(result.subject)
    result.body_text = redact_sensitive_data("\n".join(body_text_parts)) if body_text_parts else None
    result.body_html = redact_sensitive_data("\n".join(body_html_parts)) if body_html_parts else None
    result.attachments = attachments
    result.parse_warnings = warnings

    return result
