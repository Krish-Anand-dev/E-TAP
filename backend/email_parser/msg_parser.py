"""
msg_parser.py

Parses .msg files (Outlook's proprietary binary format — different from .eml,
needs a dedicated library since it's not MIME/text based, it's an OLE
compound binary file).

Requires: pip install extract-msg

Usage:
    from email_parser.msg_parser import parse_msg
    result = parse_msg("/path/to/sample.msg")
"""

import base64

import extract_msg

from .models import ParsedEmail, Attachment
from .pii_masker import redact_sensitive_data


def parse_msg(file_path: str) -> ParsedEmail:
    warnings = []
    result = ParsedEmail(source_format="msg")

    try:
        msg = extract_msg.Message(file_path)
    except Exception as e:
        # extract_msg eagerly loads attachments INSIDE its own constructor
        # (see msg.py's `self.attachments` access during __init__). A
        # single malformed/non-standard attachment stream (some .msg files
        # not produced by real Outlook don't perfectly follow the OLE
        # compound-file spec extract_msg expects) can therefore fail the
        # ENTIRE Message() construction before we ever reach our own
        # per-attachment error handling below. Without this, one bad .msg
        # file crashes the whole pipeline run instead of just failing to
        # parse that one email -- so we catch it here and return a mostly-
        # empty ParsedEmail with a clear warning, same "degrade, don't
        # crash" contract every other Stage A failure mode follows.
        warnings.append(f"Failed to open .msg file: {e}")
        result.parse_warnings = warnings
        return result

    try:
        # ---- core headers ----
        result.subject = redact_sensitive_data(msg.subject)
        result.from_raw = msg.sender
        result.to = msg.to
        result.date = str(msg.date) if msg.date else None
        result.message_id = msg.messageId

        # extract-msg exposes sender as "Name <email>" sometimes, sometimes just email
        # so we do a light parse similar to eml_parser
        from email.utils import parseaddr
        display_name, email_addr = parseaddr(result.from_raw or "")
        result.from_display_name = display_name or (msg.sender if msg.sender and "@" not in msg.sender else None)
        result.from_email = email_addr or (msg.sender if msg.sender and "@" in (msg.sender or "") else None)

        # reply-to isn't always exposed directly by extract-msg; check header dict if available
        try:
            header_dict = dict(msg.header.items()) if msg.header else {}
        except Exception:
            header_dict = {}
        result.reply_to = header_dict.get("Reply-To")

        # ---- capture all raw headers if available ----
        all_headers = {}
        if header_dict:
            for k, v in header_dict.items():
                all_headers.setdefault(k, []).append(str(v))
        else:
            warnings.append("Raw header block not available from .msg file")
        result.all_headers = all_headers

        # ---- body ----
        result.body_text = redact_sensitive_data(msg.body)
        raw_html = msg.htmlBody.decode("utf-8", errors="ignore") if isinstance(msg.htmlBody, bytes) else msg.htmlBody
        result.body_html = redact_sensitive_data(raw_html) if raw_html else None

        # ---- attachments ----
        attachments = []
        for att in msg.attachments:
            try:
                data = att.data  # raw bytes
                if data is None:
                    warnings.append(f"Attachment '{att.longFilename or att.shortFilename}' had no data")
                    continue
                attachments.append(Attachment(
                    filename=att.longFilename or att.shortFilename or "unknown_filename",
                    content_type=getattr(att, "mimetype", None) or "application/octet-stream",
                    size_bytes=len(data),
                    content_bytes_b64=base64.b64encode(data).decode("ascii"),
                ))
            except Exception as e:
                warnings.append(f"Failed to extract attachment: {e}")

        result.attachments = attachments
        result.parse_warnings = warnings

    finally:
        msg.close()

    return result
