"""
unified_parser.py

THIS is the file everyone else imports from. Nobody outside the parser
module should ever call eml_parser or msg_parser directly — always go
through parse_email() here, so the rest of the codebase doesn't need to
know or care whether the input was .eml or .msg.

Usage:
    from email_parser.unified_parser import parse_email

    result = parse_email("/path/to/uploaded_file")
    print(result.to_dict())   # JSON-serializable dict, ready to hand to the team API layer
"""

import os

from .eml_parser import parse_eml, parse_eml_bytes
from .msg_parser import parse_msg
from .models import ParsedEmail


class UnsupportedFileTypeError(Exception):
    pass


def detect_file_type(file_path: str, raw_bytes: bytes = None) -> str:
    """
    Decide if a file is .eml or .msg with strict content-based magic-byte validation.
    Protects the parser attack surface against deceptive extensions (e.g. EXEs, PDFs, ZIPs renamed to .eml/.msg).
    """
    if raw_bytes is None and os.path.exists(file_path):
        with open(file_path, "rb") as f:
            raw_bytes = f.read(4096)

    header = raw_bytes[:16] if raw_bytes else b""

    # 1. Reject known non-email binary payloads immediately regardless of file extension
    disallowed_signatures = [
        (b"MZ", "Windows Executable/DLL (PE binary)"),
        (b"\x7fELF", "Linux ELF binary"),
        (b"PK\x03\x04", "ZIP / OpenXML archive"),
        (b"%PDF", "PDF Document"),
        (b"\xca\xfe\xba\xbe", "Mach-O / Java Class binary"),
        (b"\xce\xfa\xed\xfe", "Mach-O binary"),
        (b"\xcf\xfa\xed\xfe", "Mach-O 64-bit binary"),
        (b"Rar!\x1a\x07", "RAR archive"),
        (b"7z\xbc\xaf\x27\x1c", "7-Zip archive"),
    ]
    for sig, desc in disallowed_signatures:
        if header.startswith(sig):
            raise UnsupportedFileTypeError(
                f"File content rejected: detected {desc} signature. "
                f"Only valid email artifacts (.eml / .msg) are accepted."
            )

    # 2. Check for Outlook .msg OLE Compound File signature
    OLE_SIGNATURE = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1"
    if header.startswith(OLE_SIGNATURE):
        return "msg"

    # If extension claims .msg but magic bytes do NOT match OLE signature, reject!
    ext = os.path.splitext(file_path)[1].lower()
    if ext == ".msg":
        raise UnsupportedFileTypeError(
            f"File '{file_path}' has .msg extension but is missing required Outlook OLE compound signature."
        )

    # 3. Check for .eml / RFC 822 MIME format (text with standard email header keys)
    if raw_bytes:
        sample_text = ""
        for enc in ("utf-8", "latin-1", "ascii"):
            try:
                sample_text = raw_bytes[:2048].decode(enc)
                break
            except Exception:
                continue

        if sample_text:
            common_headers = (
                "from:", "to:", "subject:", "date:", "received:",
                "message-id:", "mime-version:", "return-path:",
                "content-type:", "delivered-to:", "x-mailer:", "reply-to:"
            )
            lower_sample = sample_text.lower()
            if any(h in lower_sample for h in common_headers) or ext in (".eml", ".rfc822", ".rfc822msg", ".txt"):
                return "eml"

    raise UnsupportedFileTypeError(
        f"Could not verify valid email structure for '{file_path}'. Expected valid .eml (RFC 822) or .msg (Outlook OLE)."
    )


def parse_email(file_path: str) -> ParsedEmail:
    """
    Main entry point. Give it a file path, get back a ParsedEmail object
    with the exact same shape regardless of whether the input was .eml or .msg.
    """
    file_type = detect_file_type(file_path)

    if file_type == "eml":
        return parse_eml(file_path)
    elif file_type == "msg":
        return parse_msg(file_path)
    else:
        raise UnsupportedFileTypeError(f"Unhandled file type: {file_type}")


def parse_email_from_upload(filename: str, raw_bytes: bytes) -> ParsedEmail:
    """
    Use this version when the file comes from a web upload (FastAPI
    UploadFile) rather than sitting on disk — the team API layer will
    likely call this one instead of parse_email().
    """
    file_type = detect_file_type(filename, raw_bytes=raw_bytes)

    if file_type == "eml":
        return parse_eml_bytes(raw_bytes)
    elif file_type == "msg":
        # extract-msg needs a real file path, so write to a temp file first
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".msg", delete=False) as tmp:
            tmp.write(raw_bytes)
            tmp_path = tmp.name
        try:
            return parse_msg(tmp_path)
        finally:
            os.unlink(tmp_path)
    else:
        raise UnsupportedFileTypeError(f"Unhandled file type: {file_type}")


def parse_any(file_path: str, csv_sample: int = None):
    """
    THE universal entry point. Give it ANY supported file — .eml, .rfc822,
    .msg, or .csv (a bulk dataset) — and it figures out what to do.

    Returns:
        - ParsedEmail          if input was a single email (.eml/.rfc822/.msg)
        - List[ParsedEmail]    if input was a .csv bulk dataset

    NOTE: the return type differs (single object vs list) depending on
    input — callers should check which one they got, e.g.:

        result = parse_any(path)
        if isinstance(result, list):
            for email in result:
                handle(email)
        else:
            handle(result)

    This is intentional rather than always-returning-a-list, because a
    single .eml file conceptually IS one email, not a list of one. If this
    ever causes friction for the team API layer, we can add a
    parse_any_as_list() wrapper that always normalizes to a list — flag it
    if that's easier for the API/frontend to consume.
    """
    ext = os.path.splitext(file_path)[1].lower()

    if ext == ".csv":
        from .csv_parser import parse_csv_dataset
        return parse_csv_dataset(file_path, sample=csv_sample)

    # everything else (.eml, .rfc822, .msg, unknown-with-valid-content) goes
    # through the existing single-email path
    return parse_email(file_path)
