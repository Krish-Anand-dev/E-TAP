"""
File type detection via magic bytes.

Tries python-magic (libmagic) first since it's the most accurate/broad.
Falls back to a small hand-rolled signature table if libmagic isn't
installed on the machine (common on Windows without extra setup) — this
guarantees Stage B2 still runs and flags mismatches even without libmagic.
"""

from __future__ import annotations

try:
    import magic  # python-magic — needs libmagic installed on the system
    _HAS_LIBMAGIC = True
except Exception:
    _HAS_LIBMAGIC = False


# (offset, magic_bytes, mime_type) — checked in order, first match wins.
# Covers the file types most relevant to phishing attachments.
_SIGNATURES: list[tuple[int, bytes, str]] = [
    (0, b"%PDF-", "application/pdf"),
    (0, b"MZ", "application/x-msdownload"),  # Windows EXE/DLL
    (0, b"\x50\x4b\x03\x04", "application/zip"),  # zip-based: docx/xlsx/pptx/jar/apk all start this way
    (0, b"\x50\x4b\x05\x06", "application/zip"),  # empty zip
    (0, b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1", "application/x-ole-storage"),  # old-format .doc/.xls/.ppt, .msg
    (0, b"\xff\xd8\xff", "image/jpeg"),
    (0, b"\x89PNG\r\n\x1a\n", "image/png"),
    (0, b"GIF87a", "image/gif"),
    (0, b"GIF89a", "image/gif"),
    (0, b"\x25\x21", "application/postscript"),
    (0, b"\x7fELF", "application/x-elf"),  # Linux executable
    (0, b"\x1f\x8b", "application/gzip"),
    (0, b"Rar!\x1a\x07", "application/x-rar-compressed"),
    (0, b"7z\xbc\xaf\x27\x1c", "application/x-7z-compressed"),
    (0, b"{\\rtf", "application/rtf"),
]

# Office Open XML (docx/xlsx/pptx) are all zip containers — we can tell
# them apart by peeking at internal file names without a full unzip.
_OOXML_MARKERS = {
    b"word/": "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    b"xl/": "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    b"ppt/": "application/vnd.openxmlformats-officedocument.presentationml.presentation",
}


def detect_actual_type(data: bytes) -> str:
    """Return a best-guess MIME type for raw file bytes based on content, not filename."""
    if not data:
        return "application/x-empty"

    # MZ header is checked first and treated as authoritative regardless of
    # libmagic's answer: libmagic can report a bare/truncated MZ header as
    # generic application/octet-stream if it doesn't see a full PE structure,
    # but for phishing-attachment purposes "starts with MZ" is itself the
    # signal worth flagging -- don't let a soft libmagic miss suppress it.
    if data[:2] == b"MZ":
        return "application/x-msdownload"

    if _HAS_LIBMAGIC:
        try:
            libmagic_result = magic.from_buffer(data, mime=True)
            if libmagic_result != "application/octet-stream":
                return libmagic_result
            # fall through to manual signatures for a more specific guess
        except Exception:
            pass  # fall through to manual signatures

    for offset, sig, mime in _SIGNATURES:
        if data[offset:offset + len(sig)] == sig:
            if mime == "application/zip":
                # Refine zip-based Office formats by peeking at the first ~4KB
                # for characteristic internal folder names.
                head = data[:4096]
                for marker, refined_mime in _OOXML_MARKERS.items():
                    if marker in head:
                        return refined_mime
            return mime

    return "application/octet-stream"


def types_conflict(declared_type: str, actual_type: str) -> bool:
    """
    Decide whether declared vs actual type counts as a real mismatch.
    Deliberately lenient about generic/near-equivalent types to avoid
    flagging every benign email as suspicious.
    """
    if not declared_type:
        return False

    declared = declared_type.lower().strip()
    actual = actual_type.lower().strip()

    if declared == actual:
        return False

    # application/octet-stream is a generic "unknown" declared type — don't
    # flag it as a mismatch on its own.
    if declared == "application/octet-stream":
        return False

    # Some mail clients declare legacy Office types even for OOXML files —
    # treat the whole office family as equivalent to reduce false positives.
    office_family = {
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
        "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
        "application/vnd.openxmlformats-officedocument.presentationml.presentation",
        "application/x-ole-storage",
        "application/zip",
    }
    if declared in office_family and actual in office_family:
        return False

    return True
