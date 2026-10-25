"""Read bounded ZIP members as data; execution only happens in the guest VM."""
from __future__ import annotations

import base64
import hashlib
from io import BytesIO
from pathlib import PurePosixPath
from zipfile import ZipFile, BadZipFile

from .policy import MAX_DETONATION_SIZE, MAX_PER_EMAIL, should_detonate

MAX_ARCHIVE_ENTRIES = 100
MAX_EXPANDED_BYTES = 50 * 1024 * 1024
ARCHIVE_EXTENSIONS = {".zip", ".rar", ".7z", ".iso", ".img"}


def expand_candidate(candidate: dict) -> list[dict]:
    """Turn ZIP children into independent samples with archive provenance.

    No archive paths are written to the host filesystem. Unsupported/encrypted
    content and skipped children remain visible as incomplete inspections.
    """
    filename = candidate["filename"]
    extension = PurePosixPath(filename.replace("\\", "/")).suffix.lower()
    if extension not in ARCHIVE_EXTENSIONS and candidate.get("actual_type") != "application/zip":
        return [candidate]

    def incomplete(reason, member=None):
        return {**candidate, "filename": f"{filename} / {member}" if member else filename,
                "content_b64": "", "inspection_error": reason, "archive": filename}

    if extension != ".zip" and candidate.get("actual_type") != "application/zip":
        return [incomplete(f"Extraction is not configured for {extension} archives")]

    output = []
    launched = 0
    try:
        data = base64.b64decode(candidate.get("content_b64", ""), validate=True)
        if len(data) > MAX_DETONATION_SIZE:
            return [incomplete("Archive exceeds sandbox size limit")]
        with ZipFile(BytesIO(data)) as archive:
            entries = archive.infolist()
            if len(entries) > MAX_ARCHIVE_ENTRIES or sum(e.file_size for e in entries) > MAX_EXPANDED_BYTES:
                return [incomplete("Archive exceeds entry count or expanded size limit")]
            for entry in entries:
                if entry.is_dir():
                    continue
                path = PurePosixPath(entry.filename.replace("\\", "/"))
                if path.is_absolute() or ".." in path.parts or ":" in str(path):
                    output.append(incomplete("Unsafe archive member path", entry.filename))
                    continue
                child = {"filename": entry.filename, "size_bytes": entry.file_size}
                if entry.flag_bits & 1:
                    output.append(incomplete("Encrypted archive member cannot be inspected", entry.filename))
                    continue
                if entry.file_size > MAX_DETONATION_SIZE:
                    output.append(incomplete("Archive member exceeds sample size limit", entry.filename))
                    continue
                if not should_detonate(child):
                    continue
                if launched >= MAX_PER_EMAIL:
                    output.append(incomplete("Archive sample limit reached", entry.filename))
                    continue
                if path.suffix.lower() in ARCHIVE_EXTENSIONS:
                    output.append(incomplete("Nested archive inspection is not configured", entry.filename))
                    continue
                # Bound the read independently of the ZIP's untrusted size metadata.
                with archive.open(entry) as stream:
                    raw = stream.read(MAX_DETONATION_SIZE + 1)
                if len(raw) > MAX_DETONATION_SIZE:
                    output.append(incomplete("Archive member exceeds sample size limit", entry.filename))
                    continue
                output.append({**child, "filename": f"{filename} / {entry.filename}",
                               "archive": filename, "archive_member": entry.filename,
                               "sha256": hashlib.sha256(raw).hexdigest(),
                               "content_b64": base64.b64encode(raw).decode("ascii")})
                launched += 1
    except (BadZipFile, ValueError, OSError, RuntimeError, NotImplementedError) as exc:
        output.append(incomplete(f"Cannot inspect ZIP: {exc}"))
    return output or [incomplete("No eligible executable or document members found in ZIP")]
