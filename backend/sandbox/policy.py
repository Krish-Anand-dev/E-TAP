"""
sandbox.policy — Detonation policy and file-type launcher mapping.
===================================================================
Decides which attachments get sent to the VM and how to launch them.
"""

from __future__ import annotations

import logging

# How each file type is opened inside the guest lives with the agent, which
# runs it; selection (what is worth opening) stays here on the server.
from sandbox_agent.launchers import LAUNCHER_MAP, launcher_for  # noqa: F401

logger = logging.getLogger("E-TAP.sandbox.policy")

# Maximum file size for detonation (10 MB)
MAX_DETONATION_SIZE = 10 * 1024 * 1024

# Maximum attachments per email to detonate
MAX_PER_EMAIL = 3

# Extensions that get detonated (scripts, executables, shortcuts, HTA, archives)
DETONATABLE_EXTENSIONS = frozenset({
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".hta", ".bat", ".cmd", ".ps1", ".psh",
    ".exe", ".msi", ".dll", ".scr",
    ".lnk", ".url",
    ".zip", ".rar", ".7z",
    ".iso", ".img",
    ".one", ".onepkg",  # OneNote
    ".doc", ".docx", ".docm", ".dotm",
    ".xls", ".xlsx", ".xlsm", ".xltm",
    ".ppt", ".pptx", ".pptm", ".potm",
    ".rtf",
    ".pdf",
    ".html", ".htm", ".mhtml", ".mht",
    ".svg", ".xml",
    ".eml", ".msg",
})

# Extensions that are scripts/executables (higher priority)
EXECUTABLE_EXTENSIONS = frozenset({
    ".js", ".jse", ".vbs", ".vbe", ".wsf", ".wsh",
    ".hta", ".bat", ".cmd", ".ps1", ".psh",
    ".exe", ".msi", ".scr",
})

def should_detonate(att_result: dict) -> bool:
    """
    Decide if an attachment should be sent to the sandbox.

    Args:
        att_result: A single attachment's B2 forensic result dict.

    Returns:
        True if the attachment should be detonated.
    """
    filename = att_result.get("filename", "")
    size = att_result.get("size_bytes", 0)
    actual_type = att_result.get("actual_type", "")
    declared_type = att_result.get("declared_type", "")

    # Size check
    if size > MAX_DETONATION_SIZE:
        logger.debug("Skipping %s: too large (%d bytes)", filename, size)
        return False

    if size == 0:
        return False

    # Extension check
    ext = _get_extension(filename)
    if ext in DETONATABLE_EXTENSIONS:
        return True

    # Also check by actual type for files with wrong extensions
    if actual_type in ("application/x-msdownload", "application/x-elf"):
        return True

    # Check for archives by magic bytes
    if actual_type in ("application/zip", "application/x-rar",
                       "application/x-7z-compressed", "application/x-iso9660-image"):
        return True

    return False


def get_detonation_candidates(attachments: list[dict]) -> list[dict]:
    """
    Filter and prioritize attachments for detonation.
    Returns up to MAX_PER_EMAIL attachments, prioritizing executables/scripts.
    """
    candidates = []
    for att in attachments:
        if should_detonate(att):
            candidates.append(att)

    # Sort: executables/scripts first, then by size (smaller first)
    def priority(a):
        ext = _get_extension(a.get("filename", ""))
        is_exec = 0 if ext in EXECUTABLE_EXTENSIONS else 1
        return (is_exec, a.get("size_bytes", 0))

    candidates.sort(key=priority)
    return candidates[:MAX_PER_EMAIL]


def _get_extension(filename: str) -> str:
    """Extract lowercase file extension."""
    if "." in filename:
        return "." + filename.rsplit(".", 1)[-1].lower()
    return ""
