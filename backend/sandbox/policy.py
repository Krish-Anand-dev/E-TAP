"""
sandbox.policy — Detonation policy and file-type launcher mapping.
===================================================================
Decides which attachments get sent to the VM and how to launch them.
"""

from __future__ import annotations

import os
import logging

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

# Launcher mapping: extension -> (guest_exe, args_template)
# args_template uses {file} as placeholder for the file path
LAUNCHER_MAP = {
    # Scripts
    # Console host reports script errors instead of waiting on invisible GUI dialogs.
    ".js":   (r"C:\Windows\System32\cscript.exe", '//Nologo "{file}"'),
    ".jse":  (r"C:\Windows\System32\cscript.exe", '//Nologo "{file}"'),
    ".vbs":  (r"C:\Windows\System32\cscript.exe", '//Nologo "{file}"'),
    ".vbe":  (r"C:\Windows\System32\cscript.exe", '//Nologo "{file}"'),
    ".wsf":  (r"C:\Windows\System32\cscript.exe", '//Nologo "{file}"'),
    ".wsh":  (r"C:\Windows\System32\wscript.exe", '"{file}"'),
    ".hta":  (r"C:\Windows\System32\mshta.exe", '"{file}"'),
    ".bat":  (r"C:\Windows\System32\cmd.exe", '/c "{file}"'),
    ".cmd":  (r"C:\Windows\System32\cmd.exe", '/c "{file}"'),
    ".ps1":  (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              '-ExecutionPolicy Bypass -File "{file}"'),
    ".psh":  (r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
              '-ExecutionPolicy Bypass -File "{file}"'),

    # Executables
    ".exe":  (None, '"{file}"'),  # Run directly
    ".msi":  (r"C:\Windows\System32\msiexec.exe", '/i "{file}" /qn'),
    ".scr":  (None, '"{file}"'),

    # Shortcuts
    ".lnk":  (r"C:\Windows\System32\cmd.exe", '/c start "" "{file}"'),
    ".url":  (r"C:\Windows\System32\cmd.exe", '/c start "" "{file}"'),

    # Documents (require installed applications)
    ".doc":   (None, None),  # Need Word
    ".docx":  (None, None),
    ".docm":  (None, None),
    ".dotm":  (None, None),
    ".xls":   (None, None),  # Need Excel
    ".xlsx":  (None, None),
    ".xlsm":  (None, None),
    ".xltm":  (None, None),
    ".ppt":   (None, None),  # Need PowerPoint
    ".pptx":  (None, None),
    ".pptm":  (None, None),
    ".potm":  (None, None),
    ".rtf":   (None, None),
    ".pdf":   (None, None),  # Need PDF viewer
    ".html":  (None, None),  # Need browser
    ".htm":   (None, None),
    ".mhtml": (None, None),
    ".mht":   (None, None),
    ".svg":   (None, None),
    ".xml":   (None, None),
    ".one":   (None, None),  # Need OneNote
    ".onepkg": (None, None),
    ".eml":   (None, None),  # Need email client
    ".msg":   (None, None),
}


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


def launcher_for(filename: str) -> tuple[str | None, str | None]:
    """
    Return (guest_exe, args_template) for launching a file in the VM.

    Returns (None, None) if no launcher is configured for this extension
    (requires manual application installation check).
    """
    ext = _get_extension(filename)
    return LAUNCHER_MAP.get(ext, (None, None))


def _get_extension(filename: str) -> str:
    """Extract lowercase file extension."""
    if "." in filename:
        return "." + filename.rsplit(".", 1)[-1].lower()
    return ""
