"""
sandbox_agent.launchers -- how each file type is opened inside the guest VM.
===========================================================================
Maps an attachment's extension to (guest_exe, args_template); `{file}` in
the template is replaced with the sample's path inside the guest.
"""

from __future__ import annotations

import os


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


def launcher_for(filename: str) -> tuple[str | None, str | None]:
    """
    Return (guest_exe, args_template) for launching a file in the VM.

    Returns (None, None) if no launcher is configured for this extension
    (requires manual application installation check).
    """
    ext = _get_extension(filename)
    if ext == ".pdf":
        return _pdf_launcher()
    return LAUNCHER_MAP.get(ext, (None, None))


def _pdf_launcher() -> tuple[str | None, str | None]:
    """
    PDFs open in the guest's PDF viewer.

    SANDBOX_PDF_VIEWER (a path inside the guest, e.g. Acrobat Reader) is used
    when set; otherwise the guest's default PDF handler opens the file via
    `start`. SANDBOX_PDF_VIEWER=none turns PDF opening off again.
    Note: nothing clicks inside the document, and Windows 11's default viewer
    (Edge) does not run PDF Launch actions, so a PDF that only acts on a click
    or a prompt is expected to come back inconclusive.
    """
    viewer = os.getenv("SANDBOX_PDF_VIEWER", "").strip()
    if viewer.lower() == "none":
        return (None, None)
    if viewer:
        return (viewer, '"{file}"')
    return (r"C:\Windows\System32\cmd.exe", '/c start "" "{file}"')


def _get_extension(filename: str) -> str:
    """Extract lowercase file extension."""
    if "." in filename:
        return "." + filename.rsplit(".", 1)[-1].lower()
    return ""
