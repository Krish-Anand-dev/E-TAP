"""
Macro detection and static behavioral analysis for Office documents
(both legacy .doc/.xls/.ppt OLE files and modern .docx/.xlsx/.pptm
zip-based files).

Uses oletools' VBA_Parser -- which handles both formats transparently --
for presence detection, and its VBA_Scanner (via analyze_macros()) for
STATIC behavioral analysis: what the macro's code actually does, without
ever running it. This is "static sandboxing" -- decompiling and scoring
risky behavior, not dynamic detonation.

Never executes anything. Ever.
"""

from __future__ import annotations
import io

try:
    from oletools.olevba import VBA_Parser
    _HAS_OLETOOLS = True
except Exception:
    _HAS_OLETOOLS = False


# oletools' own category names from VBA_Scanner. Kept as constants so the
# rest of the code (and tests) don't rely on magic strings scattered around.
_CATEGORY_AUTOEXEC = "AutoExec"
_CATEGORY_SUSPICIOUS = "Suspicious"
_CATEGORY_IOC = "IOC"

# Categories we escalate straight to "suspicious": true auto-execution
# triggers (runs the instant the file is opened, no user click needed)
# and suspicious API usage (process spawning, network calls, obfuscation
# primitives). "IOC" entries (referenced filenames, URLs) are evidence,
# not on their own proof of malice -- surfaced separately, not counted
# toward the suspicious verdict by themselves.
_HIGH_RISK_CATEGORIES = {_CATEGORY_AUTOEXEC, _CATEGORY_SUSPICIOUS}


def analyze_macro_behavior(data: bytes, filename: str = "") -> dict:
    """
    Static behavioral analysis of any VBA macros in the file.

    Returns:
        {
            "has_macro": bool,
            "suspicious": bool,          # True if any AutoExec or Suspicious-category finding exists
            "autoexec_triggers": [str],  # e.g. "AutoOpen" -- runs on document open, no click needed
            "suspicious_actions": [str], # e.g. "Shell", "CreateObject", "powershell"
            "referenced_iocs": [str],    # e.g. "powershell.exe", "cmd.exe" -- filenames/URLs the macro mentions
            "flags": [str],              # human-readable summary lines for the evidence list
        }

    Never executes the macro -- only statically inspects and decompiles
    its source via oletools. Safe to call on completely untrusted input.
    """
    result = {
        "has_macro": False,
        "suspicious": False,
        "parse_failed": False,
        "autoexec_triggers": [],
        "suspicious_actions": [],
        "referenced_iocs": [],
        "flags": [],
    }

    if not _HAS_OLETOOLS or not data:
        return result

    try:
        vba = VBA_Parser(filename or "attachment", data=data)
    except Exception:
        # Not a parseable Office file, corrupted, or password-protected --
        # flag parse failure so the caller can decide how to treat it.
        # Password-protected Office docs are themselves suspicious and
        # should be escalated by the caller.
        result["parse_failed"] = True
        return result

    try:
        if not vba.detect_vba_macros():
            return result

        result["has_macro"] = True

        try:
            findings = vba.analyze_macros()
        except Exception as exc:
            result["flags"].append(f"macro present but static analysis failed: {exc}")
            return result

        for kw_type, keyword, description in findings:
            if kw_type == _CATEGORY_AUTOEXEC:
                result["autoexec_triggers"].append(keyword)
                result["flags"].append(f"auto-runs on open ({keyword}): {description}")
            elif kw_type == _CATEGORY_SUSPICIOUS:
                result["suspicious_actions"].append(keyword)
                result["flags"].append(f"suspicious API usage ({keyword}): {description}")
            elif kw_type == _CATEGORY_IOC:
                result["referenced_iocs"].append(keyword)
                # IOCs are evidence, not flagged as suspicious on their own --
                # surfaced in referenced_iocs for Stage D to pick up, not
                # duplicated into the human-readable flags list here.

        result["suspicious"] = bool(result["autoexec_triggers"] or result["suspicious_actions"])

        return result
    finally:
        vba.close()


def has_macro(data: bytes, filename: str = "") -> bool:
    """
    Return True if the file contains VBA macro code.

    Kept as a lightweight boolean check for callers that only need
    presence, not full behavioral analysis. Delegates to
    analyze_macro_behavior() so there's exactly one code path for macro
    detection to keep in sync.
    """
    return analyze_macro_behavior(data, filename)["has_macro"]


def is_office_document(filename: str, actual_type: str) -> bool:
    """Quick check used by the caller to decide whether macro scanning is relevant."""
    office_extensions = (
        ".doc", ".docm", ".docx", ".dot", ".dotm",
        ".xls", ".xlsm", ".xlsx", ".xlt", ".xltm",
        ".ppt", ".pptm", ".pptx", ".pot", ".potm",
    )
    office_mimes = (
        "application/msword",
        "application/vnd.ms-excel",
        "application/vnd.ms-powerpoint",
        "application/x-ole-storage",
        "application/vnd.openxmlformats-officedocument",  # prefix match handled below
    )
    name_match = filename.lower().endswith(office_extensions)
    mime_match = any(actual_type.startswith(m) for m in office_mimes)
    return name_match or mime_match
