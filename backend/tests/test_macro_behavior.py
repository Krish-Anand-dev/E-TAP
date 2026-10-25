"""
Tests for static behavioral macro analysis (v2 "static sandbox" upgrade).

This never executes any macro code -- it verifies that oletools'
VBA_Scanner (via analyze_macros()) correctly identifies auto-exec
triggers, suspicious API usage, and referenced IOCs from real malicious-
style VBA source, and that Stage B2 correctly surfaces that detail.

Run from backend/:
    python tests/test_macro_behavior.py
"""
import sys
import os
import base64
import json
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from forensics.macro_scan import analyze_macro_behavior
from forensics.attachment_forensics import analyze_attachments


def test_real_malicious_vba_source_is_correctly_flagged():
    """
    Proves the underlying oletools engine (not our wiring) correctly
    identifies real malicious-style behavior in VBA source. This is the
    same scan_vba() call path analyze_macros() uses internally.
    """
    from oletools.olevba import scan_vba

    malicious_vba = """
    Sub AutoOpen()
        Dim x As Object
        Set x = CreateObject("WScript.Shell")
        x.Run "powershell.exe -enc SGVsbG8="
        Shell("cmd.exe /c calc.exe")
    End Sub
    """
    results = scan_vba(malicious_vba, False)
    types_found = {r[0] for r in results}
    assert "AutoExec" in types_found, "should detect AutoOpen as an auto-exec trigger"
    assert "Suspicious" in types_found, "should detect Shell/CreateObject/powershell as suspicious"
    assert "IOC" in types_found, "should surface referenced executable names as IOCs"
    print("PASS: real malicious VBA source correctly flagged by oletools")


def test_wiring_surfaces_behavior_correctly():
    """Proves our own code correctly maps oletools' findings into our output shape."""
    fake_vba = MagicMock()
    fake_vba.detect_vba_macros.return_value = True
    fake_vba.analyze_macros.return_value = [
        ("AutoExec", "AutoOpen", "Runs when the Word document is opened"),
        ("Suspicious", "Shell", "May run an executable file or a system command"),
        ("Suspicious", "CreateObject", "May create an OLE object"),
        ("IOC", "powershell.exe", "Executable file name"),
        ("IOC", "cmd.exe", "Executable file name"),
    ]

    with patch("forensics.macro_scan.VBA_Parser", return_value=fake_vba):
        result = analyze_macro_behavior(b"fake ole bytes", "invoice.docm")

    assert result["has_macro"] is True
    assert result["suspicious"] is True
    assert result["autoexec_triggers"] == ["AutoOpen"]
    assert set(result["suspicious_actions"]) == {"Shell", "CreateObject"}
    assert set(result["referenced_iocs"]) == {"powershell.exe", "cmd.exe"}
    assert len(result["flags"]) == 3  # 1 autoexec + 2 suspicious, IOCs not duplicated into flags
    print("PASS: wiring correctly surfaces behavioral findings")


def test_clean_document_produces_no_false_positives():
    fake_clean = MagicMock()
    fake_clean.detect_vba_macros.return_value = False

    with patch("forensics.macro_scan.VBA_Parser", return_value=fake_clean):
        result = analyze_macro_behavior(b"x", "report.docx")

    assert result == {
        "has_macro": False, "suspicious": False,
        "autoexec_triggers": [], "suspicious_actions": [],
        "referenced_iocs": [], "flags": [],
        "parse_failed": False,
    }
    print("PASS: clean document produces no false positives")


def test_full_pipeline_through_stage_b2():
    """End-to-end through analyze_attachments(), same entry point Stage B2 exposes."""
    fake_vba = MagicMock()
    fake_vba.detect_vba_macros.return_value = True
    fake_vba.analyze_macros.return_value = [
        ("AutoExec", "AutoOpen", "Runs when the Word document is opened"),
        ("Suspicious", "Shell", "May run an executable file or a system command"),
    ]

    attachment = {
        "filename": "invoice.docm",
        "content_type": "application/vnd.ms-word.document.macroEnabled.12",
        "content_bytes_b64": base64.b64encode(b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1fake").decode(),
    }

    with patch("forensics.macro_scan.VBA_Parser", return_value=fake_vba):
        result = analyze_attachments([attachment])

    att = result["attachments"][0]
    assert att["has_macro"] is True
    assert att["suspicious"] is True
    assert att["macro_behavior"]["autoexec_triggers"] == ["AutoOpen"]
    assert "auto-runs on open (AutoOpen)" in " ".join(att["flags"])
    print("PASS: full Stage B2 pipeline surfaces macro behavior end-to-end")


if __name__ == "__main__":
    test_real_malicious_vba_source_is_correctly_flagged()
    test_wiring_surfaces_behavior_correctly()
    test_clean_document_produces_no_false_positives()
    test_full_pipeline_through_stage_b2()
    print("\nAll tests passed.")
