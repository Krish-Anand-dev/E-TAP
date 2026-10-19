"""Regression checks for parser recovery and the deterministic offline fallback.

Run from backend/: python tests/test_pre_c_fixes.py
No API keys, MongoDB, or live network requests are needed.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from ai_engine.stage_g import _offline_content_classification

BACKEND_DIR = Path(__file__).resolve().parents[1]


def test_invalid_charset_recovers_text_and_records_warning():
    # Run the parser check in a child process so the import-only extract_msg
    # test stub can never contaminate other pytest tests or application imports.
    script = r'''
import importlib.util, sys
from types import SimpleNamespace
if importlib.util.find_spec("extract_msg") is None:
    sys.modules["extract_msg"] = SimpleNamespace(Message=None)
from email_parser.eml_parser import parse_eml_bytes
raw = (
    b"From: sender@example.com\r\n"
    b"To: recipient@example.com\r\n"
    b"Subject: Charset recovery test\r\n"
    b"MIME-Version: 1.0\r\n"
    b"Content-Type: text/plain; charset=DEFAULT\r\n"
    b"\r\n"
    b"Please review the meeting notes at https://example.com/notes\r\n"
)
parsed = parse_eml_bytes(raw)
assert parsed.body_text is not None, parsed.parse_warnings
assert "meeting notes" in parsed.body_text, parsed.body_text
assert any("charset" in warning.lower() or "decoding fallback" in warning.lower() for warning in parsed.parse_warnings), parsed.parse_warnings
'''
    completed = subprocess.run(
        [sys.executable, "-c", script],
        cwd=BACKEND_DIR,
        capture_output=True,
        text=True,
        check=False,
    )
    assert completed.returncode == 0, completed.stdout + completed.stderr


def test_offline_fallback_does_not_flag_every_url_as_malicious():
    report = _offline_content_classification({
        "subject": "Project update",
        "body_text": "See the agenda here: https://example.com/meeting",
    })
    categories = {entry["name"] for entry in report["categories"]}
    assert report["verdict"] != "Likely Malicious"
    assert "Malicious Link / URL" not in categories


def test_offline_fallback_flags_converging_credential_lure_signals():
    report = _offline_content_classification({
        "subject": "Urgent account issue",
        "body_text": "Click here to verify your account immediately https://evil.test/login",
    })
    categories = {entry["name"] for entry in report["categories"]}
    assert report["verdict"] == "Likely Malicious"
    assert "Credential Phishing" in categories
    assert "Malicious Link / URL" in categories


def test_offline_fallback_treats_empty_content_as_incomplete_not_safe():
    report = _offline_content_classification({"subject": "", "body_text": "", "body_html": None})
    assert report["analysis_available"] is False
    assert report["verdict"] == "Suspicious"
    assert report["content_risk_score"] == 50


if __name__ == "__main__":
    for name, function in sorted(globals().items()):
        if name.startswith("test_") and callable(function):
            function()
            print("PASS:", name)
    print("All pre-C parser/fallback regression checks passed.")
