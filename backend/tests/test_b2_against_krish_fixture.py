"""
Integration test: Stage B2 against Krish's real Stage A fixture
(docs/parser_fixtures/double_extension_attachment.json), instead of
purely synthetic data. Confirms the actual key name Stage A uses
(content_bytes_b64) is handled correctly end-to-end.

Run from backend/:
    python tests/test_b2_against_krish_fixture.py
"""
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from forensics.attachment_forensics import analyze_attachments

FIXTURE_PATH = os.path.join(
    os.path.dirname(__file__), "..", "..", "docs", "parser_fixtures",
    "double_extension_attachment.json"
)

def main():
    with open(FIXTURE_PATH, encoding="utf-8") as f:
        email_obj = json.load(f)

    result = analyze_attachments(email_obj["attachments"])
    print(json.dumps(result, indent=2))

    by_name = {a["filename"]: a for a in result["attachments"]}

    assert by_name["payslip.pdf"]["suspicious"] is False, "payslip.pdf should be clean"
    assert by_name["policy_update.pdf.exe"]["suspicious"] is True, "disguised exe should be flagged"
    assert by_name["policy_update.pdf.exe"]["type_mismatch"] is True
    assert by_name["policy_update.pdf.exe"]["actual_type"] == "application/x-msdownload"

    print("\nAll assertions passed against Krish's real fixture.")

if __name__ == "__main__":
    main()
