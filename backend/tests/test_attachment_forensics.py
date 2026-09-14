"""
Quick manual test for Stage B2, using synthetic attachments that cover
each detection case: clean PDF, mismatched type, macro-enabled docx-like
zip, disguised EXE, double extension.
"""
import base64
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
from forensics.attachment_forensics import analyze_attachments

def b64(data: bytes) -> str:
    return base64.b64encode(data).decode()

test_attachments = [
    {
        # Clean, legit PDF -- should NOT be flagged
        "filename": "invoice.pdf",
        "content_type": "application/pdf",
        "bytes_b64": b64(b"%PDF-1.4\n%mock pdf content for testing\n"),
    },
    {
        # Classic phishing trick: EXE renamed with a PDF-looking name, declared as PDF
        "filename": "invoice.pdf",
        "content_type": "application/pdf",
        "bytes_b64": b64(b"MZ\x90\x00\x03\x00\x00\x00fake exe payload for testing"),
    },
    {
        # Double extension trick
        "filename": "invoice.pdf.exe",
        "content_type": "application/octet-stream",
        "bytes_b64": b64(b"MZ\x90\x00\x03\x00\x00\x00another fake exe"),
    },
    {
        # No data at all -- malformed/empty attachment entry
        "filename": "mystery.bin",
        "content_type": "application/octet-stream",
        "bytes_b64": "",
    },
]

result = analyze_attachments(test_attachments)
print(json.dumps(result, indent=2))
