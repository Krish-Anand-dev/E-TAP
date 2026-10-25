"""Original Gmail bytes must take the same header-analysis path as an .eml upload.

Run without pytest: python -m unittest discover -s backend/tests -p test_extension_original.py
"""
import os
import sys
import unittest
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from db.connection import set_db
from db.fake_mongo import FakeDatabase
from email_parser.eml_parser import parse_eml_bytes
from pipeline import analyze_email_upload


ORIGINAL = (
    b"Delivered-To: reader@example.test\r\n"
    b"Received: from relay.example.test by mx.google.com; Sun, 18 Oct 2026 08:00:00 +0000\r\n"
    b"Received: from sender.example.test by relay.example.test; Sun, 18 Oct 2026 07:59:59 +0000\r\n"
    b"Authentication-Results: mx.google.com; spf=pass;\r\n\tdkim=pass; dmarc=pass\r\n"
    b"From: Sender <sender@example.test>\r\nTo: reader@example.test\r\n"
    b"Date: Sun, 18 Oct 2026 08:00:00 +0000\r\nMessage-ID: <extension-original@example.test>\r\n"
    b"Subject: Original message\r\nMIME-Version: 1.0\r\nContent-Type: multipart/mixed; boundary=x\r\n\r\n"
    b"--x\r\nContent-Type: text/plain; charset=iso-8859-1\r\nContent-Transfer-Encoding: 8bit\r\n\r\ncaf\xe9\r\n"
    b"--x\r\nContent-Type: application/octet-stream\r\nContent-Disposition: attachment; filename=sample.bin\r\n"
    b"Content-Transfer-Encoding: base64\r\n\r\nAP+A\r\n--x--\r\n"
)


class ExtensionOriginalTests(unittest.TestCase):
    def test_mime_and_repeated_transport_headers_are_retained(self):
        parsed = parse_eml_bytes(ORIGINAL).to_dict()
        self.assertEqual(len(parsed["all_headers"]["Received"]), 2)
        self.assertIn("caf\xe9", parsed["body_text"])
        self.assertEqual(parsed["attachments"][0]["filename"], "sample.bin")

    def test_full_message_evaluates_authentication_like_manual_upload(self):
        with patch.dict(os.environ, {"USE_FAKE_DB": "1", "THREAT_INTEL_LIVE": "0", "GEMINI_API_KEY": "", "USE_FALLBACK_EMBEDDINGS": "1"}), \
                patch("ai_engine.triage_model._get_model", return_value=None), \
                patch("forensics.auth_results._query_txt_records", side_effect=AssertionError("Delivered auth headers should be used")):
            set_db(FakeDatabase())
            extension = analyze_email_upload("gmail_original.eml", ORIGINAL, "full_message")
            set_db(FakeDatabase())
            manual = analyze_email_upload("downloaded.eml", ORIGINAL)
        self.assertEqual(extension["headers"], manual["headers"])
        self.assertTrue(extension["headers"]["available"])
        for mechanism in ("spf", "dkim", "dmarc"):
            self.assertEqual(extension["headers"][mechanism], "pass")
        self.assertEqual(len(extension["headers"]["received_chain"]), 2)
        self.assertEqual(extension["analysis_provenance"]["input_mode"], "full_message")
        self.assertTrue(extension["analysis_provenance"]["headers_available"])
        self.assertEqual(extension["stage_status"]["B"], "complete")
        auth = next(item for item in extension["evidence_report"]["evidence"] if item["id"] == "hdr.auth")
        self.assertEqual(auth["title"], "Sender authentication passed")


if __name__ == "__main__":
    unittest.main()
