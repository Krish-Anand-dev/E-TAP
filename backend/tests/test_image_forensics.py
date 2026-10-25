"""
Unit test for Feature 2: Image Forensics (QR decoding and OCR scanning)
"""

import io
import sys
import os
import unittest
import numpy as np

# Ensure backend root is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from forensics.image_forensics import scan_image_attachment
from forensics.attachment_forensics import analyze_attachment
from forensics.ioc_extraction import extract_iocs


class TestImageForensics(unittest.TestCase):

    def setUp(self):
        # Create a simple synthetic image with a QR code or pattern using OpenCV / PIL
        import cv2
        # Generate a small 200x200 image
        img = np.full((200, 200, 3), 255, dtype=np.uint8)
        # Put some text on it
        cv2.putText(img, "URGENT INVOICE OVERDUE", (10, 100), cv2.FONT_HERSHEY_SIMPLEX, 0.5, (0, 0, 0), 1)
        _, encoded = cv2.imencode(".png", img)
        self.test_img_bytes = encoded.tobytes()

    def test_scan_image_empty_and_corrupt(self):
        # Empty bytes should return gracefully
        res_empty = scan_image_attachment(b"", "empty.png")
        self.assertEqual(res_empty["qr_urls"], [])
        self.assertEqual(res_empty["ocr_text"], "")

        # Random corrupt bytes should not crash
        res_corrupt = scan_image_attachment(b"not-a-real-image-byte-sequence-12345", "corrupt.png")
        self.assertEqual(res_corrupt["qr_urls"], [])
        self.assertEqual(res_corrupt["ocr_text"], "")

    def test_scan_synthetic_image(self):
        # Should decode successfully without throwing
        res = scan_image_attachment(self.test_img_bytes, "invoice.png")
        self.assertIsInstance(res["qr_urls"], list)
        self.assertIsInstance(res["ocr_text"], str)

    def test_attachment_forensics_integration(self):
        import base64
        raw_att = {
            "filename": "fake_qr.png",
            "content_type": "image/png",
            "content_bytes_b64": base64.b64encode(self.test_img_bytes).decode("ascii"),
        }
        res = analyze_attachment(raw_att)
        self.assertIn("ocr_text", res)
        self.assertIn("qr_urls", res)
        self.assertEqual(res["actual_type"], "image/png")

    def test_ioc_extraction_with_qr_urls(self):
        fake_attachment_analysis = {
            "attachments": [
                {
                    "filename": "phish_qr.png",
                    "sha256": "a" * 64,
                    "qr_urls": ["https://evil-phish-domain.com/login?id=99"],
                }
            ]
        }
        iocs = extract_iocs(attachment_analysis=fake_attachment_analysis)
        self.assertIn("https://evil-phish-domain.com/login?id=99", iocs["urls"])
        self.assertIn("evil-phish-domain.com", iocs["domains"])
        self.assertIn("ioc_metadata", iocs)
        self.assertEqual(
            iocs["ioc_metadata"]["https://evil-phish-domain.com/login?id=99"]["source"],
            "qr_code"
        )


if __name__ == "__main__":
    unittest.main()
