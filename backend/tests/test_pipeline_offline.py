"""
Offline end-to-end regression for A -> B/B2 -> D -> E -> F -> G -> H.

Run from backend/:
    python tests/test_pipeline_offline.py
"""

from __future__ import annotations

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

os.environ["USE_FAKE_DB"] = "1"
os.environ["THREAT_INTEL_LIVE"] = "0"
os.environ.pop("GEMINI_API_KEY", None)

from db.connection import reset_db
from pipeline import analyze_email_upload


def _sample_email(message_id: str, subject: str) -> bytes:
    return f"""From: Security Team <security-alert@example-security.com>
To: victim@example.com
Subject: {subject}
Date: Sat, 5 Sep 2026 21:30:00 +0530
Message-ID: {message_id}
Reply-To: verify@example-security-support.com
Authentication-Results: mx.example.com; spf=fail smtp.mailfrom=example-security.com; dkim=fail; dmarc=fail
Received: from attacker.example-security.com (attacker.example-security.com [45.33.32.156]) by mx.example.com
MIME-Version: 1.0
Content-Type: text/plain; charset=utf-8

Urgent: your account will be suspended within 24 hours.
Verify your login immediately at http://example-security-login.com/verify.
""".encode("utf-8")


def main():
    reset_db()

    first = analyze_email_upload(
        "first.eml",
        _sample_email("<pipeline-offline-1@example.com>", "Urgent account verification"),
    )
    second = analyze_email_upload(
        "second.eml",
        _sample_email("<pipeline-offline-2@example.com>", "Final warning: verify account"),
    )

    assert first["stage_status"]["H"] == "complete"
    assert first["stage_status"]["E"] == "offline_placeholder"
    assert first["ai_analysis"]["content_classification"]["provider"] == "offline_fallback"
    assert 0 <= first["risk_score"] <= 100
    assert first["verdict"]
    assert first["iocs"]["urls"]

    assert first["email_id"] in second["correlation"]["related_emails"]
    assert second["correlation"]["shared_infrastructure"]
    assert second["correlation"]["campaign_id"] == first["correlation"]["campaign_id"]

    print("PASS: offline end-to-end pipeline returns final JSON and correlates history")
    print("First verdict:", first["verdict"], first["risk_score"])
    print("Second related emails:", second["correlation"]["related_emails"])


if __name__ == "__main__":
    main()
