"""Background analysis jobs (live stage progress) and verified trusted senders."""
import os
import sys
import time
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["USE_FAKE_DB"] = "1"
os.environ["THREAT_INTEL_LIVE"] = "0"
os.environ.pop("GEMINI_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import app  # noqa: E402
from db import connection  # noqa: E402
from db.fake_mongo import FakeDatabase  # noqa: E402
from workflow_c import trusted_sender_check  # noqa: E402

EML = b"""From: Payroll <hr@payro11-update.com>
To: a@example.com
Subject: Urgent payroll verification
Message-ID: <job-test-1@payro11-update.com>
Date: Mon, 1 Jan 2026 10:00:00 +0000
Content-Type: text/plain

Verify your payroll account now at http://payro11-update.com/login.
"""


class AnalysisJobTests(unittest.TestCase):
    def setUp(self):
        connection.set_db(FakeDatabase())
        self.client = TestClient(app)

    def wait(self, job_id, limit=120):
        deadline = time.time() + limit
        while time.time() < deadline:
            job = self.client.get(f"/analyze/jobs/{job_id}").json()
            if job["status"] != "running":
                return job
            time.sleep(0.2)
        self.fail("job did not finish")

    def test_job_reports_every_stage_and_returns_report(self):
        started = self.client.post("/analyze/jobs", files={"file": ("a.eml", EML, "message/rfc822")})
        self.assertEqual(started.status_code, 200)
        body = started.json()
        self.assertEqual([s["key"] for s in body["stages"]][:4], ["parse", "headers", "static_attachments", "sandbox"])
        job = self.wait(body["job_id"])
        self.assertEqual(job["status"], "done")
        states = {s["key"]: s["state"] for s in job["stages"]}
        self.assertEqual(states["sandbox"], "not_available")
        self.assertEqual(states["reputation"], "skipped")
        for key in ("parse", "headers", "static_attachments", "indicators", "history", "ai", "verdict"):
            self.assertEqual(states[key], "done", key)
        self.assertTrue(job["report"]["email_id"])
        self.assertIn(job["report"]["verdict"], job["stages"][-1]["detail"])

    def test_unknown_job_is_404(self):
        self.assertEqual(self.client.get("/analyze/jobs/nope").status_code, 404)

    def test_rejected_file_is_reported_as_job_error(self):
        started = self.client.post("/analyze/jobs", files={"file": ("a.eml", b"MZ\x90\x00binary", "message/rfc822")})
        job = self.wait(started.json()["job_id"])
        self.assertEqual(job["status"], "error")
        self.assertIn("rejected", job["error"])


def _report(spf="pass", dkim="pass", dmarc="pass", flags=None, score=50, **extra):
    report = {
        "risk_score": score,
        "headers": {"sender_email": "billing@mail.vendor.com", "spf": spf, "dkim": dkim, "dmarc": dmarc,
                    "available": True, "domain_analysis": {"flags": flags or []}},
        "attachments": [], "threat_intel": {},
    }
    report.update(extra)
    return report


class TrustedSenderTests(unittest.TestCase):
    def test_verified_sender_lowers_risk(self):
        result = trusted_sender_check(_report(), {"vendor.com"})
        self.assertTrue(result["applied"])
        self.assertEqual(result["new_score"], 25)

    def test_failed_authentication_is_not_trusted(self):
        result = trusted_sender_check(_report(dmarc="fail"), {"vendor.com"})
        self.assertFalse(result["applied"])
        self.assertEqual(result["status"], "unverified")
        self.assertIn("DMARC", result["explanation"])

    def test_spoofing_signs_or_bad_attachment_block_trust(self):
        self.assertFalse(trusted_sender_check(_report(flags=["lookalike_of_paypal.com"]), {"vendor.com"})["applied"])
        self.assertFalse(trusted_sender_check(_report(attachments=[{"suspicious": True}]), {"vendor.com"})["applied"])

    def test_domain_not_on_list_is_untouched(self):
        self.assertEqual(trusted_sender_check(_report(), {"other.com"})["status"], "not_trusted")
        self.assertEqual(trusted_sender_check(_report(), {"notvendor.com"})["status"], "not_trusted")


if __name__ == "__main__":
    unittest.main()
