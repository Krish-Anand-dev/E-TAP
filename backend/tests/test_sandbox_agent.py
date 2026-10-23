"""Paired sandbox agent: pairing, job queue, result scoring. Nothing is executed."""
import base64
import gzip
import json
import os
import sys
import time
import unittest
from email.message import EmailMessage
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["USE_FAKE_DB"] = "1"
os.environ["THREAT_INTEL_LIVE"] = "0"
os.environ.pop("GEMINI_API_KEY", None)

from fastapi.testclient import TestClient  # noqa: E402

from app import app  # noqa: E402
from db import connection, repository  # noqa: E402
from db.fake_mongo import FakeDatabase  # noqa: E402
from sandbox import agent_queue  # noqa: E402

SCRIPT = b"// harmless fixture, never executed\nWScript.Echo('hi');\n"


def eml_with_script() -> bytes:
    msg = EmailMessage()
    msg["From"] = "Billing <billing@invoices-example.test>"
    msg["To"] = "a@example.com"
    msg["Subject"] = "Your invoice"
    msg["Message-ID"] = f"<agent-{time.time_ns()}@invoices-example.test>"
    msg["Date"] = "Mon, 1 Jan 2026 10:00:00 +0000"
    msg.set_content("Please open the attached invoice.")
    msg.add_attachment(SCRIPT, maintype="application", subtype="javascript", filename="invoice.js")
    return msg.as_bytes()


def process_event(guid, parent, command, image):
    from xml.sax.saxutils import escape
    fields = {"ProcessGuid": guid, "ParentProcessGuid": parent, "CommandLine": command,
              "Image": image, "ParentImage": r"C:\Windows\System32\cmd.exe"}
    data = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in fields.items())
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><EventID>1</EventID></System><EventData>' + data + '</EventData></Event>')


class SandboxAgentTests(unittest.TestCase):
    def setUp(self):
        self.env = patch.dict(os.environ, {"SANDBOX_BACKEND": "agent"})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.db = FakeDatabase()
        connection.set_db(self.db)
        self.addCleanup(connection.reset_db)
        self.client = TestClient(app)
        # Each test registers agents and uploads emails; start every test with fresh rate limits.
        import sandbox_api
        sandbox_api.limiter.reset()
        app.state.limiter.reset()

    def register(self):
        response = self.client.post("/sandbox/agent/register", json={
            "name": "Test PC", "version": "0.1.0", "vm": {"name": "Win11-Sandbox", "snapshot": "clean"}})
        self.assertEqual(response.status_code, 200)
        return response.json()

    def pair(self):
        agent = self.register()
        auth = {"Authorization": f"Bearer {agent['agent_token']}"}
        self.assertFalse(self.client.get("/sandbox/agent/me", headers=auth).json()["paired"])
        code = agent["pairing_code"].replace("-", "").lower()  # typed loosely
        paired = self.client.post("/sandbox/pair", json={"code": code})
        self.assertEqual(paired.status_code, 200)
        self.assertTrue(self.client.get("/sandbox/agent/me", headers=auth).json()["paired"])
        return auth, {"X-ETAP-Sandbox-Token": paired.json()["sandbox_token"]}

    def analyze(self, client_headers, deep=True):
        response = self.client.post("/analyze", headers=client_headers,
                                    data={"deep_analysis": "1"} if deep else {},
                                    files={"file": ("invoice.eml", eml_with_script(), "message/rfc822")})
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    def test_pairing_code_is_single_use_and_tokens_are_hashed(self):
        agent = self.register()
        self.assertEqual(self.client.post("/sandbox/pair", json={"code": agent["pairing_code"]}).status_code, 200)
        self.assertEqual(self.client.post("/sandbox/pair", json={"code": agent["pairing_code"]}).status_code, 404)
        self.assertNotIn(agent["agent_token"], json.dumps(list(self.db["sandbox_agents"].find()), default=str))
        self.assertEqual(self.client.get("/sandbox/agent/me", headers={"Authorization": "Bearer eta_wrong"}).status_code, 401)

    def test_status_reports_online_agent(self):
        auth, client = self.pair()
        status = self.client.get("/sandbox/pairing", headers=client).json()
        self.assertTrue(status["paired"] and status["online"])
        self.assertEqual(status["vm_name"], "Win11-Sandbox")
        self.assertFalse(self.client.get("/sandbox/pairing").json()["paired"])

    def test_standard_analysis_does_not_queue(self):
        _, client = self.pair()
        report = self.analyze(client, deep=False)
        self.assertEqual(report["sandbox"]["status"], "not_requested")
        self.assertEqual(self.db["sandbox_jobs"].count_documents({}), 0)

    def test_deep_analysis_without_pairing_is_reported(self):
        report = self.analyze({}, deep=True)
        self.assertEqual(report["sandbox"]["status"], "not_requested")
        self.assertEqual(self.db["sandbox_jobs"].count_documents({}), 0)

    def test_full_round_trip_raises_score(self):
        auth, client = self.pair()
        report = self.analyze(client)
        email_id = report["email_id"]
        self.assertEqual(report["sandbox"]["status"], "queued")
        before = repository.get_analysis(self.db, email_id)["risk_score"]

        job = self.client.post("/sandbox/agent/jobs/next", headers=auth).json()["job"]
        self.assertEqual(job["samples"][0]["filename"], "invoice.js")
        sample = self.client.get(f"/sandbox/agent/jobs/{job['job_id']}/samples/0", headers=auth)
        self.assertEqual(sample.content, SCRIPT)
        self.assertIsNone(self.client.post("/sandbox/agent/jobs/next", headers=auth).json()["job"])

        self.client.post(f"/sandbox/agent/jobs/{job['job_id']}/progress", headers=auth, json={"status": "interacting"})
        live = self.client.get(f"/sandbox/{email_id}").json()["sandbox"]
        self.assertEqual((live["status"], live["mode"]), ("interacting", "agent"))

        marker = "sample_job_test_abcd1234"
        xml = ("<Events>" + process_event("root", "outside", rf"cscript //Nologo C:\sandbox\in\{marker}.js",
                                          r"C:\Windows\System32\cscript.exe") + "</Events>")
        result = self.client.post(f"/sandbox/agent/jobs/{job['job_id']}/result", headers=auth, json={
            "items": [{"index": 0, "filename": "renamed.js", "sample": f"{marker}.js", "sample_marker": marker,
                       "launched": True, "verdict": "behavior_observed", "interaction_log": [{"action": "launch"}]}],
            "sysmon_xml_gz_b64": base64.b64encode(gzip.compress(xml.encode())).decode(),
            "security_events": [],
        })
        self.assertEqual(result.status_code, 200, result.text)
        self.assertEqual(result.json()["status"], "done")

        final = self.client.get(f"/sandbox/{email_id}").json()
        item = final["sandbox"]["items"][0]
        self.assertEqual(item["filename"], "invoice.js")  # the issued name wins
        self.assertEqual(item["verdict"], "behavior_observed")
        self.assertIn("etap-004", [m["rule_id"] for m in item["matches"]])
        self.assertGreaterEqual(final["risk_score"], max(before, 65))
        self.assertEqual(self.db["sandbox_job_files"].count_documents({}), 0)
        dossier = self.client.get(f"/investigations/{email_id}").json()
        self.assertEqual(dossier["sandbox"]["status"], "done")
        self.assertEqual(dossier["risk_score"], final["risk_score"])
        # A finished job cannot be resubmitted.
        again = self.client.post(f"/sandbox/agent/jobs/{job['job_id']}/result", headers=auth, json={"items": []})
        self.assertEqual(again.status_code, 409)

    def test_other_agents_cannot_take_or_read_a_job(self):
        auth, client = self.pair()
        self.analyze(client)
        other = {"Authorization": f"Bearer {self.register()['agent_token']}"}
        self.assertIsNone(self.client.post("/sandbox/agent/jobs/next", headers=other).json()["job"])
        job = self.client.post("/sandbox/agent/jobs/next", headers=auth).json()["job"]
        self.assertEqual(self.client.get(f"/sandbox/agent/jobs/{job['job_id']}/samples/0", headers=other).status_code, 404)

    def test_unclaimed_job_expires_and_report_says_so(self):
        _, client = self.pair()
        email_id = self.analyze(client)["email_id"]
        with patch.object(agent_queue, "_now", return_value=time.time() + 7200):
            sandbox = self.client.get(f"/sandbox/{email_id}").json()["sandbox"]
        self.assertEqual(sandbox["status"], "error")
        self.assertIn("did not pick this up", sandbox["error"])
        self.assertEqual(self.db["sandbox_job_files"].count_documents({}), 0)

    def test_defender_checkpoint_failure_is_reported_not_hidden(self):
        auth, client = self.pair()
        email_id = self.analyze(client)["email_id"]
        job = self.client.post("/sandbox/agent/jobs/next", headers=auth).json()["job"]
        self.client.post(f"/sandbox/agent/jobs/{job['job_id']}/result", headers=auth, json={
            "items": [], "security_events": [], "defender_checkpoint_error": "GuestProcessTimeout: VERR_TIMEOUT"})
        sandbox = self.client.get(f"/sandbox/{email_id}").json()["sandbox"]
        self.assertIs(sandbox["defender_checked"], False)
        self.assertIn("not checked", sandbox["defender_note"])

    def test_dtd_in_telemetry_is_refused(self):
        auth, client = self.pair()
        self.analyze(client)
        job = self.client.post("/sandbox/agent/jobs/next", headers=auth).json()["job"]
        xml = '<!DOCTYPE x [<!ENTITY a "b">]><Events></Events>'
        response = self.client.post(f"/sandbox/agent/jobs/{job['job_id']}/result", headers=auth, json={
            "items": [], "sysmon_xml_gz_b64": base64.b64encode(gzip.compress(xml.encode())).decode()})
        self.assertEqual(response.status_code, 400)

    def test_agent_routes_are_off_unless_backend_is_agent(self):
        with patch.dict(os.environ, {"SANDBOX_BACKEND": "none"}):
            self.assertEqual(self.client.post("/sandbox/agent/register", json={}).status_code, 404)
            self.assertFalse(self.client.get("/sandbox/pairing").json()["available"])

    def test_agent_download_is_a_zip_with_the_package(self):
        import io
        import zipfile
        response = self.client.get("/sandbox/agent/download")
        self.assertEqual(response.status_code, 200)
        names = zipfile.ZipFile(io.BytesIO(response.content)).namelist()
        self.assertIn("E-TAP Sandbox Agent/sandbox_agent/__main__.py", names)
        self.assertIn("E-TAP Sandbox Agent/sandbox_agent/runner.py", names)
        self.assertIn("E-TAP Sandbox Agent/start-agent.cmd", names)


if __name__ == "__main__":
    unittest.main()
