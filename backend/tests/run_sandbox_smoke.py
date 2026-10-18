"""Opt-in live API/VM smoke test; never runs during unittest discovery.

From the repository root:
  .venv/Scripts/python backend/tests/run_sandbox_smoke.py --email sample.eml --allow-vm-reset
Uses an isolated in-memory DB and offline intelligence/AI; restores the configured
VM snapshot before and after executing the supplied attachment inside the VM.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
from pathlib import Path
import sys
import time


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--email", type=Path, required=True)
    parser.add_argument("--allow-vm-reset", action="store_true", required=True)
    parser.add_argument("--expect-process", default="")
    parser.add_argument("--expect-blocked-target", default="")
    args = parser.parse_args()
    root = Path(__file__).resolve().parents[2]
    sys.path.insert(0, str(root / "backend"))
    from dotenv import load_dotenv
    load_dotenv(root / ".env")
    os.environ.update(USE_FAKE_DB="1", THREAT_INTEL_LIVE="0", GEMINI_API_KEY="",
                      USE_FALLBACK_EMBEDDINGS="1", SANDBOX_BACKEND="virtualbox",
                      SANDBOX_DWELL_SECONDS="10")
    logging.basicConfig(level=logging.INFO)
    from fastapi.testclient import TestClient
    from app import app
    from sandbox.vbox import VBox

    with TestClient(app) as client:
        response = client.post("/analyze", files={
            "file": (args.email.name, args.email.read_bytes(), "message/rfc822"),
        })
        response.raise_for_status()
        initial = response.json()
        email_id = initial["email_id"]
        print("EMAIL", email_id, "INITIAL", initial["sandbox"], flush=True)
        deadline = time.monotonic() + 480
        previous = None
        while time.monotonic() < deadline:
            response = client.get(f"/investigations/{email_id}")
            response.raise_for_status()
            report = response.json()
            status = report["sandbox"].get("status")
            if status != previous:
                print("STATUS", status, flush=True)
                previous = status
            if status in {"done", "partial", "error", "unavailable", "not_applicable"}:
                break
            time.sleep(4)
        else:
            raise TimeoutError("Sandbox job did not finish within 480 seconds")
        output = root / ".local" / "sandbox-smoke.json"
        output.parent.mkdir(exist_ok=True)
        output.write_text(json.dumps(report, indent=2, default=str), encoding="utf-8")
        sandbox = report["sandbox"]
        print("RESULT", json.dumps(sandbox, indent=2), flush=True)
        print("FINAL VM STATE", VBox()._vm_state(), flush=True)
        assert sandbox["status"] == "done", sandbox
        assert sandbox["finished_at"]
        assert sandbox["coverage"]["rules_loaded"] > 0
        assert sandbox["items"] and all(i["event_count"] > 0 for i in sandbox["items"])
        if args.expect_process:
            names = {p["name"].lower() for i in sandbox["items"] for p in i["process_tree"]}
            assert args.expect_process.lower() in names, names
        if args.expect_blocked_target:
            blocked = [i for i in sandbox["items"] if i["verdict"] == "blocked_by_security_control"]
            assert blocked, sandbox
            messages = " ".join(e["message"] for i in blocked for e in i["security_events"])
            assert args.expect_blocked_target.lower() in messages.lower(), messages
        assert "content_b64" not in json.dumps(sandbox)
        status_response = client.get(f"/sandbox/{email_id}")
        status_response.raise_for_status()
        assert status_response.json()["sandbox"]["status"] == sandbox["status"]
        print("PASS: ingestion, queued job, live VM execution, telemetry, rules, persistence and both APIs", flush=True)


if __name__ == "__main__":
    main()
