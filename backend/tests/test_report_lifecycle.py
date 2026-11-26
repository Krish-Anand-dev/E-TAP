"""Reopening, re-analyzing and deleting reports (fixes of 2026-11-26), on the in-memory database."""
import threading

import pytest
from fastapi import HTTPException
from fastapi.testclient import TestClient

import cloudinary_store
import login
import pipeline
from app import app, limiter
from db import connection, repository
from db.fake_mongo import FakeDatabase
from sandbox import agent_queue, analysis


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_LIVE", "0")
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    monkeypatch.delenv("SANDBOX_BACKEND", raising=False)
    monkeypatch.setattr(limiter, "enabled", False)
    connection.set_db(FakeDatabase())
    yield TestClient(app)
    connection.reset_db()


def message(mid, body="Please see the file.", script=None):
    head = f"From: a@sender.example\nTo: b@me.example\nSubject: {mid}\nMessage-ID: <{mid}@x>\nMIME-Version: 1.0\n"
    if script is None:
        return (head + f"Content-Type: text/plain\n\n{body}\n").encode()
    return (head + "Content-Type: multipart/mixed; boundary=Z\n\n--Z\nContent-Type: text/plain\n\n"
            f"{body}\n--Z\nContent-Type: application/javascript\n"
            f"Content-Disposition: attachment; filename=a.js\n\n{script}\n--Z--\n").encode()


def analyze(client, raw, **kwargs):
    response = client.post("/analyze", files={"file": ("m.eml", raw)}, **kwargs)
    assert response.status_code == 200, response.text
    return response.json()


def sandbox_saw_malware(email_id):
    analysis.store_results(email_id, {"mode": "agent", "status": "done", "items": [
        {"filename": "a.js", "matches": [{"rule": "x", "rule_id": "etap-004", "prevention_grade": True, "mitre": []}]}]})


LINKED = "Urgent: verify your password at http://evil-login-site.com/a"


def test_reopened_report_keeps_its_history(client):
    analyze(client, message("one", LINKED))
    live = analyze(client, message("two", LINKED))
    stored = client.get(f"/investigations/{live['email_id']}").json()
    assert stored["correlation"]["related_emails"] == live["correlation"]["related_emails"] != []
    assert stored["historical_correlation"]["category_status"] == live["category_status"]


def test_delete_leaves_unrelated_reports_alone_and_resets_linked_ones(client):
    unrelated = analyze(client, message("lunch", "See you at noon."))
    linked = analyze(client, message("one", LINKED))
    victim = analyze(client, message("two", LINKED))
    assert client.delete(f"/investigations/{victim['email_id']}").status_code == 200
    db = connection.get_db()
    assert repository.get_analysis(db, unrelated["email_id"])["evidence_report"]
    after = repository.get_analysis(db, linked["email_id"])
    assert after["evidence_report"] is None and after["historical_correlation"] == {}


def test_rerun_never_lowers_what_the_sandbox_found(client):
    first = analyze(client, message("doc", script="var a = 1;"))
    sandbox_saw_malware(first["email_id"])
    again = analyze(client, message("doc", script="var a = 1;"))
    assert again["risk_score"] >= 85 and again["sandbox"]["items"][0]["matches"]
    stored = client.get(f"/investigations/{first['email_id']}").json()
    assert stored["risk_score"] >= 85 and stored["sandbox"]["status"] == "done"


def test_rerun_with_different_files_drops_the_old_sandbox_result(client):
    first = analyze(client, message("doc", script="var a = 1;"))
    sandbox_saw_malware(first["email_id"])
    again = analyze(client, message("doc", script="var b = 2;"))
    assert again["risk_score"] < 85
    assert not client.get(f"/investigations/{first['email_id']}").json()["sandbox"].get("items")


def test_rerun_deletes_the_images_of_the_earlier_run(client, monkeypatch):
    uploads, deleted = [], []

    def upload(raw, analysed):
        uploads.append(f"etap/img{len(uploads) + 1}")
        for attachment in analysed:
            attachment["cloudinary"] = {"public_id": uploads[-1]}
        return {"uploaded": len(analysed)}

    monkeypatch.setattr(pipeline, "upload_attachment_images", upload)
    monkeypatch.setattr(cloudinary_store, "delete_assets", lambda ids: deleted.extend(ids))
    first = analyze(client, message("img", script="var a = 1;"))
    analyze(client, message("img", script="var a = 1;"))
    assert deleted == ["etap/img1"]
    client.delete(f"/investigations/{first['email_id']}")
    assert deleted == ["etap/img1", "etap/img2"]


@pytest.mark.parametrize("path", ["one", "all"])
def test_delete_cancels_sandbox_work_and_its_attachment_copies(client, monkeypatch, path):
    monkeypatch.setenv("ALLOW_DELETE_ALL", "1")
    agent = agent_queue.register_agent("vm", "1", {})
    token = agent_queue.claim_pairing_code(agent["pairing_code"])["sandbox_token"]
    report = analyze(client, message("deep", script="var a = 1;"), data={"deep_analysis": "1"},
                     headers={"X-ETAP-Sandbox-Token": token})
    db = connection.get_db()
    assert list(db[agent_queue.FILES].find({}))
    client.delete(f"/investigations/{report['email_id']}" if path == "one" else "/investigations")
    assert not list(db[agent_queue.FILES].find({})) and not list(db[agent_queue.JOBS].find({}))
    poll = client.post("/sandbox/agent/jobs/next", json={},
                       headers={"Authorization": f"Bearer {agent['agent_token']}"})
    assert poll.status_code < 300


def test_delete_all_is_off_unless_the_server_switches_it_on(client, monkeypatch):
    report = analyze(client, message("keep"))
    monkeypatch.delenv("ALLOW_DELETE_ALL", raising=False)
    assert client.delete("/investigations").status_code == 403
    assert client.get(f"/investigations/{report['email_id']}").status_code == 200
    monkeypatch.setenv("ALLOW_DELETE_ALL", "1")
    assert client.delete("/investigations").json() == {"deleted": 1}


def test_simultaneous_wrong_codes_cannot_pass_the_attempt_limit(client, monkeypatch):
    monkeypatch.setenv("AUTH_DEV_ECHO", "1")
    monkeypatch.delenv("BREVO_API_KEY", raising=False)
    monkeypatch.delenv("RESEND_API_KEY", raising=False)
    login._ip_hits.clear()
    code = client.post("/auth/request-code", json={"email": "x@y.com"}).json()["dev_code"]
    wrong = "000000" if code != "000000" else "111111"
    collection = connection.get_db()[login.CODES]
    original, together = collection.find_one, threading.Barrier(12)

    def read_together(*args, **kwargs):
        found = original(*args, **kwargs)
        found = dict(found) if found else found  # what each request saw before any counting
        try:
            together.wait(timeout=3)
        except threading.BrokenBarrierError:
            pass
        return found

    monkeypatch.setattr(collection, "find_one", read_together)
    results = []

    def guess():
        try:
            login.verify_code(login.CodeVerify(email="x@y.com", code=wrong))
        except HTTPException as exc:
            results.append(exc.status_code)

    threads = [threading.Thread(target=guess) for _ in range(12)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert results.count(400) <= login.MAX_ATTEMPTS and len(results) == 12


def test_a_trusted_sender_cannot_lower_what_the_sandbox_found():
    from workflow_c import trusted_sender_check
    report = {"risk_score": 85, "headers": {"sender_email": "a@vendor.com", "spf": "pass", "dkim": "pass", "dmarc": "pass"},
              "sandbox": {"items": [{"matches": [{"rule_id": "etap-004"}]}]}}
    result = trusted_sender_check(report, {"vendor.com"})
    assert result["status"] == "unverified" and not result["applied"]
