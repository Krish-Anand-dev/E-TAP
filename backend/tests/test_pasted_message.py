"""Pasted message: a new way in. No headers, so sender checks are skipped and never score; the rest is unchanged."""
import hashlib
from email.message import EmailMessage

import pytest
from fastapi.testclient import TestClient

from app import app
from ai_engine.stage_g import _offline_final_assessment
from db.connection import set_db
from db.fake_mongo import FakeDatabase
from forensics.header_forensics import analyze_headers

TEXT = ("HDFC Bank Alert: your account will be SUSPENDED today. Complete KYC now: "
        "http://kyc-update-hdfc-secure.top/login and open the attached invoice.")
SCRIPT = b'// harmless demo\nvar sh = new ActiveXObject("WScript.Shell");\n'


def pasted_eml(with_attachment=True) -> bytes:
    """The same shape the browser builds: no From/To/Date/Received, text + html, files attached."""
    msg = EmailMessage()
    msg["Subject"] = "Pasted message: HDFC Bank Alert"
    msg["Message-ID"] = "<pasted-test@etap.local>"
    msg.set_content(TEXT)
    msg.add_alternative(f'<html><body><p>{TEXT.replace("http://kyc-update-hdfc-secure.top/login", "<a href=\"http://kyc-update-hdfc-secure.top/login\">http://kyc-update-hdfc-secure.top/login</a>")}</p></body></html>', subtype="html")
    if with_attachment:
        msg.add_attachment(SCRIPT, maintype="application", subtype="javascript", filename="invoice.js")
    return bytes(msg)


@pytest.fixture
def client(monkeypatch):
    monkeypatch.setenv("THREAT_INTEL_LIVE", "0")
    monkeypatch.setenv("GEMINI_API_KEY", "")
    monkeypatch.setenv("USE_FAKE_DB", "1")
    set_db(FakeDatabase())
    with TestClient(app) as c:
        yield c


def analyze(client, raw, source="forwarded_message"):
    response = client.post("/analyze", files={"file": ("pasted-message.eml", raw, "message/rfc822")}, data={"source": source})
    assert response.status_code == 200, response.text
    return response.json()


def test_pasted_message_skips_headers_but_checks_links_and_attachments(client):
    report = analyze(client, pasted_eml())
    headers = report["headers"]
    assert headers["not_applicable"] is True and headers["available"] is False
    assert (headers["spf"], headers["dkim"], headers["dmarc"]) == ("not_available",) * 3
    assert headers["red_flags"] == [] and headers["risk_indicator_count"] == 0
    assert report["analysis_provenance"]["input_mode"] == "forwarded_message"
    assert report["analysis_provenance"]["headers_available"] is False
    assert report["stage_status"]["B"] == "not_applicable"
    # everything else still ran: the link was found and the attachment was hashed
    assert any("kyc-update-hdfc-secure.top" in url for url in report["iocs"]["urls"])
    attachment = report["attachments"][0]
    assert attachment["filename"] == "invoice.js" and attachment["sha256"] == hashlib.sha256(SCRIPT).hexdigest()
    assert report["link_analysis"]["summary"]["total"] >= 1


def test_the_report_says_sender_checks_do_not_apply(client):
    report = analyze(client, pasted_eml())
    limits = report["evidence_report"]["conclusion"]["limitations"]
    assert any("pasted message" in text and "do not apply" in text for text in limits)
    assert not any("Link destinations and attachments were not inspected" in text for text in limits)
    auth = next(item for item in report["evidence_report"]["evidence"] if item["id"] == "hdr.auth")
    assert auth["status"] == "unavailable"
    # a missing check is never shown as safe: the share card is the grey "limited" one at best
    assert report["share_card"] is None or report["share_card"]["key"] != "safe"


def test_pasted_message_with_a_dangerous_attachment_still_scores_high(client):
    report = analyze(client, pasted_eml())
    assert report["risk_score"] >= 40  # suspicious script + risky link, with no help from headers


def test_headers_never_add_to_a_pasted_message_score():
    parsed = {"from_email": "ceo@paypa1-support.top", "from_display_name": "PayPal Support",
              "reply_to": "x@elsewhere.example", "all_headers": {}}
    skipped = analyze_headers(parsed, headers_available=False, not_an_email=True)
    assert skipped["not_applicable"] is True and skipped["red_flags"] == []
    hostile = {"not_applicable": True, "red_flags": ["a", "b", "c"], "reply_to_mismatch": True,
               "spf": "fail", "dkim": "fail", "dmarc": "fail"}
    with_hostile = _offline_final_assessment({"header_forensics": hostile}, {})
    without = _offline_final_assessment({"header_forensics": {"not_applicable": True}}, {})
    assert with_hostile["risk_score"] == without["risk_score"] == 0
    # for a real email the same flags do count, so the skip is specific to pasted messages
    assert _offline_final_assessment({"header_forensics": {**hostile, "not_applicable": False}}, {})["risk_score"] > 0


def test_a_real_email_is_unaffected(client):
    message = b"From: sender@example.test\r\nSubject: Hello\r\nContent-Type: text/plain\r\n\r\nMeeting notes"
    report = analyze(client, message, source="full_message")
    assert report["headers"].get("not_applicable") in (False, None)
    assert report["stage_status"]["B"] == "complete"


def test_unknown_sources_are_still_refused(client):
    response = client.post("/analyze", files={"file": ("a.eml", pasted_eml(), "message/rfc822")}, data={"source": "made_up"})
    assert response.status_code == 400
