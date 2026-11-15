"""Offline fallback (used when Gemini is down): fee-before-deadline scams, no false alarms, honest status."""
import pytest

from ai_engine import stage_g
from ai_engine.stage_g import _offline_content_classification, analyze_with_stage_g

INDIA_POST = ("India Post: your parcel IN7731902 is held at the sorting hub because of an unpaid redelivery fee "
              "of Rs 49. Pay within 12 hours or it will be returned to sender: http://india-post-redeliver.xyz/pay?id=IN7731902")


def categories(report):
    return {entry["name"] for entry in report["categories"]}


def test_parcel_fee_scam_is_not_called_legitimate():
    report = _offline_content_classification({"subject": "", "body_text": INDIA_POST})
    assert report["verdict"] == "Likely Malicious"
    assert {"Payment / Invoice Fraud", "Malicious Link / URL"} <= categories(report)
    assert report["content_risk_score"] >= 80


@pytest.mark.parametrize("text", [
    "Toll fee of Rs 40 unpaid on your FASTag. Settle the amount within 24 hours: http://fastag-toll-pay.top/x",
    "Customs fee pending for your package. Pay now within 2 days or it will be returned to sender http://dhl-clearance.click/p",
])
def test_other_fee_scams_are_caught(text):
    assert _offline_content_classification({"subject": "", "body_text": text})["verdict"] == "Likely Malicious"


@pytest.mark.parametrize("text", [
    "Thanks for your order. Your receipt is here: https://shop.example.com/receipt/123. Delivery within 3 days.",
    "Your monthly statement is ready: https://bank.example.com/statements. No action needed.",
    "Reminder: team lunch within 2 days, see the menu https://example.com/menu",
    "Your parcel is on the way and arrives tomorrow, track it at https://courier.example.com/t/9",
])
def test_ordinary_messages_are_not_flagged_as_fee_scams(text):
    report = _offline_content_classification({"subject": "", "body_text": text})
    assert report["verdict"] != "Likely Malicious"
    assert "Payment / Invoice Fraud" not in categories(report) or "fee demanded" not in " ".join(report["suspicious_indicators"])


def test_no_link_means_no_fee_scam():
    report = _offline_content_classification({"subject": "", "body_text": "Unpaid fee of Rs 49, pay within 12 hours."})
    assert "a fee demanded through a link before a deadline" not in report["suspicious_indicators"]


def test_fallback_status_is_honest_when_the_key_is_set(monkeypatch):
    def down(context):
        raise RuntimeError("All Gemini models failed -> m: ServerError 503 UNAVAILABLE")
    monkeypatch.setattr(stage_g, "_gemini_combined_analysis", down)
    monkeypatch.setenv("GEMINI_API_KEY", "set")
    result = analyze_with_stage_g({"email": {"subject": "", "body_text": INDIA_POST}})
    for part in (result["content_classification"], result["final_assessment"]):
        assert part["provider"] == "offline_fallback"
        assert "unavailable" in part["status"] and "not configured" not in part["status"]
        assert "503" in part["fallback_reason"]
    assert result["final_assessment"]["verdict"] != "LIKELY LEGITIMATE"


def test_fallback_status_still_says_not_configured_without_a_key(monkeypatch):
    def down(context):
        raise RuntimeError("no key")
    monkeypatch.setattr(stage_g, "_gemini_combined_analysis", down)
    monkeypatch.delenv("GEMINI_API_KEY", raising=False)
    result = analyze_with_stage_g({"email": {"subject": "Hi", "body_text": "See you at lunch"}})
    assert "not configured" in result["content_classification"]["status"]
