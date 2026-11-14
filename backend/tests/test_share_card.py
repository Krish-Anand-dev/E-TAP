"""Share card: no message content, never 'safe' when checks are missing, off without Cloudinary."""
import io
import os
import sys
from datetime import datetime, timezone
from unittest import mock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cloudinary_store as cs  # noqa: E402
import share_card as sc  # noqa: E402

ENV = ("CLOUDINARY_URL", "CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET", "CLOUDINARY_ENABLED")
WHEN = datetime(2026, 10, 30, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def clean(monkeypatch):
    for name in ENV:
        monkeypatch.delenv(name, raising=False)
    sc._ensured.clear()


def configure(monkeypatch):
    monkeypatch.setenv("CLOUDINARY_URL", "cloudinary://key123:secret@democloud")


def report(band="danger", limitations=None, top=("att.macro", "link.bad")):
    return {"conclusion": {"band": band, "limitations": limitations or []}, "top_reasons": list(top)}


def test_off_without_cloudinary_and_makes_no_request():
    with mock.patch.object(cs.requests, "post") as post:
        assert sc.for_report(label="SUSPICIOUS", band="caution", score=50, evidence_report=report("caution"), ensure=True) is None
    assert not post.called


def test_card_url_has_verdict_score_and_date_but_no_message_content(monkeypatch):
    configure(monkeypatch)
    ev = report("danger")
    ev["evidence"] = [{"id": "att.macro", "title": "Invoice_Q3.docm has a macro", "detail": "from evil@bank-fake.com"}]
    card = sc.for_report(label="HIGH-RISK PHISHING", band="danger", score=91, evidence_report=ev, analyzed_at=WHEN)
    assert card["url"].startswith("https://res.cloudinary.com/democloud/image/upload/")
    assert card["url"].endswith("/etap/templates/card_danger.png")
    assert "HIGH-RISK%20PHISHING" in card["url"] and "Risk%20score%2091%20of%20100" in card["url"]
    assert "30%20Oct%202026" in card["url"]
    for private in ("Invoice", "evil", "bank-fake", "docm"):
        assert private not in card["url"]
    assert card["reasons"] == ["An attachment looks dangerous", "A link in the message looks risky"]
    assert "fl_attachment" in card["download_url"] and "fl_attachment" not in card["url"]


def test_good_result_says_no_problems_found_never_safe(monkeypatch):
    configure(monkeypatch)
    card = sc.for_report(label="LIKELY LEGITIMATE", band="safe", score=5, evidence_report=report("safe", top=()), analyzed_at=WHEN)
    assert card["key"] == "safe" and card["headline"] == "NO PROBLEMS FOUND"
    assert "SAFE" not in card["headline"].upper().replace("NO PROBLEMS", "")


def test_good_result_with_missing_checks_becomes_limited_grey_card(monkeypatch):
    configure(monkeypatch)
    ev = report("safe", limitations=["Original email headers were not available"], top=())
    card = sc.for_report(label="LOW RISK", band="safe", score=12, evidence_report=ev, analyzed_at=WHEN)
    assert card["key"] == "limited" and card["headline"] == "LIMITED CHECK"
    assert card["url"].endswith("card_limited.png") and "Some checks could not run" in card["reasons"]


def test_missing_checks_do_not_soften_a_dangerous_result():
    assert sc.card_key("danger", ["Headers missing"]) == "danger"
    assert sc.card_key("caution", ["Headers missing"]) == "caution"


def test_text_layers_cannot_break_the_url():
    assert sc._clean('Pay now, "Bob" / 100% <b>x</b>?#&') == "Pay now Bob 100 b x b"
    assert sc._clean(None) == ""


def test_reason_without_matching_evidence_still_gives_a_line():
    assert sc.reasons_for("danger", []) == ["The overall risk score is high"]
    assert sc.reasons_for("caution", ["zzz.unknown"]) == ["The overall risk score is raised"]
    assert len(sc.reasons_for("danger", ["att.a", "link.b", "rep.c", "qr.d"])) == 3


def test_templates_are_valid_1200_by_630_pngs():
    from PIL import Image
    for key in sc.COLOURS:
        image = Image.open(io.BytesIO(sc.template_png(key)))
        assert image.size == (1200, 630)
        assert image.getpixel((5, 5)) == sc.COLOURS[key][0]


def test_fallback_png_without_pillow_is_valid(monkeypatch):
    from PIL import Image
    monkeypatch.setitem(sys.modules, "PIL", None)
    data = sc.template_png("limited")
    monkeypatch.undo()
    assert Image.open(io.BytesIO(data)).size == (1200, 630)


def test_template_uploaded_once_per_colour_without_overwriting(monkeypatch):
    configure(monkeypatch)
    ok = mock.Mock(status_code=200, text="ok")
    with mock.patch.object(cs.requests, "post", return_value=ok) as post:
        for _ in range(3):
            assert sc.for_report(label="SUSPICIOUS", band="caution", score=50, evidence_report=report("caution"), ensure=True)
    assert post.call_count == 1
    sent = post.call_args.kwargs["data"]
    assert sent["public_id"] == "etap/templates/card_caution" and sent["overwrite"] == "false"


def test_card_is_skipped_when_the_template_cannot_be_saved(monkeypatch):
    configure(monkeypatch)
    with mock.patch.object(cs.requests, "post", return_value=mock.Mock(status_code=401, text="bad key")):
        assert sc.for_report(label="SUSPICIOUS", band="caution", score=50, evidence_report=report("caution"), ensure=True) is None


def test_network_error_never_raises(monkeypatch):
    configure(monkeypatch)
    with mock.patch.object(cs.requests, "post", side_effect=cs.requests.ConnectionError("down")):
        assert sc.for_report(label="SUSPICIOUS", band="caution", score=50, evidence_report=report("caution"), ensure=True) is None
