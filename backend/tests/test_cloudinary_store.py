"""Cloudinary evidence store: off by default, never breaks an analysis, cleans up after itself."""
import base64
import hashlib
import io
import os
import sys
from unittest import mock

import pytest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import cloudinary_store as cs  # noqa: E402
from forensics.attachment_forensics import analyze_attachments  # noqa: E402

ENV = ("CLOUDINARY_URL", "CLOUDINARY_CLOUD_NAME", "CLOUDINARY_API_KEY", "CLOUDINARY_API_SECRET",
       "CLOUDINARY_ENABLED", "CLOUDINARY_OCR", "CLOUDINARY_MODERATION")


@pytest.fixture(autouse=True)
def clean_env(monkeypatch):
    for name in ENV:
        monkeypatch.delenv(name, raising=False)


def configure(monkeypatch, **extra):
    monkeypatch.setenv("CLOUDINARY_URL", "cloudinary://key123:sec%2Fret@democloud")
    for k, v in extra.items():
        monkeypatch.setenv(k, v)


def png_attachment():
    from PIL import Image
    buf = io.BytesIO()
    Image.new("RGB", (40, 40), "white").save(buf, "PNG")
    return {"filename": "scan.png", "content_type": "image/png",
            "content_bytes_b64": base64.b64encode(buf.getvalue()).decode()}


def reply(status=200, body=None):
    response = mock.Mock(status_code=status, text="x")
    response.json.return_value = body or {}
    return response


UPLOADED = {"secure_url": "https://res.cloudinary.com/democloud/image/upload/v1/etap/abc.png",
            "public_id": "etap/abc", "width": 40, "height": 40, "bytes": 99, "format": "png"}


def test_off_without_credentials_and_makes_no_request():
    raw = [png_attachment()]
    results = analyze_attachments(raw)["attachments"]
    with mock.patch.object(cs.requests, "post") as post:
        summary = cs.upload_attachment_images(raw, results)
    assert summary == {"enabled": False, "attempted": 0, "uploaded": 0, "failed": 0}
    assert not post.called and "cloudinary" not in results[0]


def test_url_credentials_are_parsed(monkeypatch):
    configure(monkeypatch)
    assert cs._credentials() == ("democloud", "key123", "sec/ret")
    monkeypatch.setenv("CLOUDINARY_ENABLED", "0")
    assert not cs.enabled()


def test_signature_follows_the_cloudinary_rule():
    params = {"timestamp": 5, "public_id": "etap/a", "tags": "etap,evidence"}
    expected = hashlib.sha1(b"public_id=etap/a&tags=etap,evidence&timestamp=5SECRET").hexdigest()
    assert cs._sign(params, "SECRET") == expected


def test_image_is_uploaded_and_recorded(monkeypatch):
    configure(monkeypatch)
    raw = [png_attachment()]
    results = analyze_attachments(raw)["attachments"]
    with mock.patch.object(cs.requests, "post", return_value=reply(200, UPLOADED)) as post:
        summary = cs.upload_attachment_images(raw, results)
    assert summary["uploaded"] == 1 and summary["failed"] == 0
    info = results[0]["cloudinary"]
    assert info["public_id"] == "etap/abc"
    assert "e_blur" in info["blurred_url"] and "e_blur" not in info["preview_url"]
    sent = post.call_args.kwargs["data"]
    assert sent["api_key"] == "key123" and sent["public_id"].startswith("etap/") and "ocr" not in sent


def test_only_images_are_uploaded(monkeypatch):
    configure(monkeypatch)
    pdf = {"filename": "a.pdf", "content_type": "application/pdf",
           "content_bytes_b64": base64.b64encode(b"%PDF-1.4 hi").decode()}
    raw = [pdf]
    results = analyze_attachments(raw)["attachments"]
    with mock.patch.object(cs.requests, "post") as post:
        summary = cs.upload_attachment_images(raw, results)
    assert summary["attempted"] == 0 and not post.called


def test_a_failed_upload_never_breaks_the_analysis(monkeypatch):
    configure(monkeypatch)
    raw = [png_attachment()]
    results = analyze_attachments(raw)["attachments"]
    with mock.patch.object(cs.requests, "post", side_effect=cs.requests.ConnectionError("down")):
        summary = cs.upload_attachment_images(raw, results)
    assert summary["failed"] == 1 and "cloudinary" not in results[0]


def test_addon_failure_retries_without_addons_and_keeps_the_upload(monkeypatch):
    configure(monkeypatch, CLOUDINARY_OCR="1", CLOUDINARY_MODERATION="1")
    with mock.patch.object(cs.requests, "post", side_effect=[reply(400), reply(200, UPLOADED)]) as post:
        info = cs.upload_image(b"img", "a.png")
    assert info and info["public_id"] == "etap/abc"
    first, second = (c.kwargs["data"] for c in post.call_args_list)
    assert first["ocr"] == "adv_ocr" and first["moderation"] == "aws_rek"
    assert "ocr" not in second and "moderation" not in second


def test_ocr_and_moderation_results_reach_the_report(monkeypatch):
    configure(monkeypatch, CLOUDINARY_OCR="1", CLOUDINARY_MODERATION="1")
    body = dict(UPLOADED,
                info={"ocr": {"adv_ocr": {"data": [{"description": "Pay now: bank-verify.example"}]}}},
                moderation=[{"status": "rejected", "response": {"moderation_labels": [{"name": "Suggestive"}]}}])
    raw = [png_attachment()]
    results = analyze_attachments(raw)["attachments"]
    with mock.patch.object(cs.requests, "post", return_value=reply(200, body)):
        cs.upload_attachment_images(raw, results)
    assert results[0]["ocr_text"] == "Pay now: bank-verify.example"
    assert any("Cloudinary OCR" in f for f in results[0]["flags"])
    assert any("moderation rejected" in f for f in results[0]["flags"])


def test_at_most_three_images_per_email(monkeypatch):
    configure(monkeypatch)
    raw = [png_attachment() for _ in range(5)]
    results = analyze_attachments(raw)["attachments"]
    with mock.patch.object(cs.requests, "post", return_value=reply(200, UPLOADED)):
        summary = cs.upload_attachment_images(raw, results)
    assert summary["attempted"] == cs.MAX_IMAGES


def test_delete_removes_the_saved_images(monkeypatch):
    configure(monkeypatch)
    doc = {"attachment_analysis": {"attachments": [{"cloudinary": {"public_id": "etap/a"}}, {"filename": "x"}]}}
    assert cs.public_ids_of(doc) == ["etap/a"]
    with mock.patch.object(cs.requests, "post", return_value=reply(200, {"result": "ok"})) as post:
        assert cs.delete_assets(cs.public_ids_of(doc)) == 1
    assert post.call_args.args[0].endswith("/image/destroy")
    assert cs.delete_assets([]) == 0


def test_privacy_report_says_when_images_left_the_server(monkeypatch):
    import privacy
    configure(monkeypatch)
    sent = privacy.build_privacy_report(email={}, iocs={}, threat_intel={}, provenance={},
                                        attachments=[{"cloudinary": {"public_id": "etap/a"}}])
    flow = {f["id"]: f for f in sent["flows"]}["cloudinary"]
    assert flow["status"] == "sent" and flow["count"] == 1
    monkeypatch.delenv("CLOUDINARY_URL")
    off = privacy.build_privacy_report(email={}, iocs={}, threat_intel={}, provenance={}, attachments=[])
    assert {f["id"]: f for f in off["flows"]}["cloudinary"]["status"] == "off"
