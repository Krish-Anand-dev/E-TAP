"""
Tests for B5 (link text vs destination), B6 (QR trace) and B10 (URL privacy
before VirusTotal, privacy report). Offline; no network.

Run from backend/:  python tests/test_links_qr_privacy.py
"""
import base64
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
os.environ["USE_FAKE_DB"] = "1"
os.environ["THREAT_INTEL_LIVE"] = "0"
os.environ.pop("GEMINI_API_KEY", None)

import privacy
from forensics.link_analysis import analyze_links, analyze_url, registrable_domain
from forensics.qr_trace import build_qr_trace
import evidence as ev


# ---------------------------------------------------------------- B10 policy
def test_plan_full_trimmed_skip():
    assert privacy.plan_url_lookup("https://example.com/")["action"] == "full"
    t = privacy.plan_url_lookup("https://example.com/a?utm=1&page=2#x")
    assert t["action"] == "trimmed" and t["lookup_url"] == "https://example.com/a"
    for url in (
        "https://x.com/v?token=abc",
        "https://x.com/v?e=bob%40corp.com",
        "https://x.com/r?u=aGVsbG93b3JsZHRoaXNpc2Fsb25ndG9rZW4",
        "https://user:pw@x.com/",
        "http://192.168.1.5/admin",
        "http://intranet/hr",
        "https://x.com/9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
        "https://x.com/#access_token=abcdef",
    ):
        p = privacy.plan_url_lookup(url)
        assert p["action"] == "skip" and p["lookup_url"] is None and p["reasons"], url


def test_ordinary_urls_are_not_over_blocked():
    for url in ("https://news.com/2024/article-about-something-interesting-today",
                "https://x.com/documentation/getting-started-guide-v2",
                "https://inside.com/p?inside=1"):  # 'sid' must not match inside 'inside'
        assert privacy.plan_url_lookup(url)["action"] != "skip", url


def test_vt_never_called_for_sensitive_url_and_receives_trimmed_url():
    from threat_intel import vt_lookup
    seen = []
    real = vt_lookup._vt_lookup
    vt_lookup._vt_lookup = lambda key, path: seen.append((key, path)) or {"malicious": False}
    try:
        r = vt_lookup.check_url_reputation("https://evil.com/login?token=SECRET123&e=bob%40corp.com")
        assert r["status"] == "skipped_privacy" and r["malicious"] is None and seen == []
        assert "SECRET123" not in str(r) and "bob" not in str(r)

        r = vt_lookup.check_url_reputation("https://example.com/a?page=2")
        assert r["lookup_url_trimmed"] is True and len(seen) == 1
        sent = base64.urlsafe_b64decode(seen[0][1].split("/")[1] + "==").decode()
        assert sent == "https://example.com/a", sent  # query string never left
    finally:
        vt_lookup._vt_lookup = real


def test_skipped_lookup_is_unknown_not_clean_in_evidence():
    ti = {"lookup_mode": "live", "url_reputation": {
        "https://evil.com/v?token=abc": {"malicious": None, "status": "skipped_privacy",
                                         "privacy_reasons": ["sensitive_parameter_name"]}}}
    items = ev._reputation_items(ti)
    ids = [i["id"] for i in items]
    assert "rep.url.unavailable" in ids and "rep.url.clean" not in ids
    it = next(i for i in items if i["id"] == "rep.url.unavailable")
    assert "privacy" in it["detail"].lower() or "VirusTotal" in it["detail"]
    assert it["direction"] == ev.NEUTRAL and it["status"] == ev.STATUS_UNAVAILABLE


def test_privacy_report_matches_policy_and_mode():
    iocs = {"urls": ["https://a.com/x", "https://a.com/y?p=1", "https://b.com/v?token=zz"],
            "ips": ["8.8.8.8"], "domains": ["a.com", "b.com"], "hashes": []}
    off = privacy.build_privacy_report(email={}, iocs=iocs, threat_intel={},
                                       provenance={"threat_intel_mode": "offline_placeholder",
                                                   "assessment_provider": "offline_fallback"})
    assert off["url_lookups"]["sent_in_full"] == 0 and off["url_lookups"]["sent_trimmed"] == 0
    assert off["url_lookups"]["would_send_in_full"] == 1 and off["url_lookups"]["would_send_trimmed"] == 1
    assert len(off["url_lookups"]["skipped_for_privacy"]) == 1
    flows = {f["id"]: f for f in off["flows"]}
    assert flows["gemini"]["status"] == "off" and flows["virustotal_urls"]["status"] == "off"

    live = privacy.build_privacy_report(email={}, iocs=iocs, threat_intel={"url_reputation": {
                                            "https://a.com/x": {"status": "available", "lookup_source": "remote", "malicious": False},
                                            "https://a.com/y?p=1": {"status": "available", "lookup_source": "remote", "malicious": False},
                                            "https://b.com/v?token=zz": {"status": "skipped_privacy", "malicious": None},
                                        }},
                                        provenance={"threat_intel_mode": "live",
                                                    "assessment_provider": "gemini"})
    flows = {f["id"]: f for f in live["flows"]}
    assert live["url_lookups"]["sent_in_full"] == 1 and live["url_lookups"]["sent_trimmed"] == 1
    assert flows["gemini"]["status"] == "sent" and flows["virustotal_urls"]["count"] == 2
    assert "token=zz" not in str(live)  # skipped URLs are shown without their query


# ------------------------------------------------------------------- B5 links
def test_registrable_domain():
    assert registrable_domain("a.b.paypal.com") == "paypal.com"
    assert registrable_domain("shop.example.co.uk") == "example.co.uk"


def test_text_vs_destination_flags():
    html = ('<a href="http://evil.example.ru/x">https://www.paypal.com/signin</a>'
            '<a href="https://paypal.com@evil.com/">www.paypal.com</a>'
            '<a href="https://news.example.com/unsub">Unsubscribe</a>'
            '<a href="https://www.paypal.com/help">https://paypal.com/help</a>'
            '<a href="mailto:a@b.com">mail</a><a href="#top">top</a>')
    r = analyze_links(html)
    by_host = {l["host"]: l for l in r["links"]}
    assert "text_shows_different_site" in by_host["evil.example.ru"]["flags"]
    assert "userinfo_in_url" in by_host["evil.com"]["flags"]
    assert by_host["news.example.com"]["flags"] == []            # no claim in text, no flag
    assert by_host["www.paypal.com"]["flags"] == []              # same site, different subdomain/path
    assert r["summary"]["total"] == 4                            # mailto and # skipped
    assert all(l["resolution"]["status"] == "not_resolved" for l in r["links"])


def test_redirect_parameter_is_labelled_inferred():
    l = analyze_url("https://track.mailer.com/c?url=https%3A%2F%2Fbank.evil.io%2Fx", "Read more")
    assert "redirect_parameter_to_other_site" in l["flags"]
    assert l["details"]["inferred_target_host"] == "bank.evil.io"
    assert l["resolution"]["status"] == "not_resolved"


def test_no_html_is_unavailable_not_clean():
    r = analyze_links(None)
    assert r["available"] is False
    items = ev._link_analysis_items(r, {"urls": ["https://a.com"]}, "full_message")
    assert [i["id"] for i in items] == ["link.text_check"] and items[0]["status"] == ev.STATUS_UNAVAILABLE
    assert ev._link_analysis_items(r, {"urls": ["https://a.com"]}, "quick_content_check") == []


def test_link_evidence_strength():
    strong = analyze_links('<a href="https://paypa1.com/l">https://www.paypal.com</a>')
    items = ev._link_analysis_items(strong, {"urls": ["x"]}, "full_message")
    flag = next(i for i in items if i["id"] == "link.flag.0")
    assert flag["direction"] == ev.RAISES and flag["weight"] == ev.STRONG
    # a bare tracking redirect with a mismatch only is weak, with a hedge
    weak = analyze_links('<a href="https://click.mailer.com/x">https://www.nytimes.com/story</a>')
    flag = next(i for i in ev._link_analysis_items(weak, {"urls": ["x"]}, "full_message") if i["id"] == "link.flag.0")
    assert flag["weight"] == ev.WEAK and "legitimate" in flag["why"]
    ok = analyze_links('<a href="https://example.com/a">Read the docs</a>')
    items = ev._link_analysis_items(ok, {"urls": ["x"]}, "full_message")
    assert any(i["id"] == "link.text_ok" for i in items)
    assert all(i["direction"] == ev.NEUTRAL for i in items)      # never "lowers risk"


# --------------------------------------------------------------------- B6 QR
def _qr_png(text):
    import cv2
    img = cv2.QRCodeEncoder.create().encode(text)
    img = cv2.resize(img, None, fx=8, fy=8, interpolation=cv2.INTER_NEAREST)
    img = cv2.copyMakeBorder(img, 40, 40, 40, 40, cv2.BORDER_CONSTANT, value=255)
    return cv2.imencode(".png", img)[1].tobytes()


def _att(png, name):
    from forensics.attachment_forensics import analyze_attachment
    return analyze_attachment({"filename": name, "content_type": "image/png",
                               "size_bytes": len(png), "content_bytes_b64": base64.b64encode(png).decode()})


def test_qr_trace_end_to_end():
    import cv2, numpy as np
    qr = _att(_qr_png("https://paypa1.com/login?e=bob%40corp.com"), "scan-me.png")
    blank = _att(cv2.imencode(".png", np.full((200, 200, 3), 255, np.uint8))[1].tobytes(), "logo.png")
    bad = _att(b"this is not an image at all", "broken.png")
    trace = build_qr_trace([qr, blank, bad])
    by = {e["source_attachment"]: e for e in trace["entries"]}
    assert by["scan-me.png"]["status"] == "decoded"
    link = by["scan-me.png"]["decoded"][0]["link"]
    assert link["host"] == "paypa1.com" and "lookalike_domain" in link["flags"]
    assert link["personalised"] is True
    assert by["logo.png"]["status"] == "no_qr_found" and by["broken.png"]["status"] == "image_unreadable"
    assert by["broken.png"]["checked"] is False

    items = ev._qr_items(trace)
    ids = {i["id"]: i for i in items}
    assert ids["qr.0.0"]["direction"] == ev.RAISES
    assert ids["qr.1.none"]["status"] == ev.STATUS_ABSENT
    assert ids["qr.2.unchecked"]["status"] == ev.STATUS_UNAVAILABLE
    assert "bob" not in str(items)                               # no recipient value in evidence text


def test_benign_qr_is_not_flagged_for_being_a_qr():
    trace = build_qr_trace([_att(_qr_png("https://www.example.org/tickets/summer"), "ticket.png")])
    item = next(i for i in ev._qr_items(trace) if i["id"] == "qr.0.0")
    assert item["direction"] == ev.NEUTRAL and "example.org" in item["title"]


def test_qr_flag_not_double_counted():
    att = _att(_qr_png("https://www.example.org/x"), "t.png")
    old = ev._attachment_items([att], "full_message")
    new = ev._attachment_items([att], "full_message", qr_traced=True)
    assert any(".qr." in i["id"] for i in old)
    assert not any(".qr." in i["id"] or "hidden_qr" in i["id"] for i in new)
    assert not any(i["id"].endswith(".clean") for i in new)      # an image with a QR is not "no red flags"


# ------------------------------------------------------------------ pipeline
def test_pipeline_exposes_new_blocks_and_stays_private():
    from db.connection import reset_db
    from pipeline import analyze_email_upload
    reset_db()
    raw = (b"From: Billing <billing@paypa1-secure.com>\nTo: v@example.com\nSubject: Verify\n"
           b"Message-ID: <t1@x>\nMIME-Version: 1.0\nContent-Type: text/html; charset=utf-8\n\n"
           b'<p><a href="https://paypa1-secure.com/v?token=SECRET99">https://www.paypal.com/verify</a></p>')
    res = analyze_email_upload("t.eml", raw)
    assert res["link_analysis"]["available"] and res["link_analysis"]["summary"]["text_mismatch"] == 1
    assert res["privacy_report"]["url_lookups"]["skipped_for_privacy"]
    assert "SECRET99" not in str(res["privacy_report"])
    ids = [i["id"] for i in res["evidence_report"]["evidence"]]
    assert "link.flag.0" in ids and "link.resolution" in ids


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("PASS:", name)
    print("All B5/B6/B10 tests passed.")
