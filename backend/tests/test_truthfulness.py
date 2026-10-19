"""
B-0 truthfulness regressions (no network, no API keys needed):
  * VirusTotal / AbuseIPDB / WHOIS failures are never cached
  * failed lookups report malicious=None (unknown), never False
  * header analysis can be told the original headers were unavailable
  * error text does not leak the looked-up URL
"""
import os
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import requests
from threat_intel import vt_lookup


def _reset_vt():
    vt_lookup._vt_cache._store.clear()
    vt_lookup._vt_limiter.request_timestamps.clear()
    os.environ["VIRUSTOTAL_API_KEY"] = "fake_key_for_test"


def _ok_response():
    r = MagicMock()
    r.status_code = 200
    r.json.return_value = {"data": {"attributes": {"last_analysis_stats": {"malicious": 3, "harmless": 60}}}}
    r.raise_for_status.return_value = None
    return r


def test_vt_429_is_not_cached():
    _reset_vt()
    limited = MagicMock(status_code=429)
    with patch("threat_intel.vt_lookup.requests.get", side_effect=[limited, _ok_response()]) as get:
        first = vt_lookup.check_url_reputation("http://example.test/a")
        assert first["malicious"] is None and first["status"] == "rate_limited", first
        second = vt_lookup.check_url_reputation("http://example.test/a")
        assert get.call_count == 2, "the 429 must not be served from cache"
        assert second["malicious"] is True and second["malicious_engine_count"] == 3


def test_vt_network_failure_is_not_cached_and_does_not_leak_url():
    _reset_vt()
    # B10: a URL with a token is now skipped before any request (see
    # test_links_qr_privacy.py). The error path still must not echo the URL
    # that WAS sent, so use one that passes the privacy policy.
    secret_url = "http://example.test/account/orders"
    boom = requests.ConnectionError(f"HTTPSConnectionPool ... /urls/{vt_lookup._url_to_vt_id(secret_url)}")
    with patch("threat_intel.vt_lookup.requests.get", side_effect=[boom, _ok_response()]) as get:
        first = vt_lookup.check_url_reputation(secret_url)
        assert first["malicious"] is None and first["status"] == "network_error"
        assert "account/orders" not in first["error"]
        assert vt_lookup._url_to_vt_id(secret_url) not in first["error"]
        vt_lookup.check_url_reputation(secret_url)
        assert get.call_count == 2


def test_vt_definitive_answers_are_cached():
    _reset_vt()
    with patch("threat_intel.vt_lookup.requests.get", return_value=_ok_response()) as get:
        vt_lookup.check_hash_reputation("a" * 64)
        vt_lookup.check_hash_reputation("a" * 64)
        assert get.call_count == 1
    _reset_vt()
    not_found = MagicMock(status_code=404)
    with patch("threat_intel.vt_lookup.requests.get", return_value=not_found) as get:
        r1 = vt_lookup.check_url_reputation("http://never-seen.test/")
        vt_lookup.check_url_reputation("http://never-seen.test/")
        assert r1["malicious"] is None  # unknown, not "clean"
        assert get.call_count == 1


def test_vt_missing_key_is_unknown_not_clean():
    _reset_vt()
    os.environ.pop("VIRUSTOTAL_API_KEY", None)
    r = vt_lookup.check_url_reputation("http://example.test/")
    assert r["malicious"] is None and r["status"] == "not_configured"
    assert "error" in r


def test_abuseipdb_failure_not_cached():
    from threat_intel import ip_lookup
    ip_lookup._ip_cache._store.clear()
    os.environ["ABUSEIPDB_API_KEY"] = "fake_key_for_test"
    ok = MagicMock()
    ok.json.return_value = {"data": {"abuseConfidenceScore": 90, "totalReports": 5, "countryCode": "RU"}}
    ok.raise_for_status.return_value = None
    with patch("threat_intel.ip_lookup.requests.get", side_effect=[requests.Timeout("t"), ok]) as get:
        first = ip_lookup.check_ip_reputation("185.12.34.56")
        assert first["malicious"] is None and "error" in first
        second = ip_lookup.check_ip_reputation("185.12.34.56")
        assert get.call_count == 2 and second["malicious"] is True


def _parsed(from_addr="Alice <alice@example.com>"):
    class P:
        def to_dict(self):
            return {
                "from_email": "alice@example.com", "from_display_name": "Alice",
                "reply_to": None,
                "all_headers": {"From": from_addr, "Subject": "hi"},
            }
    return P()


def test_headers_unavailable_mode_skips_auth_and_marks_not_available():
    from forensics.header_forensics import analyze_headers
    # Must not touch DNS at all in this mode.
    with patch("forensics.header_forensics.evaluate_authentication", side_effect=AssertionError("auth must not run")):
        out = analyze_headers(_parsed(), headers_available=False)
    assert out["available"] is False
    assert out["spf"] == out["dkim"] == out["dmarc"] == "not_available"
    assert out["originating_ip"] is None and out["received_chain"] == []
    assert "no_received_headers" not in out["red_flags"]  # absence is not evidence here
    assert out["unavailable_reason"]


def test_headers_default_mode_unchanged():
    from forensics.header_forensics import analyze_headers
    fake_auth = {k: {"verdict": "pass"} for k in ("spf", "dkim", "dmarc")}
    with patch("forensics.header_forensics.evaluate_authentication", return_value=fake_auth):
        out = analyze_headers(_parsed())
    assert out["available"] is True and out["spf"] == "pass"
    assert "no_received_headers" in out["red_flags"]


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS:", name)
    print("All truthfulness tests passed.")
