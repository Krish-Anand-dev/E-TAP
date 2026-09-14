"""
Test Stage E with mocked HTTP responses (shaped exactly like the real
APIs' documented responses) plus real behavior checks for missing keys
and rate-limit handling. No live network calls -- see also
test_threat_intel_live.py for a real end-to-end check you should run
yourself with actual API keys before the demo.
"""
import sys, os, json
from unittest.mock import patch, MagicMock

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from threat_intel.ip_lookup import check_ip_reputation, get_ip_geolocation
from threat_intel.vt_lookup import check_url_reputation, check_hash_reputation
from threat_intel.threat_intel import enrich_iocs


def test_ip_reputation_no_key():
    # No ABUSEIPDB_API_KEY set -> should degrade gracefully, not crash
    os.environ.pop("ABUSEIPDB_API_KEY", None)
    result = check_ip_reputation("185.12.34.56")
    assert "error" in result
    print("PASS: check_ip_reputation degrades gracefully with no key")


def test_ip_reputation_with_mock():
    os.environ["ABUSEIPDB_API_KEY"] = "fake_key_for_test"
    mock_response = MagicMock()
    mock_response.json.return_value = {
        "data": {
            "ipAddress": "118.25.6.39",
            "abuseConfidenceScore": 100,
            "totalReports": 1,
            "countryCode": "CN",
            "isp": "Tencent Cloud Computing",
            "domain": "tencent.com",
            "isTor": False,
        }
    }
    mock_response.raise_for_status = lambda: None

    with patch("threat_intel.ip_lookup.requests.get", return_value=mock_response):
        result = check_ip_reputation("118.25.6.39")

    assert result["malicious"] is True
    assert result["abuse_confidence_score"] == 100
    print("PASS: check_ip_reputation parses real AbuseIPDB response shape correctly")
    print(json.dumps(result, indent=2))


def test_geolocation_with_mock():
    mock_response = MagicMock()
    mock_response.json.return_value = [
        {
            "status": "success", "query": "8.8.8.8", "countryCode": "US",
            "lat": 39.03, "lon": -77.5, "isp": "Google LLC", "org": "Google Public DNS",
            "hosting": True, "proxy": False,
        }
    ]
    mock_response.raise_for_status = lambda: None

    with patch("threat_intel.ip_lookup.requests.post", return_value=mock_response):
        result = get_ip_geolocation(["8.8.8.8"])

    assert result["8.8.8.8"]["lat"] == 39.03
    assert result["8.8.8.8"]["country"] == "US"
    print("PASS: get_ip_geolocation parses real ip-api.com batch response correctly")
    print(json.dumps(result, indent=2))


def test_vt_rate_limit_handled_gracefully():
    os.environ["VIRUSTOTAL_API_KEY"] = "fake_key_for_test"
    mock_response = MagicMock()
    mock_response.status_code = 429

    with patch("threat_intel.vt_lookup.requests.get", return_value=mock_response):
        result = check_url_reputation("http://fake-bank.com/login")

    assert "error" in result and "rate limit" in result["error"].lower()
    print("PASS: VirusTotal 429 handled gracefully, not raised as exception")


def test_vt_not_previously_scanned():
    os.environ["VIRUSTOTAL_API_KEY"] = "fake_key_for_test"
    mock_response = MagicMock()
    mock_response.status_code = 404

    with patch("threat_intel.vt_lookup.requests.get", return_value=mock_response):
        result = check_hash_reputation("deadbeef" * 8)

    assert result["malicious"] is None
    print("PASS: VirusTotal 404 (unknown hash) reported as unknown, not treated as clean or crash")


def test_enrich_iocs_end_to_end_with_mocks():
    """Full Stage E call against a Stage-D-shaped IOC dict, all APIs mocked."""
    os.environ["ABUSEIPDB_API_KEY"] = "fake"
    os.environ["VIRUSTOTAL_API_KEY"] = "fake"

    # Use a fresh IP not touched by earlier tests in this file -- the module-level
    # TTLCache persists across test functions in one process run, so reusing
    # "8.8.8.8" here would silently return an earlier test's cached mock result
    # instead of this test's own mock.
    fake_iocs = {
        "ips": ["1.1.1.1"],
        "domains": ["example.com"],
        "urls": ["http://example.com/x"],
        "hashes": [],
    }

    abuse_mock = MagicMock()
    abuse_mock.json.return_value = {"data": {"abuseConfidenceScore": 0, "totalReports": 0, "countryCode": "US"}}
    abuse_mock.raise_for_status = lambda: None

    geo_mock = MagicMock()
    geo_mock.json.return_value = [{"status": "success", "query": "1.1.1.1", "countryCode": "US", "lat": 1.0, "lon": 2.0}]
    geo_mock.raise_for_status = lambda: None

    vt_mock = MagicMock()
    vt_mock.status_code = 404

    # ip_lookup.py and vt_lookup.py both `import requests`, so they share the
    # SAME module object -- patching requests.get twice in one block just
    # makes the second patch silently clobber the first. Use one GET mock
    # that branches by URL instead.
    def fake_get(url, *args, **kwargs):
        if "abuseipdb" in url:
            return abuse_mock
        if "virustotal" in url:
            return vt_mock
        raise AssertionError(f"Unexpected GET to {url}")

    with patch("requests.get", side_effect=fake_get), \
         patch("requests.post", return_value=geo_mock), \
         patch("threat_intel.domain_lookup.whois.whois", side_effect=Exception("mocked: no real whois call")):

        result = enrich_iocs(fake_iocs)

    assert "1.1.1.1" in result["ip_reputation"]
    assert "example.com" in result["domain_info"]
    assert "http://example.com/x" in result["url_reputation"]
    assert len(result["geo"]) == 1 and result["geo"][0]["lat"] == 1.0
    print("PASS: enrich_iocs produces the full expected output shape")
    print(json.dumps(result, indent=2))


if __name__ == "__main__":
    test_ip_reputation_no_key()
    test_ip_reputation_with_mock()
    test_geolocation_with_mock()
    test_vt_rate_limit_handled_gracefully()
    test_vt_not_previously_scanned()
    test_enrich_iocs_end_to_end_with_mocks()
    print("\nAll Stage E tests passed (mocked -- run test_threat_intel_live.py for a real check).")
