"""Regression tests for B11 provider-status aggregation.

Run from backend/: python tests/test_provider_status.py
No external API calls or database are required.
"""
import os
import sys
from unittest.mock import patch

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from provider_status import build_provider_status


def build(threat_intel=None, final=None, live=True, skipped=False):
    return build_provider_status(
        threat_intel=threat_intel or {},
        iocs={},
        threat_intel_live=live,
        final_assessment=final or {"provider": "gemini", "model": "gemini-3.5-flash-lite"},
        gemini_skipped=skipped,
    )


def test_no_indicators_are_not_provider_failures():
    status = build()
    assert status["analysis_status"] == "completed"
    assert status["coverage_status"] == "complete"
    assert status["unavailable_count"] == 0
    assert status["providers"]["virustotal"]["status"] == "not_needed"


def test_provider_timeouts_and_rate_limits_are_not_reported_as_skips():
    ti = {
        "url_reputation": {"https://timeout.example/path": {"status": "timeout", "malicious": None, "error": "timeout"}},
        "ip_reputation": {"203.0.113.7": {"status": "rate_limited_internal", "malicious": None}},
    }
    with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "gemini-3.5-flash-lite"}):
        status = build(ti, {"provider": "offline_fallback", "fallback_reason": "request timeout"})
    assert status["providers"]["gemini"]["status"] == "timeout"
    assert status["providers"]["gemini"]["timed_out"] == 1
    assert status["providers"]["virustotal"]["status"] == "timeout"
    assert status["providers"]["virustotal"]["timed_out"] == 1
    assert status["providers"]["abuseipdb"]["status"] == "rate_limited"
    assert status["providers"]["abuseipdb"]["rate_limited"] == 1
    assert status["unavailable_count"] == 3
    assert status["summary"] == "Analysis completed; 3 providers unavailable."


def test_privacy_and_policy_skips_are_not_unavailable():
    ti = {
        "url_reputation": {"https://example.com/reset?token=secret": {"status": "skipped_privacy", "malicious": None}},
        "ip_reputation": {"10.0.0.1": {"status": "skipped_non_public", "malicious": None}},
        "domain_info": {"example.internal": {"status": "skipped_limit", "malicious": None}},
    }
    status = build(ti)
    assert status["providers"]["virustotal"]["status"] == "skipped_for_privacy"
    assert status["providers"]["abuseipdb"]["status"] == "skipped_by_policy"
    assert status["providers"]["whois"]["status"] == "skipped_by_policy"
    assert status["unavailable_count"] == 0
    assert status["coverage_status"] == "partial"
    assert status["unavailable_count"] == 0
    assert status["intentionally_skipped_count"] == 3
    assert "intentionally skipped" in status["summary"]


def test_mixed_success_and_failure_means_partial_coverage():
    ti = {
        "url_reputation": {
            "https://a.example/": {"status": "available", "malicious": False},
            "https://b.example/": {"status": "timeout", "malicious": None},
        }
    }
    status = build(ti)
    provider = status["providers"]["virustotal"]
    assert provider["status"] == "partial"
    assert provider["succeeded"] == 1 and provider["failed"] == 1
    assert status["coverage_status"] == "partial"
    assert status["partial_count"] >= 1


def test_virustotal_not_found_is_unknown_not_clean():
    ti = {"url_reputation": {"https://new.example/": {"status": "not_found", "malicious": None}}}
    status = build(ti)
    provider = status["providers"]["virustotal"]
    assert provider["status"] == "available"
    assert provider["succeeded"] == 1
    assert "unknown results are not clean verdicts" in provider["summary"]
    assert status["unavailable_count"] == 0


def test_gemini_triage_skip_is_explicit_and_not_failure():
    status = build(final={"provider": "xgboost_triage"}, skipped=True)
    assert status["providers"]["gemini"]["status"] == "skipped_by_triage"
    assert status["providers"]["gemini"]["skipped"] == 1
    assert status["unavailable_count"] == 0


def test_missing_gemini_key_is_not_configured():
    with patch.dict(os.environ, {}, clear=True):
        status = build(final={"provider": "offline_fallback", "fallback_reason": "GEMINI_API_KEY missing"})
    assert status["providers"]["gemini"]["status"] == "not_configured"
    assert status["unavailable_count"] == 1



def test_live_lookups_disabled_is_partial_coverage_not_provider_failure():
    ti = {
        "url_reputation": {"https://example.com/": {"status": "not_checked", "malicious": None}},
        "ip_reputation": {"203.0.113.8": {"status": "not_checked", "malicious": None}},
    }
    status = build(ti, live=False)
    assert status["providers"]["virustotal"]["status"] == "disabled"
    assert status["providers"]["abuseipdb"]["status"] == "disabled"
    assert status["unavailable_count"] == 0
    assert status["coverage_status"] == "partial"
    assert "disabled by configuration" in status["summary"]


def test_analysis_completed_two_providers_unavailable_summary():
    ti = {
        "url_reputation": {"https://a.example/": {"status": "timeout", "malicious": None}},
        "ip_reputation": {"203.0.113.9": {"status": "network_error", "malicious": None}},
    }
    with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key", "GEMINI_MODEL": "gemini-3.5-flash-lite"}):
        status = build(ti, {"provider": "gemini", "model": "gemini-3.5-flash-lite"})
    assert status["analysis_status"] == "completed"
    assert status["unavailable_count"] == 2
    assert status["summary"] == "Analysis completed; 2 providers unavailable."

def test_summary_does_not_leak_raw_provider_exceptions():
    ti = {"url_reputation": {"url": {"status": "network_error", "error": "request failed with TOKEN=private"}}}
    with patch.dict(os.environ, {"GEMINI_API_KEY": "test-key"}):
        status = build(ti, {"provider": "offline_fallback", "fallback_reason": "request failed with API key TOKEN=private"})
    serialized = str(status)
    assert "TOKEN=private" not in serialized
    assert "API key" not in serialized


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS:", name)
    print("All provider-status tests passed.")
