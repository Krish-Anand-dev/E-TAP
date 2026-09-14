"""
URL and file-hash reputation via VirusTotal API v3.

VirusTotal's free tier is the tightest constraint in Stage E:
4 requests/min, 500/day. This module leans hard on TTLCache to avoid
burning quota on repeat lookups, and treats HTTP 429 (rate limited) as
a normal, expected outcome to report gracefully -- not a crash.
"""

from __future__ import annotations
import os
import base64
import time
from collections import deque
import requests

from .cache import TTLCache

_vt_cache = TTLCache(ttl_seconds=3600)

VT_BASE_URL = "https://www.virustotal.com/api/v3"


class VirusTotalRateLimiter:
    """
    Sliding window throttle for VirusTotal's strict public API limit:
    4 requests per minute, 500 requests per day.
    Prevents API lockout (HTTP 429) across concurrent demo calls.
    """
    def __init__(self, max_requests_per_minute: int = 4):
        self.max_rpm = max_requests_per_minute
        self.request_timestamps: deque[float] = deque()

    def can_request(self) -> bool:
        now = time.monotonic()
        while self.request_timestamps and now - self.request_timestamps[0] > 60.0:
            self.request_timestamps.popleft()
        return len(self.request_timestamps) < self.max_rpm

    def record_request(self) -> None:
        self.request_timestamps.append(time.monotonic())


# NOTE: _vt_limiter uses process-local in-memory state and will under-protect the real quota if the backend is ever run with multiple Uvicorn workers (use Redis or an external distributed lock for multi-worker setups).
_vt_limiter = VirusTotalRateLimiter(max_requests_per_minute=4)


def _get_vt_key() -> str | None:
    return os.getenv("VIRUSTOTAL_API_KEY")


def _vt_headers() -> dict:
    return {"x-apikey": _get_vt_key(), "Accept": "application/json"}


def _url_to_vt_id(url: str) -> str:
    """VirusTotal identifies URLs by the base64 of the URL, no padding."""
    return base64.urlsafe_b64encode(url.encode()).decode().strip("=")


def check_url_reputation(url: str) -> dict:
    cache_key = f"vt_url:{url}"
    cached = _vt_cache.get(cache_key)
    if cached is not None:
        return cached

    api_key = _get_vt_key()
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not set"}

    # Internal throttle: protect the 4 req/min free-tier quota
    if not _vt_limiter.can_request():
        return {
            "status": "rate_limited_internal",
            "error": "VirusTotal free-tier quota (4 req/min) active — remote query throttled to prevent API lockout",
            "malicious": None,
        }

    url_id = _url_to_vt_id(url)

    try:
        _vt_limiter.record_request()
        response = requests.get(
            f"{VT_BASE_URL}/urls/{url_id}",
            headers=_vt_headers(),
            timeout=10,
        )

        if response.status_code == 429:
            result = {"error": "VirusTotal rate limit hit (4/min, 500/day on free tier)"}
        elif response.status_code == 404:
            # URL not previously seen by VT -- not necessarily benign, just unknown.
            # Submitting it for a fresh scan costs another quota unit, so we
            # report "unknown" rather than auto-submitting.
            result = {"malicious": None, "status": "not previously scanned by VirusTotal"}
        else:
            response.raise_for_status()
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
            result = {
                "malicious": malicious_count > 0,
                "malicious_engine_count": malicious_count,
                "total_engines": sum(stats.values()),
                "stats": stats,
            }
    except requests.RequestException as e:
        result = {"error": f"VirusTotal request failed: {e}"}

    _vt_cache.set(cache_key, result)
    return result


def check_hash_reputation(file_hash: str) -> dict:
    cache_key = f"vt_hash:{file_hash}"
    cached = _vt_cache.get(cache_key)
    if cached is not None:
        return cached

    api_key = _get_vt_key()
    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not set"}

    # Internal throttle: protect the 4 req/min free-tier quota
    if not _vt_limiter.can_request():
        return {
            "status": "rate_limited_internal",
            "error": "VirusTotal free-tier quota (4 req/min) active — remote query throttled to prevent API lockout",
            "malicious": None,
        }

    try:
        _vt_limiter.record_request()
        response = requests.get(
            f"{VT_BASE_URL}/files/{file_hash}",
            headers=_vt_headers(),
            timeout=10,
        )

        if response.status_code == 429:
            result = {"error": "VirusTotal rate limit hit (4/min, 500/day on free tier)"}
        elif response.status_code == 404:
            result = {"malicious": None, "status": "not previously scanned by VirusTotal"}
        else:
            response.raise_for_status()
            stats = response.json()["data"]["attributes"]["last_analysis_stats"]
            malicious_count = stats.get("malicious", 0) + stats.get("suspicious", 0)
            result = {
                "malicious": malicious_count > 0,
                "malicious_engine_count": malicious_count,
                "total_engines": sum(stats.values()),
                "stats": stats,
            }
    except requests.RequestException as e:
        result = {"error": f"VirusTotal request failed: {e}"}

    _vt_cache.set(cache_key, result)
    return result
