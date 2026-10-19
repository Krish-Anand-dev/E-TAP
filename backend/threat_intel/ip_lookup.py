"""
IP lookups for Stage E.

- Reputation: AbuseIPDB /check endpoint (needs ABUSEIPDB_API_KEY)
- Geolocation: ip-api.com /batch endpoint (no key needed at all)

Both wrapped with the shared TTLCache to avoid re-querying the same IP
across multiple emails in one test run.
"""

from __future__ import annotations
import ipaddress
import os
import requests

from .cache import TTLCache

_ip_cache = TTLCache(ttl_seconds=3600)

ABUSEIPDB_CHECK_URL = "https://api.abuseipdb.com/api/v2/check"
IPAPI_BATCH_URL = "http://ip-api.com/batch"

# ip-api's batch endpoint accepts up to 100 IPs per call and is capped at
# 15 requests/min -- batching everything from one email in a single call
# is both faster and keeps well under that limit for normal use.
IPAPI_MAX_BATCH = 100


def is_public_routable_ip(ip: str) -> bool:
    """
    SSRF & Network Leakage Guard: Check if IP is a publicly routable global address.
    Rejects private (RFC 1918 10.x/172.16.x/192.168.x), loopback (127.x),
    link-local (169.254.x cloud metadata), multicast, and reserved ranges.
    """
    try:
        addr = ipaddress.ip_address(ip.strip())
        return not (
            addr.is_private
            or addr.is_loopback
            or addr.is_link_local
            or addr.is_reserved
            or addr.is_multicast
            or addr.is_unspecified
        )
    except ValueError:
        return False


def _get_abuseipdb_key() -> str | None:
    return os.getenv("ABUSEIPDB_API_KEY")


def check_ip_reputation(ip: str) -> dict:
    """
    Query AbuseIPDB for a single IP's abuse reputation.
    Returns a dict shaped for Stage E's "ip_reputation" output, or an
    error marker if the API key is missing / the request fails -- never
    raises, since one bad IOC shouldn't take down the whole pipeline run.
    """
    # SSRF Guard: reject private, loopback, or cloud metadata IPs before outbound calls
    if not is_public_routable_ip(ip):
        return {
            "status": "skipped_non_public",
            "reason": "External reputation lookup was skipped for a private, reserved or non-public IP.",
            "malicious": None,
        }

    cache_key = f"abuseipdb:{ip}"
    cached = _ip_cache.get(cache_key)
    if cached is not None:
        return dict(cached, lookup_source="cache")

    api_key = _get_abuseipdb_key()
    if not api_key:
        result = {"status": "not_configured", "error": "ABUSEIPDB_API_KEY not set", "malicious": None}
        return result  # not cached -- a key might get added later in the same run

    try:
        response = requests.get(
            ABUSEIPDB_CHECK_URL,
            params={"ipAddress": ip, "maxAgeInDays": 90},
            headers={"Key": api_key, "Accept": "application/json"},
            timeout=(2, 4)
        )
        response.raise_for_status()
        data = response.json().get("data", {})

        result = {
            "status": "available",
            "lookup_source": "remote",
            "malicious": data.get("abuseConfidenceScore", 0) >= 50,
            "abuse_confidence_score": data.get("abuseConfidenceScore"),
            "reports": data.get("totalReports"),
            "country": data.get("countryCode"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "is_tor": data.get("isTor"),
        }
    except requests.Timeout:
        return {"malicious": None, "status": "timeout", "lookup_source": "remote", "error": "AbuseIPDB request timed out"}
    except requests.RequestException as e:
        # Do not include request URLs, headers or credential-bearing details.
        return {"malicious": None, "status": "network_error", "lookup_source": "remote", "error": f"AbuseIPDB request failed ({type(e).__name__})"}
    except (ValueError, TypeError, KeyError):
        return {"malicious": None, "status": "invalid_response", "lookup_source": "remote", "error": "AbuseIPDB returned an invalid response"}

    _ip_cache.set(cache_key, result)
    return result


def get_ip_geolocation(ips: list[str]) -> dict[str, dict]:
    """
    Batch-geolocate a list of IPs via ip-api.com.
    Returns {ip: {lat, lon, country, ...}}. No API key required.

    Splits into chunks of IPAPI_MAX_BATCH if given more than 100 IPs
    (unlikely for a single email, but safe regardless).
    """
    if not ips:
        return {}

    uncached_ips = []
    results: dict[str, dict] = {}

    for ip in ips:
        # SSRF Guard: skip private/reserved IPs from public geolocation
        if not is_public_routable_ip(ip):
            results[ip] = {
                "status": "skipped_non_public",
                "reason": "Geolocation is skipped for private or non-public IPs.",
            }
            continue

        cached = _ip_cache.get(f"geo:{ip}")
        if cached is not None:
            results[ip] = dict(cached, lookup_source="cache")
        else:
            uncached_ips.append(ip)

    for i in range(0, len(uncached_ips), IPAPI_MAX_BATCH):
        chunk = uncached_ips[i:i + IPAPI_MAX_BATCH]
        try:
            response = requests.post(
                IPAPI_BATCH_URL,
                json=chunk,
                params={"fields": "status,message,query,country,countryCode,lat,lon,isp,org,as,hosting,proxy"},
                timeout=(2, 4)
            )
            response.raise_for_status()
            batch_result = response.json()
        except requests.Timeout:
            for ip in chunk:
                results[ip] = {"status": "timeout", "lookup_source": "remote", "error": "IP geolocation request timed out"}
            continue
        except requests.RequestException as e:
            for ip in chunk:
                results[ip] = {"status": "network_error", "lookup_source": "remote", "error": f"IP geolocation request failed ({type(e).__name__})"}
            continue
        except (ValueError, TypeError):
            for ip in chunk:
                results[ip] = {"status": "invalid_response", "lookup_source": "remote", "error": "IP geolocation returned an invalid response"}
            continue

        for entry in batch_result:
            ip = entry.get("query")
            if entry.get("status") != "success":
                geo = {"status": "provider_error", "lookup_source": "remote", "error": "IP geolocation provider did not return a result"}
            else:
                geo = {
                    "status": "available",
                    "lookup_source": "remote",
                    "lat": entry.get("lat"),
                    "lon": entry.get("lon"),
                    "country": entry.get("countryCode"),
                    "isp": entry.get("isp"),
                    "org": entry.get("org"),
                    "hosting": entry.get("hosting"),
                    "proxy": entry.get("proxy"),
                }
            results[ip] = geo
            if "error" not in geo:  # only cache successes
                _ip_cache.set(f"geo:{ip}", geo)

    return results
