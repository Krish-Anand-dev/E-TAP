"""
Stage E -- Threat Intelligence Lookup
Owner: Bhavit

Input: Stage D's IOC output -- {"ips": [...], "domains": [...], "urls": [...], "hashes": [...]}

Output:
{
    "ip_reputation": {"185.x.x.x": {"malicious": true, "reports": 45, "country": "RU"}},
    "domain_info": {"fake-bank.com": {"age_days": 3, "registrar": "..."}},
    "url_reputation": {"http://fake-bank.com/login": {"malicious": true}},
    "geo": [{"ip": "185.x.x.x", "lat": 55.7, "lon": 37.6, "country": "RU"}]
}

Note on hashes: the original spec's output shape doesn't have a
dedicated top-level key for hash results (only ip/domain/url/geo) --
they're folded into "hash_reputation" here as a reasonable extension,
matching the same {hash: {...}} shape as ip_reputation/url_reputation.
Flag this to the team if Stage F/G expects a different key name.
"""

from __future__ import annotations

import os

from .ip_lookup import check_ip_reputation, get_ip_geolocation
from .domain_lookup import get_domain_info
from .vt_lookup import check_url_reputation, check_hash_reputation


def _placeholder(value: str, reason: str) -> dict:
    return {
        "malicious": None,
        "status": "not_checked",
        "reason": reason,
        "indicator": value,
    }


def _offline_enrichment(iocs: dict, reason: str) -> dict:
    ips = iocs.get("ips", []) or []
    domains = iocs.get("domains", []) or []
    urls = iocs.get("urls", []) or []
    hashes = iocs.get("hashes", []) or []

    return {
        "lookup_mode": "offline_placeholder",
        "ip_reputation": {ip: _placeholder(ip, reason) for ip in ips},
        "domain_info": {domain: _placeholder(domain, reason) for domain in domains},
        "url_reputation": {url: _placeholder(url, reason) for url in urls},
        "hash_reputation": {h: _placeholder(h, reason) for h in hashes},
        "geo": [],
    }


def enrich_iocs(iocs: dict, live_lookup: bool | None = None) -> dict:
    """
    Main Stage E entry point. Call this with Stage D's output dict.

    By default this preserves the original live lookup behavior. Pipeline
    orchestration can pass live_lookup=False so local demos/tests do not
    depend on API keys, WHOIS, or outbound network access.
    """
    if live_lookup is False:
        return _offline_enrichment(
            iocs,
            "Live threat-intelligence lookups disabled. Set THREAT_INTEL_LIVE=1 "
            "and configure API keys to query external services.",
        )

    ips = iocs.get("ips", []) or []
    domains = iocs.get("domains", []) or []
    urls = iocs.get("urls", []) or []
    hashes = iocs.get("hashes", []) or []

    ip_reputation = {ip: check_ip_reputation(ip) for ip in ips}
    domain_info = {domain: get_domain_info(domain) for domain in domains}
    url_reputation = {url: check_url_reputation(url) for url in urls}
    hash_reputation = {h: check_hash_reputation(h) for h in hashes}

    geo_by_ip = get_ip_geolocation(ips)
    geo = [
        {
            "ip": ip,
            "lat": geo_by_ip.get(ip, {}).get("lat"),
            "lon": geo_by_ip.get(ip, {}).get("lon"),
            "country": geo_by_ip.get(ip, {}).get("country"),
        }
        for ip in ips
        if "error" not in geo_by_ip.get(ip, {"error": True})
    ]

    return {
        "lookup_mode": "live",
        "ip_reputation": ip_reputation,
        "domain_info": domain_info,
        "url_reputation": url_reputation,
        "hash_reputation": hash_reputation,
        "geo": geo,
    }
