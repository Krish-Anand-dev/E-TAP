"""Stage E: bounded, privacy-aware IOC enrichment with explicit statuses.

Each external lookup has a per-analysis cap. Provider failures, provider limits,
privacy skips and indicators that were not attempted are represented separately;
none is interpreted as a benign verdict.
"""
from __future__ import annotations

import os
from typing import Any

from .ip_lookup import check_ip_reputation, get_ip_geolocation, is_public_routable_ip
from .domain_lookup import get_domain_info
from .vt_lookup import check_url_reputation, check_hash_reputation


def _placeholder(value: str, reason: str, status: str = "not_checked") -> dict:
    return {"malicious": None, "status": status, "reason": reason, "indicator": value}


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
        "hash_reputation": {value: _placeholder(value, reason) for value in hashes},
        "geo": [],
        "geo_lookup": {ip: _placeholder(ip, reason) for ip in ips},
    }


def _max_lookups_per_provider() -> int:
    """Bound slow external work so one message cannot trigger unbounded calls."""
    try:
        configured = int(os.getenv("THREAT_INTEL_MAX_LOOKUPS_PER_PROVIDER", "2"))
    except (TypeError, ValueError):
        configured = 2
    return max(1, min(configured, 20))


def _limit_result(value: str, provider: str, limit: int) -> dict:
    # Do not echo a full URL or recipient-specific value into an error/report.
    return _placeholder(
        value,
        f"Per-analysis {provider} lookup limit ({limit}) reached; this indicator was not queried.",
        status="skipped_limit",
    )


def enrich_iocs(iocs: dict, live_lookup: bool | None = None) -> dict:
    """Run configured live lookups with explicit per-indicator status data.

    `THREAT_INTEL_MAX_LOOKUPS_PER_PROVIDER` defaults to 2. VirusTotal URL and
    hash lookups share one budget because they consume the same API quota.
    Private/reserved IPs are skipped by the provider helpers without consuming
    the public-lookup budget. Intentionally skipped IOCs remain unknown.
    """
    if live_lookup is False:
        return _offline_enrichment(
            iocs,
            "Live threat-intelligence lookups disabled. Set THREAT_INTEL_LIVE=1 "
            "and configure API keys to query external services.",
        )

    ips = list(dict.fromkeys(iocs.get("ips", []) or []))
    domains = list(dict.fromkeys(iocs.get("domains", []) or []))
    urls = list(dict.fromkeys(iocs.get("urls", []) or []))
    hashes = list(dict.fromkeys(iocs.get("hashes", []) or []))
    limit = _max_lookups_per_provider()

    # IP reputation: avoid external calls for private/reserved values and cap
    # the number of public addresses submitted to AbuseIPDB.
    ip_reputation: dict[str, dict] = {}
    public_ip_attempts = 0
    for ip in ips:
        if not is_public_routable_ip(ip):
            ip_reputation[ip] = check_ip_reputation(ip)  # emits skipped_non_public
        elif public_ip_attempts < limit:
            ip_reputation[ip] = check_ip_reputation(ip)
            public_ip_attempts += 1
        else:
            ip_reputation[ip] = _limit_result(ip, "AbuseIPDB", limit)

    # WHOIS calls are individually slow and vary by registry, so cap them too.
    domain_info: dict[str, dict] = {}
    for index, domain in enumerate(domains):
        if index < limit:
            domain_info[domain] = get_domain_info(domain)
        else:
            domain_info[domain] = _limit_result(domain, "WHOIS", limit)

    # URLs and hashes share a budget; only actual external lookups consume it.
    # check_url_reputation performs privacy screening and returns immediately
    # for a skipped URL, so a privacy skip does not use a VirusTotal request.
    from privacy import plan_url_lookup

    url_reputation: dict[str, dict] = {}
    vt_attempts = 0
    for url in urls:
        plan = plan_url_lookup(url)
        if plan["action"] == "skip":
            url_reputation[url] = check_url_reputation(url)
        elif vt_attempts < limit:
            url_reputation[url] = check_url_reputation(url)
            vt_attempts += 1
        else:
            url_reputation[url] = _limit_result(url, "VirusTotal", limit)

    hash_reputation: dict[str, dict] = {}
    for file_hash in hashes:
        if vt_attempts < limit:
            hash_reputation[file_hash] = check_hash_reputation(file_hash)
            vt_attempts += 1
        else:
            hash_reputation[file_hash] = _limit_result(file_hash, "VirusTotal", limit)

    # Geolocation uses a separate provider/budget. Batch only a few public IPs
    # so the analysis request remains bounded on free hosting.
    geo_lookup: dict[str, dict] = {}
    geo_candidates = []
    for ip in ips:
        if not is_public_routable_ip(ip):
            geo_lookup[ip] = {
                "status": "skipped_non_public",
                "reason": "Geolocation is skipped for private, reserved or non-public IPs.",
            }
        elif len(geo_candidates) < limit:
            geo_candidates.append(ip)
        else:
            geo_lookup[ip] = _limit_result(ip, "IP geolocation", limit)
    if geo_candidates:
        geo_lookup.update(get_ip_geolocation(geo_candidates))

    geo = [
        {
            "ip": ip,
            "lat": geo_lookup.get(ip, {}).get("lat"),
            "lon": geo_lookup.get(ip, {}).get("lon"),
            "country": geo_lookup.get(ip, {}).get("country"),
        }
        for ip in geo_candidates
        if geo_lookup.get(ip, {}).get("status") == "available"
    ]

    return {
        "lookup_mode": "live",
        "ip_reputation": ip_reputation,
        "domain_info": domain_info,
        "url_reputation": url_reputation,
        "hash_reputation": hash_reputation,
        "geo": geo,
        "geo_lookup": geo_lookup,
        "lookup_budget": {"per_provider_limit": limit, "virustotal_calls_attempted": vt_attempts},
    }
