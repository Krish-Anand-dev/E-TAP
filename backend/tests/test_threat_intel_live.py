"""
REAL end-to-end test for Stage E -- actually calls AbuseIPDB, ip-api.com,
VirusTotal, and does a real WHOIS lookup. NOT run as part of automated
tests (no network access from CI/sandboxes) -- run this yourself once
you have real API keys in your .env, before the demo.

Usage (from backend/):
    python tests/test_threat_intel_live.py

Uses a small, safe set of well-known IOCs (Google's public DNS, a real
domain) so it won't burn much of your VirusTotal daily quota.
"""
import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from dotenv import load_dotenv
load_dotenv()

from threat_intel.threat_intel import enrich_iocs

# Small, known-safe set -- avoid burning VT quota on a big test run.
test_iocs = {
    "ips": ["8.8.8.8"],           # Google Public DNS -- always safe, always resolvable
    "domains": ["google.com"],     # long-registered, real WHOIS data
    "urls": ["http://example.com"],
    "hashes": [],                  # skip -- no safe well-known hash to test with
}

if __name__ == "__main__":
    missing = []
    if not os.getenv("ABUSEIPDB_API_KEY"):
        missing.append("ABUSEIPDB_API_KEY")
    if not os.getenv("VIRUSTOTAL_API_KEY"):
        missing.append("VIRUSTOTAL_API_KEY")

    if missing:
        print(f"Missing from .env: {', '.join(missing)} -- add them before running this.")
        print("(ip-api.com and WHOIS need no key, those parts will still run.)")

    print("Running real lookups against:", json.dumps(test_iocs, indent=2))
    result = enrich_iocs(test_iocs)
    print("\n=== RESULT ===")
    print(json.dumps(result, indent=2))

    print("\n=== SANITY CHECKS ===")
    ip_rep = result["ip_reputation"].get("8.8.8.8", {})
    if "error" in ip_rep:
        print(f"[FAIL] AbuseIPDB: {ip_rep['error']}")
    else:
        print(f"[OK] AbuseIPDB reachable, 8.8.8.8 abuse score: {ip_rep.get('abuse_confidence_score')}")

    geo = result["geo"]
    if geo and geo[0].get("lat") is not None:
        print(f"[OK] ip-api.com reachable, 8.8.8.8 geolocated to lat={geo[0]['lat']}, country={geo[0]['country']}")
    else:
        print("[FAIL] ip-api.com geolocation did not return coordinates")

    domain_info = result["domain_info"].get("google.com", {})
    if "error" in domain_info:
        print(f"[FAIL] WHOIS: {domain_info['error']}")
    else:
        print(f"[OK] WHOIS reachable, google.com age_days: {domain_info.get('age_days')}")

    url_rep = result["url_reputation"].get("http://example.com", {})
    if "error" in url_rep:
        print(f"[FAIL] VirusTotal: {url_rep['error']}")
    else:
        print(f"[OK] VirusTotal reachable, example.com status: {url_rep.get('status', url_rep.get('malicious'))}")
