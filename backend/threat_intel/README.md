# Stage E — Threat Intelligence Lookup (Owner: Bhavit)

threat intel requirements additions: requests>=2.31.0 and python-whois>=0.9.4

## Input

Stage D's IOC output: `{"ips": [...], "domains": [...], "urls": [...], "hashes": [...]}`

## Output

```json
{
  "lookup_mode": "live",
  "ip_reputation": {
    "185.x.x.x": {
      "malicious": true,
      "abuse_confidence_score": 100,
      "reports": 45,
      "country": "RU",
      "isp": "...",
      "domain": "...",
      "is_tor": false
    }
  },
  "domain_info": {
    "fake-bank.com": {
      "age_days": 3,
      "registrar": "...",
      "creation_date": "..."
    }
  },
  "url_reputation": {
    "http://fake-bank.com/login": {
      "malicious": true,
      "malicious_engine_count": 12,
      "total_engines": 70
    }
  },
  "hash_reputation": {
    "abc123...": {
      "malicious": true,
      "malicious_engine_count": 40,
      "total_engines": 70
    }
  },
  "geo": [{ "ip": "185.x.x.x", "lat": 55.7, "lon": 37.6, "country": "RU" }]
}
```

Note: `hash_reputation` isn't in the original Stage E spec's output shape
(only ip/domain/url/geo) — added as a reasonable extension since Stage D
provides hashes and something needs to look them up. Flag to whoever
builds Stage F/G in case they expect a different key name.

## Sources

| IOC                   | Source                                         | API key needed?            |
| --------------------- | ---------------------------------------------- | -------------------------- |
| IP reputation         | AbuseIPDB                                      | Yes — `ABUSEIPDB_API_KEY`  |
| IP geolocation        | ip-api.com                                     | **No**                     |
| Domain age/registrar  | WHOIS (via `python-whois` library, not an API) | No                         |
| URL / hash reputation | VirusTotal                                     | Yes — `VIRUSTOTAL_API_KEY` |

## Setup

```
pip install requests python-whois
```

Add to `.env`:

```
THREAT_INTEL_LIVE=1
ABUSEIPDB_API_KEY=your_key_here
VIRUSTOTAL_API_KEY=your_key_here
```

`THREAT_INTEL_LIVE=0` keeps the full pipeline in offline placeholder mode
so local demos do not depend on API keys, WHOIS, or outbound network.
ip-api.com and WHOIS need no keys, but they still require network access,
so the pipeline disables them unless live mode is explicitly enabled.

## Rate limits to know about

- **VirusTotal free tier is the tight one**: 4 requests/min, 500/day.
  This module caches every VT lookup for 1 hour in-memory to avoid
  burning quota on repeat IOCs across test runs — but the cache resets
  when the process restarts, so don't loop the live test script.
- AbuseIPDB free: 1,000 checks/day — comfortable.
- ip-api.com: 45 requests/min via its batch endpoint, no daily cap
  mentioned, no key needed — this module batches all IPs from one
  email into a single call rather than one call per IP.

## Usage

```python
from threat_intel.threat_intel import enrich_iocs

enrichment = enrich_iocs(stage_d_output)  # live/default Stage E behavior
offline = enrich_iocs(stage_d_output, live_lookup=False)
```

## Failure handling

Every lookup function degrades gracefully instead of raising:

- Missing API key → `{"error": "...API_KEY not set"}`
- Rate limited (VT 429) → `{"error": "...rate limit hit..."}`
- IOC not found/unknown (VT 404) → `{"malicious": None, "status": "not previously scanned..."}`
  — deliberately distinct from `malicious: False`, since "unknown" and
  "confirmed clean" are different things.
- Network/WHOIS failure → `{"error": "..."}`

This means a single bad or rate-limited IOC never crashes the whole
Stage E call — the rest of the IOCs in the batch still get processed.

## Files

- `cache.py` — simple TTL cache shared by all lookup modules
- `ip_lookup.py` — AbuseIPDB reputation + ip-api.com geolocation
- `domain_lookup.py` — WHOIS domain age/registrar
- `vt_lookup.py` — VirusTotal URL/hash reputation
- `threat_intel.py` — `enrich_iocs()`, the Stage E entry point
- `../tests/test_threat_intel.py` — mocked tests (no real network calls,
  matches documented API response shapes exactly)
- `../tests/test_threat_intel_live.py` — **run this yourself** with real
  API keys before the demo; sandbox environments used to build this
  module couldn't reach these APIs to test live

## Known limitation

This was built and tested entirely against mocked HTTP responses shaped
to match each API's official documentation — not verified against a
real live call yet. Run `test_threat_intel_live.py` once you have real
keys in `.env` to confirm actual behavior before relying on this for
the demo.
