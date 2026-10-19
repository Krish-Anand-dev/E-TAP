"""
hop_geo.py -- geolocate the Received-chain hops and re-judge the origin using
the network owner (ip-api org/isp) that only the geo lookup can tell us.

Rules the UI relies on:
  * coordinates of a provider relay are the provider's data centre, NOT the sender
  * ip-api `proxy` flag (Tor/VPN/open proxy) marks a hop as an anonymizer
  * the verdict lives in header_analysis["origin_analysis"]
"""
from __future__ import annotations

from forensics.received_chain import provider_from_org, resolve_origin, _classify
from .ip_lookup import get_ip_geolocation, is_public_routable_ip

MAX_HOP_LOOKUPS = 12


def attach_hop_geo(header_analysis: dict, threat_intel: dict | None, live: bool) -> dict:
    hops = header_analysis.get("hops") or []
    if not hops:
        return header_analysis

    known = dict((threat_intel or {}).get("geo_lookup") or {})
    ips = []
    for h in hops:
        ip = h.get("ip")
        if ip and h.get("ip_is_public") and is_public_routable_ip(ip) and ip not in ips:
            ips.append(ip)
    ips = ips[:MAX_HOP_LOOKUPS]

    missing = [ip for ip in ips if known.get(ip, {}).get("status") != "available"]
    if live and missing:
        known.update(get_ip_geolocation(missing))
    elif not live:
        for ip in missing:
            known.setdefault(ip, {"status": "disabled", "reason": "Live geolocation is disabled."})

    # Hop lookups are real provider activity too. Preserve failures as well as
    # answers so coverage cannot say "not needed" after a hop lookup ran.
    if threat_intel is not None:
        threat_intel["geo_lookup"] = known
    geo = {ip: known[ip] for ip in ips if known.get(ip, {}).get("status") == "available"}

    for h in hops:
        g = geo.get(h.get("ip"))
        if not g:
            h["geo"] = None
            continue
        h["geo"] = {k: g.get(k) for k in ("lat", "lon", "country", "isp", "org", "hosting", "proxy")}
        if not h.get("provider"):
            h["provider"] = provider_from_org(g.get("org"), g.get("isp"))
        h["anonymizer"] = bool(g.get("proxy"))
        h["kind"] = _classify(h)

    origin = resolve_origin(hops, [(c["header"], c["ip"]) for c in
                                   (header_analysis.get("origin_analysis") or {}).get("client_header_ips", [])])
    origin["geo_resolved"] = bool(geo)
    header_analysis["origin_analysis"] = origin
    return header_analysis
