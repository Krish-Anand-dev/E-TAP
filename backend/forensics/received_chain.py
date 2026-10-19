"""
received_chain.py

Parses the Received: header chain into structured HOPS and works out the
sender's true origin -- or, just as importantly, says honestly when the
origin is hidden behind a mail provider.

Why the old logic kept pointing at Google
-----------------------------------------
Old behaviour: grab every IP in every Received line and return the oldest
public one. For mail sent through Gmail / Outlook / SES etc. the oldest
public IP in the chain IS the provider's outbound relay (e.g. a
mail-xxx.google.com box). The sender's real IP is not in the headers at all:
Gmail webmail strips it, Outlook.com strips it. So every Gmail-sent email
"originated" in the same Google data centre.

Fixes here
----------
1. Only the `from` clause of each Received line is read for the connecting IP
   (the old regex also picked up IPs from the `by` / `for` clauses).
2. Compressed IPv6 (2607:f8b0::b41) is parsed; the old regex only matched
   fully expanded addresses.
3. Hops are classified: provider_relay (Google, Microsoft, SES, ...),
   private, relay, anonymizer (Tor/VPN/proxy; set later from geo data).
4. Client-IP headers (X-Originating-IP, X-Sender-IP, ...) are consulted.
5. The result carries an explicit origin verdict + explanation, so the UI
   can say "origin hidden by Google" instead of pinning a Google relay as
   if it were the attacker.

`find_originating_ip` is unchanged in contract: it returns the first public
IP that touched the chain (the connecting relay). SPF evaluation needs
exactly that IP, so it must not change. The *display* origin is
`resolve_origin(...)["true_origin_ip"]`.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import timezone
from email.utils import parsedate_to_datetime
from typing import Dict, List, Optional, Tuple

# --------------------------------------------------------------------------
# Provider knowledge
# --------------------------------------------------------------------------

# hostname suffix -> provider label
_PROVIDER_HOST_SUFFIXES: List[Tuple[str, str]] = [
    (".google.com", "Google"), (".googlemail.com", "Google"),
    (".gmail.com", "Google"), (".1e100.net", "Google"),
    (".outlook.com", "Microsoft"), (".protection.outlook.com", "Microsoft"),
    (".hotmail.com", "Microsoft"), (".office365.com", "Microsoft"),
    (".microsoft.com", "Microsoft"), (".live.com", "Microsoft"),
    (".amazonses.com", "Amazon SES"),
    (".yahoo.com", "Yahoo"), (".yahoodns.net", "Yahoo"),
    (".sendgrid.net", "SendGrid"), (".mailgun.org", "Mailgun"),
    (".mandrillapp.com", "Mailchimp/Mandrill"), (".mcsv.net", "Mailchimp"),
    (".protonmail.ch", "Proton"), (".zoho.com", "Zoho"),
    (".icloud.com", "Apple"), (".me.com", "Apple"),
]

# Substrings of ip-api `org` / `isp` / `as` -> provider label (used after geo lookup)
_PROVIDER_ORG_KEYWORDS: List[Tuple[str, str]] = [
    ("google", "Google"), ("microsoft", "Microsoft"),
    ("amazon", "Amazon SES"), ("yahoo", "Yahoo"),
    ("sendgrid", "SendGrid"), ("mailgun", "Mailgun"),
    ("mailchimp", "Mailchimp"), ("proton", "Proton"),
    ("zoho", "Zoho"), ("apple inc", "Apple"),
]

# Headers some mail systems use to record the submitting client's IP.
CLIENT_IP_HEADERS = ("X-Originating-IP", "X-Sender-IP", "X-Client-IP", "X-Real-IP")

# --------------------------------------------------------------------------
# IP helpers
# --------------------------------------------------------------------------

_BRACKET_RE = re.compile(r"\[([^\[\]]+)\]")
_PAREN_RE = re.compile(r"\(([^()]*)\)")
_IPV4_ANY = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")
# kept for backwards compatibility with older callers
IPV4_PATTERN = _IPV4_ANY
IPV6_PATTERN = re.compile(r"\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{0,4}){2,7})\b")


def _clean_ip(token: str) -> Optional[str]:
    token = token.strip().strip("[]").strip()
    if token.lower().startswith("ipv6:"):
        token = token[5:]
    token = token.split("%")[0]
    try:
        return str(ipaddress.ip_address(token))
    except ValueError:
        return None


def extract_ips_from_text(text: str) -> List[str]:
    """Every valid IPv4/IPv6 address in `text` (compressed IPv6 included)."""
    found: List[str] = []
    for m in _IPV4_ANY.finditer(text or ""):
        ip = _clean_ip(m.group(1))
        if ip:
            found.append(ip)
    for m in IPV6_PATTERN.finditer(text or ""):
        ip = _clean_ip(m.group(1))
        if ip and ":" in ip:
            found.append(ip)
    seen, out = set(), []
    for ip in found:
        if ip not in seen:
            seen.add(ip)
            out.append(ip)
    return out


def is_public_ip(ip_str: str) -> bool:
    """True for a real public internet address (not private/loopback/etc.)."""
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (
            ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
            or ip_obj.is_multicast or ip_obj.is_reserved or ip_obj.is_unspecified
        )
    except ValueError:
        return False


def provider_from_host(host: Optional[str]) -> Optional[str]:
    if not host:
        return None
    h = host.lower().rstrip(".")
    for suffix, name in _PROVIDER_HOST_SUFFIXES:
        if h.endswith(suffix) or h == suffix.lstrip("."):
            return name
    return None


def provider_from_org(*org_strings: Optional[str]) -> Optional[str]:
    blob = " ".join(s for s in org_strings if s).lower()
    for kw, name in _PROVIDER_ORG_KEYWORDS:
        if kw in blob:
            return name
    return None


# --------------------------------------------------------------------------
# Hop parsing
# --------------------------------------------------------------------------

_FROM_RE = re.compile(r"^\s*from\s+(?P<frm>.*?)(?=\s+by\s|\s*$)", re.I | re.S)
_BY_RE = re.compile(r"\bby\s+(?P<by>\S+)", re.I)
_WITH_RE = re.compile(r"\bwith\s+(?P<with>[A-Za-z0-9\-]+)", re.I)
_HOST_RE = re.compile(r"^\s*(\S+)")


def _unfold(raw: str) -> str:
    return re.sub(r"\s+", " ", raw or "").strip()


def _parse_timestamp(raw: str) -> Optional[str]:
    if ";" not in raw:
        return None
    try:
        dt = parsedate_to_datetime(raw.rsplit(";", 1)[1].strip())
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).isoformat()
    except (TypeError, ValueError, IndexError):
        return None


def _connecting_ip(from_clause: str) -> Optional[str]:
    """IP of the machine that connected, taken from the `from` clause only.

    Preference: a bracketed literal [1.2.3.4] (what the receiving server
    actually saw), then a parenthesised one, then a bare one.
    """
    for rx in (_BRACKET_RE, _PAREN_RE):
        candidates = []
        for m in rx.finditer(from_clause):
            inner = m.group(1)
            ip = _clean_ip(inner)
            if ip:
                candidates.append(ip)
            else:  # "(host.example.com. [1.2.3.4])" style
                candidates.extend(extract_ips_from_text(inner))
        pub = [c for c in candidates if is_public_ip(c)]
        if pub:
            return pub[-1]
        if candidates:
            return candidates[-1]
    ips = extract_ips_from_text(from_clause)
    pub = [c for c in ips if is_public_ip(c)]
    return (pub or ips or [None])[0]


def parse_hop(raw: str) -> Dict:
    text = _unfold(raw)
    m = _FROM_RE.match(text)
    from_clause = m.group("frm") if m else ""
    hm = _HOST_RE.match(from_clause)
    helo = hm.group(1).strip("[]()") if hm else None
    ip = _connecting_ip(from_clause)

    # rDNS hostname is usually "(rdns.example.com. [ip])"; fall back to HELO
    rdns = None
    for pm in _PAREN_RE.finditer(from_clause):
        cand = pm.group(1).split("[")[0].strip().rstrip(".").split(" ")[0]
        if cand and "." in cand and not _clean_ip(cand):
            rdns = cand
            break
    host = rdns or (helo if helo and not _clean_ip(helo) else None)

    by_m = _BY_RE.search(text)
    with_m = _WITH_RE.search(text)
    provider = provider_from_host(rdns) or provider_from_host(helo)
    return {
        "raw": raw,
        "from_helo": helo,
        "from_host": host,
        "ip": ip,
        "ip_is_public": bool(ip and is_public_ip(ip)),
        "by_host": by_m.group("by").strip(";") if by_m else None,
        "protocol": with_m.group("with") if with_m else None,
        "timestamp": _parse_timestamp(raw),
        "provider": provider,
        "anonymizer": False,
        "kind": None,   # filled by _classify
    }


def _classify(hop: Dict) -> str:
    if not hop["ip"] or not hop["ip_is_public"]:
        return "private"
    if hop.get("anonymizer"):
        return "anonymizer"
    if hop.get("provider"):
        return "provider_relay"
    return "relay"


def parse_hops(all_headers: dict) -> List[Dict]:
    """Structured hops, OLDEST FIRST (index 0 = closest to the sender)."""
    raw_list = list((all_headers or {}).get("Received", []) or [])
    hops = [parse_hop(r) for r in reversed(raw_list)]
    prev_ts = None
    from datetime import datetime
    for i, hop in enumerate(hops):
        hop["index"] = i
        hop["kind"] = _classify(hop)
        delay = None
        if hop["timestamp"] and prev_ts:
            delay = int((datetime.fromisoformat(hop["timestamp"]) - prev_ts).total_seconds())
        hop["delay_s"] = delay
        hop["out_of_order"] = bool(delay is not None and delay < -300)
        if hop["timestamp"]:
            prev_ts = datetime.fromisoformat(hop["timestamp"])
    return hops


# --------------------------------------------------------------------------
# Origin resolution
# --------------------------------------------------------------------------

def _header_client_ips(all_headers: dict) -> List[Tuple[str, str]]:
    out = []
    lowered = {k.lower(): v for k, v in (all_headers or {}).items()}
    for name in CLIENT_IP_HEADERS:
        val = lowered.get(name.lower())
        if not val:
            continue
        vals = val if isinstance(val, list) else [val]
        for v in vals:
            for ip in extract_ips_from_text(str(v)):
                if is_public_ip(ip):
                    out.append((name, ip))
    return out


def resolve_origin(hops: List[Dict], client_header_ips: Optional[List[Tuple[str, str]]] = None) -> Dict:
    """
    Decide what to show as 'where the mail came from'.

    origin_kind:
      sender_client        a non-provider public IP is the first hop / is in a
                           client-IP header -> plausibly the sender's own host
      anonymizer_exit      first public hop is a Tor/VPN/proxy exit; real IP
                           is not recoverable from the message
      provider_relay_only  oldest public hop is Gmail/Outlook/SES/etc.; the
                           sender's real IP is NOT in the headers
      unknown_relay        public IP, provider unknown -> shown, low confidence
      none                 no public IP anywhere in the chain
    """
    client_header_ips = client_header_ips or []
    first_public = next((h for h in hops if h["ip_is_public"]), None)
    result = {
        "true_origin_ip": None,
        "origin_source": None,
        "origin_kind": "none",
        "origin_provider": None,
        "first_public_hop_ip": first_public["ip"] if first_public else None,
        "first_public_hop_index": first_public["index"] if first_public else None,
        "confidence": "none",
        "explanation": "No public IP address appears in the Received chain.",
        "client_header_ips": [{"header": h, "ip": ip} for h, ip in client_header_ips],
    }

    # 1) client-IP header, unless it is the same IP as a known provider relay
    provider_ips = {h["ip"] for h in hops if h["kind"] == "provider_relay"}
    for header, ip in client_header_ips:
        if ip not in provider_ips:
            result.update(
                true_origin_ip=ip, origin_source=f"header:{header}", origin_kind="sender_client",
                confidence="medium",
                explanation=(f"{header} names {ip} as the submitting client. This header is written by the "
                             "sender's own mail system, so treat it as a strong lead, not proof."),
            )
            return result

    if not first_public:
        return result

    # 2) walk oldest -> newest and judge the first public hop
    if first_public["kind"] == "anonymizer":
        result.update(
            true_origin_ip=first_public["ip"], origin_source="received_chain", origin_kind="anonymizer_exit",
            confidence="low",
            explanation=(f"The first public hop {first_public['ip']} is a Tor/VPN/proxy exit. "
                         "That is as far back as the message can be traced; the real sender IP is not recoverable."),
        )
    elif first_public["kind"] == "provider_relay":
        prov = first_public["provider"]
        result.update(
            origin_kind="provider_relay_only", origin_provider=prov, confidence="high",
            explanation=(f"This message left through {prov}'s mail servers ({first_public['ip']}). "
                         f"{prov} does not put the sender's own IP in the headers, so the true origin "
                         "cannot be determined from this email. The relay is shown for the path only."),
        )
    else:
        known = first_public["index"] == 0 or all(h["kind"] == "private" for h in hops[: first_public["index"]])
        result.update(
            true_origin_ip=first_public["ip"], origin_source="received_chain",
            origin_kind="sender_client" if known else "unknown_relay",
            confidence="high" if known else "low",
            explanation=(f"{first_public['ip']} is the first public host to hand the message on, "
                         "and it is not a known mail provider."),
        )
    return result


def build_origin_analysis(all_headers: dict) -> Dict:
    hops = parse_hops(all_headers)
    origin = resolve_origin(hops, _header_client_ips(all_headers))
    return {"hops": hops, "origin": origin}


# --------------------------------------------------------------------------
# Backwards-compatible API
# --------------------------------------------------------------------------

def parse_received_chain(all_headers: dict) -> List[Dict]:
    """Legacy shape: newest hop first, with `ips_found` / `public_ips`."""
    out = []
    for raw in (all_headers or {}).get("Received", []) or []:
        ips = extract_ips_from_text(raw)
        out.append({"raw": raw, "ips_found": ips, "public_ips": [i for i in ips if is_public_ip(i)]})
    return out


def find_originating_ip(all_headers: dict) -> Optional[str]:
    """First public IP that touched the chain (the connecting relay).
    Kept stable because SPF must be evaluated against this exact address."""
    hop = next((h for h in parse_hops(all_headers) if h["ip_is_public"]), None)
    return hop["ip"] if hop else None


def get_received_chain_summary(all_headers: dict) -> List[str]:
    """Raw Received strings, oldest first."""
    return list(reversed((all_headers or {}).get("Received", []) or []))
