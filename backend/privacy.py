"""
B10: decide what may leave E-TAP in an external lookup, and describe the data
flows of an analysis.

Why: VirusTotal documents that URLs queried through its API can enter a
dataset shared with its community, and says not to submit sensitive
indicators. A phishing link usually carries exactly the sort of value that must
not leak: the recipient's address, a reset or session token, a one-time code.
Hostnames inside a private network are also something the user would not want
published.

`plan_url_lookup(url)` returns one of three actions:

    full     the URL as-is is safe to look up (no query, fragment or secret-looking path)
    trimmed  look up scheme://host/path only; the query string and fragment are dropped
    skip     do not send anything; the link looks personal, secret or internal

The check is heuristic and deliberately conservative. A skipped lookup is shown
to the user as "not looked up for privacy", never as "clean".
"""
from __future__ import annotations

import ipaddress
import math
import re
from typing import Any, Optional
from urllib.parse import parse_qsl, unquote, urlsplit

# Query keys that name a secret or a person. Matched against whole tokens of
# the key (split on _ - . and camelCase), so "sid" matches but "inside" does not.
_SENSITIVE_KEY_TOKENS = frozenset({
    "token", "tok", "key", "apikey", "secret", "sig", "signature", "session", "sessionid",
    "sid", "auth", "authorization", "code", "otp", "pass", "password", "pwd", "reset",
    "jwt", "bearer", "ticket", "nonce", "state", "email", "mail", "user", "username",
    "uid", "userid", "recipient", "rcpt", "to", "login", "account", "acct", "hash",
    "cred", "credential", "csrf", "mfa",
})
_EMAIL_RE = re.compile(r"[A-Za-z0-9._%+\-]+(?:@|%40)[A-Za-z0-9.\-]+\.[A-Za-z]{2,}", re.I)
_B64ISH_RE = re.compile(r"^[A-Za-z0-9+/_\-=]{20,}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]{16,}$")
_UUID_RE = re.compile(r"^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$", re.I)
_PRIVATE_SUFFIXES = (".local", ".internal", ".lan", ".corp", ".home", ".intranet", ".localdomain")


def _key_tokens(key: str) -> set[str]:
    spaced = re.sub(r"([a-z0-9])([A-Z])", r"\1 \2", key)
    return {t for t in re.split(r"[^A-Za-z0-9]+", spaced.lower()) if t}


def _entropy(text: str) -> float:
    if not text:
        return 0.0
    counts: dict[str, int] = {}
    for ch in text:
        counts[ch] = counts.get(ch, 0) + 1
    n = len(text)
    return -sum((c / n) * math.log2(c / n) for c in counts.values())


def _looks_like_secret_value(value: str) -> bool:
    v = unquote(value or "")
    if _EMAIL_RE.search(v):
        return True
    if _HEX_RE.match(v) or _UUID_RE.match(v):
        return True
    if _B64ISH_RE.match(v) and _entropy(v) >= 3.2:
        return True
    return False


def _token_like_path_segment(seg: str) -> bool:
    """Long random-looking segment. A hyphenated word slug is not one."""
    if len(seg) < 24:
        return False
    if _HEX_RE.match(seg) or _UUID_RE.match(seg):
        return True
    hyphen_ratio = (seg.count("-") + seg.count("_")) / len(seg)
    if hyphen_ratio > 0.08:  # words joined by - or _, like an article slug
        return False
    has_digit = any(c.isdigit() for c in seg)
    has_alpha = any(c.isalpha() for c in seg)
    return has_digit and has_alpha and _entropy(seg) >= 3.8


def _internal_host(host: str) -> bool:
    h = host.lower().rstrip(".")
    if not h:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return not ip.is_global
    except ValueError:
        pass
    return "." not in h or h == "localhost" or h.endswith(_PRIVATE_SUFFIXES)


def sensitive_url_reasons(url: str) -> list[str]:
    """Machine-readable reasons a URL should not be sent out. Empty list = nothing found."""
    reasons: list[str] = []
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
    except ValueError:
        return ["unparseable_url"]

    if parts.username or parts.password:
        reasons.append("credentials_in_url")
    if _internal_host(host):
        reasons.append("internal_or_private_host")
    if _EMAIL_RE.search(unquote(url)):
        reasons.append("email_address_in_url")

    pairs = parse_qsl(parts.query, keep_blank_values=True)
    # Fragments are sometimes used like query strings (#token=...).
    if parts.fragment and "=" in parts.fragment:
        pairs += parse_qsl(parts.fragment, keep_blank_values=True)
    for key, value in pairs:
        if _key_tokens(key) & _SENSITIVE_KEY_TOKENS:
            reasons.append("sensitive_parameter_name")
            break
    for _, value in pairs:
        if _looks_like_secret_value(value):
            reasons.append("token_like_parameter_value")
            break

    for seg in (s for s in parts.path.split("/") if s):
        seg = unquote(seg)
        if _token_like_path_segment(seg):
            reasons.append("token_like_path_segment")
            break
    if parts.fragment and "=" not in parts.fragment and _looks_like_secret_value(parts.fragment):
        reasons.append("token_like_fragment")

    # stable, de-duplicated
    return list(dict.fromkeys(reasons))


def personalised_url(url: str) -> bool:
    """True if the URL appears to carry a recipient-specific or secret value."""
    return any(r != "internal_or_private_host" for r in sensitive_url_reasons(url))


def plan_url_lookup(url: str) -> dict[str, Any]:
    """Decide how (or whether) `url` may be sent to an external reputation service."""
    reasons = sensitive_url_reasons(url)
    if reasons:
        return {"action": "skip", "lookup_url": None, "reasons": reasons}
    try:
        parts = urlsplit(url)
    except ValueError:
        return {"action": "skip", "lookup_url": None, "reasons": ["unparseable_url"]}
    if parts.query or parts.fragment:
        trimmed = f"{parts.scheme}://{parts.netloc}{parts.path}"
        return {"action": "trimmed", "lookup_url": trimmed, "reasons": ["query_or_fragment_removed"]}
    return {"action": "full", "lookup_url": url, "reasons": []}


REASON_TEXT = {
    "credentials_in_url": "contains a username or password",
    "internal_or_private_host": "points at a private or internal host",
    "email_address_in_url": "contains an email address",
    "sensitive_parameter_name": "has a parameter that names a token, code or person",
    "token_like_parameter_value": "has a long random-looking value (likely a token or ID)",
    "token_like_path_segment": "has a long random-looking path segment (likely a token or ID)",
    "token_like_fragment": "has a long random-looking fragment",
    "unparseable_url": "could not be parsed",
    "query_or_fragment_removed": "query string and fragment were removed before lookup",
}


def redact_url_for_external_ai(url: str) -> str:
    """Return a conservative URL representation suitable for an external LLM."""
    try:
        parts = urlsplit(url)
        plan = plan_url_lookup(url)
        if plan["action"] == "skip":
            return f"{parts.scheme}://{parts.hostname or ''}/[sensitive destination details omitted]"
        # `trimmed` drops query and fragment; `full` is only a URL without those parts.
        return str(plan.get("lookup_url") or f"{parts.scheme}://{parts.hostname or ''}/[destination omitted]")
    except Exception:
        return "[URL omitted by privacy policy]"


_URL_TEXT_RE = re.compile(r"https?://[^\s<>\"']+", re.IGNORECASE)


def sanitize_for_external_ai(value: Any) -> Any:
    """Recursively sanitize email text and URL-shaped keys before LLM requests.

    Original parsed evidence is preserved server-side and in the forensic report.
    Only the context copied to the external model is transformed.
    """
    if isinstance(value, str):
        def _sub(match):
            raw = match.group(0)
            trailing = ""
            while raw and raw[-1] in set(".,;:!?)]}\\"):
                trailing = raw[-1] + trailing
                raw = raw[:-1]
            return redact_url_for_external_ai(raw) + trailing
        sanitized = _URL_TEXT_RE.sub(_sub, value)
        # Defense in depth for metadata and JSON/.msg paths: parsers may not
        # have applied all body PII masking to every header/field.
        from email_parser.pii_masker import redact_sensitive_data
        return redact_sensitive_data(sanitized)
    if isinstance(value, list):
        return [sanitize_for_external_ai(item) for item in value]
    if isinstance(value, tuple):
        return [sanitize_for_external_ai(item) for item in value]
    if isinstance(value, dict):
        result = {}
        for key, item in value.items():
            safe_key = sanitize_for_external_ai(str(key))
            if safe_key in result:
                safe_key = f"{safe_key} [additional indicator]"
            result[safe_key] = sanitize_for_external_ai(item)
        return result
    return value


def _safe_display(url: str) -> str:
    """Display only the origin for skipped sensitive URLs; paths can hold tokens."""
    try:
        p = urlsplit(url)
        host = p.hostname or ""
        reasons = sensitive_url_reasons(url)
        if reasons:
            return f"{p.scheme}://{host}/[destination details omitted]"
        shown = f"{p.scheme}://{host}{p.path}"
        if len(shown) > 80:
            shown = shown[:79] + "…"
        return shown + ("?…" if (p.query or p.fragment) else "")
    except ValueError:
        return "(unparseable link)"


def build_privacy_report(
    *,
    email: dict,
    iocs: dict,
    threat_intel: dict,
    provenance: dict,
    attachments: Optional[list] = None,
) -> dict:
    """
    Plain data describing where this analysis's content went. Built from what
    the code actually does; the UI renders it, it does not invent it.
    """
    live = (provenance or {}).get("threat_intel_mode") == "live"
    provider = (provenance or {}).get("assessment_provider") or ""
    skipped_by_triage = bool((provenance or {}).get("gemini_skipped_by_triage"))
    gemini_used = provider.startswith("gemini") or "gemini" in provider
    urls = [u for u in (iocs or {}).get("urls") or [] if u]

    plans = [(u, plan_url_lookup(u)) for u in urls]
    url_results = (threat_intel or {}).get("url_reputation") or {}
    n_full = n_trim = cached_full = cached_trim = 0
    skipped = []
    skipped_by_policy = []
    missing_key_count = throttled_count = 0
    for url, plan in plans:
        result = url_results.get(url) if isinstance(url_results, dict) else None
        result = result if isinstance(result, dict) else {}
        status = str(result.get("status") or "").lower()
        lookup_source = result.get("lookup_source")
        if plan["action"] == "skip":
            skipped.append({"url": _safe_display(url), "reasons": plan["reasons"],
                            "why": "; ".join(REASON_TEXT.get(r, r) for r in plan["reasons"])})
            continue
        if status == "not_configured":
            missing_key_count += 1
            continue
        if status in {"skipped_limit", "rate_limited_internal", "not_checked", "disabled"}:
            skipped_by_policy.append({"url": _safe_display(url), "status": status})
            if status == "rate_limited_internal":
                throttled_count += 1
            continue
        if lookup_source == "cache":
            if plan["action"] == "trimmed":
                cached_trim += 1
            else:
                cached_full += 1
            continue
        # lookup_source=remote is set for successful and failed remote requests.
        if lookup_source == "remote":
            if plan["action"] == "trimmed":
                n_trim += 1
            else:
                n_full += 1
    n_ips = len((iocs or {}).get("ips") or [])
    n_domains = len((iocs or {}).get("domains") or [])
    n_hashes = len((iocs or {}).get("hashes") or [])

    def ext(provider_id, name, sends, lookups, notes=None):
        entries = [v for v in (lookups or {}).values() if isinstance(v, dict)]
        remote = sum(1 for value in entries if value.get("lookup_source") == "remote")
        cached = sum(1 for value in entries if value.get("lookup_source") == "cache")
        missing = sum(1 for value in entries if value.get("status") == "not_configured")
        skipped_privacy = sum(1 for value in entries if value.get("status") == "skipped_privacy")
        skipped_policy = sum(1 for value in entries if value.get("status") in {"skipped_limit", "skipped_non_public", "rate_limited_internal", "not_checked", "disabled"})
        failed = sum(1 for value in entries if value.get("status") in {"timeout", "network_error", "provider_error", "invalid_response", "rate_limited", "unavailable"})
        if not live:
            state = "off"
        elif not entries:
            state = "nothing_to_send"
        elif remote and (failed or missing or skipped_privacy or skipped_policy):
            state = "partial"
        elif remote:
            state = "sent"
        elif cached:
            state = "cached"
        elif missing:
            state = "not_configured"
        elif skipped_privacy and not skipped_policy:
            state = "skipped_for_privacy"
        elif skipped_policy:
            state = "skipped_by_policy"
        elif failed:
            state = "unavailable"
        else:
            state = "nothing_to_send"
        flow_notes = list(notes or [])
        if remote or cached or failed or missing or skipped_privacy or skipped_policy:
            flow_notes.append(
                f"This analysis: {remote} outbound request(s), {cached} cached result(s), "
                f"{failed} failed result(s), {missing} not configured, "
                f"{skipped_privacy} privacy skip(s), {skipped_policy} policy/limit skip(s)."
            )
        return {
            "id": provider_id, "name": name, "status": state, "sends": sends,
            # `count` is the number of remote requests for this analysis. Cached,
            # failed, unconfigured, and skipped indicators are reported separately
            # below so the privacy panel cannot imply a request was sent when it was not.
            "count": remote, "counts": {"remote": remote, "cached": cached, "failed": failed,
            "not_configured": missing, "skipped_for_privacy": skipped_privacy, "skipped_by_policy": skipped_policy},
            "notes": flow_notes,
        }

    flows = [
        {
            "id": "local_parsing", "name": "E-TAP backend (parsing and analysis)",
            "status": "always",
            "sends": ([
                "a simplified message reconstructed from visible sender/subject/body text by the Gmail extension",
                "not the original raw message, original authentication/routing headers, link targets or attachments",
            ] if (provenance or {}).get("input_mode") == "quick_content_check" else [
                "the uploaded .eml/.msg artifact, including available headers, body and attachments",
            ]),
            "notes": ["The browser sends the selected content to the E-TAP backend over HTTPS. Parsing and forensic checks run on the E-TAP server."],
        },
        {
            "id": "mongodb", "name": "E-TAP database (MongoDB)",
            "status": "stored",
            "sends": ["subject, sender and recipient addresses, date",
                      "header, attachment and link analysis results (including text read from images by OCR)",
                      "the list of URLs, domains, IPs and file hashes found, with full URLs",
                      "the verdict and explanation"],
            "notes": ["The message body is not saved as its own field.",
                      "There is currently no delete or retention control for stored analyses."],
        },
        {
            "id": "gemini", "name": "Google Gemini (AI interpretation)",
            "status": ("sent" if gemini_used else ("skipped_by_triage" if skipped_by_triage else "off")),
            "sends": ["subject, sender, recipient and reply-to",
                      "message body text and HTML after parser masking plus an additional external-LLM PII-sanitization pass",
                      "header, link and attachment findings after URL and common-PII sanitization",
                      "sanitized URL representations; query strings/fragments are removed and secret-bearing destinations are reduced to their origin",
                      "text read from images by OCR after common-PII sanitization"],
            "notes": ["The external-LLM context is sanitized before the request; e-mail addresses and common PII patterns are masked, query/fragment values are removed, and secret-bearing destinations are reduced to their origin."],
        },
        ext("virustotal_urls", "VirusTotal (URLs)",
            ["scheme, host and path only when a query string is present; the full URL otherwise"],
            url_results,
            notes=["VirusTotal may add queried URLs to a dataset shared with its community."]),
        ext("virustotal_hashes", "VirusTotal (file hashes)", ["SHA-256 hash only; files are never uploaded"],
            (threat_intel or {}).get("hash_reputation") or {}),
        ext("abuseipdb", "AbuseIPDB (IP addresses)", ["public IP addresses found in headers and links"],
            (threat_intel or {}).get("ip_reputation") or {}),
        ext("whois", "WHOIS (domains)", ["domain names found in the message"],
            (threat_intel or {}).get("domain_info") or {}),
        ext("ip_geolocation", "IP geolocation", ["public IP addresses; geographic estimates, not attribution"],
            (threat_intel or {}).get("geo_lookup") or {},
            notes=["Geolocation estimates a network address; it does not prove a person's location or attacker identity."]),
    ]
    return {
        "schema_version": 1,
        "input_mode": (provenance or {}).get("input_mode"),
        "external_lookups_enabled": live,
        "flows": flows,
        "url_lookups": {
            "total_urls": len(urls),
            # Actual requests made/reused during this analysis.
            "sent_in_full": n_full if live else 0,
            "sent_trimmed": n_trim if live else 0,
            "cached_full": cached_full if live else 0,
            "cached_trimmed": cached_trim if live else 0,
            # Useful preview counts when live lookup is off. These are policy
            # estimates only; they do not mean any request was made.
            "would_send_in_full": sum(1 for _, plan in plans if plan["action"] == "full"),
            "would_send_trimmed": sum(1 for _, plan in plans if plan["action"] == "trimmed"),
            "skipped_for_privacy": skipped,
            "skipped_by_policy": skipped_by_policy,
            "not_sent_missing_key": missing_key_count,
            "not_sent_internal_throttle": throttled_count,
            "note": ("Lookups are off, so nothing was sent." if not live else
                     "Remote requests, cached results and skipped lookups are distinguished below. Skipped indicators are unknown, not clean."),
        },
        "caveats": [
            "Hosted analysis is not local processing: submitted content is sent to the E-TAP backend.",
            "When Gemini interpretation runs, a sanitized, reduced copy of email-derived context is sent to Google Gemini. Sanitization is heuristic and cannot guarantee removal of every sensitive value.",
            "Full extracted URLs/IOCs may be stored in MongoDB for correlation even when query-bearing URLs are trimmed or skipped for external VirusTotal lookups.",
        ],
    }
