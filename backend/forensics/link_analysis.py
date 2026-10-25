"""
B5: link text versus real destination.

Reads the `<a href>` links in an HTML body together with the text a reader
actually sees, and reports where they disagree. Also provides `analyze_url()`
for a bare URL (used for QR-code destinations).

Observed vs inferred. Everything here is read from the message itself. Nothing
is fetched: no redirects are followed and no page is visited, so
`resolution.status` is always "not_resolved" and the final destination after
any redirect is unknown. If a link carries a redirect-style parameter
(`?url=https://other.site`) the other host is reported as `inferred_target_host`,
clearly labelled as inferred, never as an observed destination.

Flags are signals, not verdicts. Mail from legitimate senders also uses
tracking domains and shorteners, so the evidence layer treats most of these as
weak and only a visible-text/real-host mismatch as strong.
"""
from __future__ import annotations

import re
from html.parser import HTMLParser
from typing import Any, Optional
from urllib.parse import parse_qsl, unquote, urlsplit

from .brand_domains import COMMONLY_IMPERSONATED_DOMAINS
from .domain_similarity import find_lookalike_brand, has_mixed_scripts, is_punycode, decode_punycode

MAX_LINKS = 200
MAX_TEXT = 200

_SHORTENERS = frozenset({
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly",
    "cutt.ly", "shorturl.at", "tiny.cc", "rb.gy", "lnkd.in", "t.ly", "s.id",
})
# second-level suffixes where the registrable domain is three labels
_TWO_LEVEL = frozenset({
    "co.uk", "org.uk", "ac.uk", "gov.uk", "co.in", "org.in", "gov.in", "ac.in", "net.in",
    "com.au", "net.au", "org.au", "co.nz", "co.jp", "com.br", "com.cn", "co.za", "com.sg",
})
_REDIRECT_KEYS = frozenset({"url", "u", "redirect", "redirect_uri", "redirecturl", "target",
                            "dest", "destination", "next", "continue", "return", "returnto", "goto", "link", "r"})
_URL_IN_TEXT = re.compile(r"(?:https?://)?(?:[a-z0-9\-]+\.)+[a-z]{2,}(?:[/:?#]\S*)?", re.I)
_IP_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def registrable_domain(host: str) -> str:
    host = (host or "").lower().rstrip(".")
    if not host or _IP_RE.match(host):
        return host
    labels = host.split(".")
    if len(labels) >= 3 and ".".join(labels[-2:]) in _TWO_LEVEL:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:]) if len(labels) >= 2 else host


def _host_of(url: str) -> Optional[str]:
    try:
        return (urlsplit(url).hostname or "").lower().rstrip(".") or None
    except ValueError:
        return None


def _display_host(text: str) -> Optional[str]:
    """Host that the visible link text claims, if the text looks like an address."""
    m = _URL_IN_TEXT.search(text or "")
    if not m:
        return None
    candidate = m.group(0)
    if not re.match(r"^https?://", candidate, re.I):
        candidate = "http://" + candidate
    return _host_of(candidate)


def _brands_named_in(text: str) -> set[str]:
    low = (text or "").lower()
    out = set()
    for dom in COMMONLY_IMPERSONATED_DOMAINS:
        root = dom.split(".")[0]
        if len(root) >= 4 and re.search(r"\b" + re.escape(root) + r"\b", low):
            out.add(dom)
    return out


def _clip(text: str, n: int = MAX_TEXT) -> str:
    t = " ".join((text or "").split())
    return t if len(t) <= n else t[: n - 1] + "…"


def analyze_url(url: str, display_text: Optional[str] = None) -> dict[str, Any]:
    """Static checks on one URL, optionally against the text shown for it."""
    out: dict[str, Any] = {
        "href": url, "host": None, "registrable_domain": None,
        "display_text": _clip(display_text) if display_text else None,
        "display_host": None, "flags": [], "details": {},
        "resolution": {"status": "not_resolved",
                       "note": "Redirects were not followed, so the final destination is unknown."},
    }
    flags: list[str] = out["flags"]
    try:
        parts = urlsplit(url)
    except ValueError:
        flags.append("unparseable_url")
        return out
    scheme = (parts.scheme or "").lower()
    if scheme in {"javascript", "data", "vbscript"}:
        flags.append("non_web_scheme")
        out["details"]["scheme"] = scheme
        return out
    if scheme not in {"http", "https"}:
        return out  # mailto:, tel:, relative links, anchors: not a web destination

    host = (parts.hostname or "").lower().rstrip(".")
    out["host"] = host
    out["registrable_domain"] = registrable_domain(host)

    if scheme == "http":
        flags.append("plain_http")
    if parts.username or parts.password:
        flags.append("userinfo_in_url")  # http://paypal.com@evil.com style
    if _IP_RE.match(host):
        flags.append("ip_address_host")
    if parts.port and parts.port not in (80, 443):
        flags.append("non_standard_port")
        out["details"]["port"] = parts.port
    if host in _SHORTENERS or out["registrable_domain"] in _SHORTENERS:
        flags.append("url_shortener")
    if is_punycode(host):
        flags.append("punycode_host")
        decoded = decode_punycode(host)
        out["details"]["decoded_host"] = decoded
        if decoded and has_mixed_scripts(decoded):
            flags.append("homograph_suspected")
    elif has_mixed_scripts(host):
        flags.append("homograph_suspected")
    if not _IP_RE.match(host):
        look = find_lookalike_brand(host)
        if look:
            flags.append("lookalike_domain")
            out["details"]["lookalike_of"] = look["brand"]

    # redirect-style parameter: the named target is inferred, not observed
    for key, value in parse_qsl(parts.query, keep_blank_values=True):
        if key.lower() in _REDIRECT_KEYS and re.match(r"^https?://", unquote(value), re.I):
            target = _host_of(unquote(value))
            if target and registrable_domain(target) != out["registrable_domain"]:
                flags.append("redirect_parameter_to_other_site")
                out["details"]["inferred_target_host"] = target
                break

    if display_text:
        dhost = _display_host(display_text)
        out["display_host"] = dhost
        if dhost and registrable_domain(dhost) != out["registrable_domain"]:
            flags.append("text_shows_different_site")
        elif not dhost:
            for brand in sorted(_brands_named_in(display_text)):
                if registrable_domain(brand) != out["registrable_domain"]:
                    flags.append("text_names_brand_link_goes_elsewhere")
                    out["details"]["brand_named"] = brand
                    break
    return out


class _AnchorParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.links: list[tuple[str, str]] = []
        self._href: Optional[str] = None
        self._text: list[str] = []
        self._depth = 0

    def handle_starttag(self, tag, attrs):
        t = tag.lower()
        if t == "a":
            if self._href is not None:  # unclosed previous anchor
                self._close()
            href = dict((k.lower(), v) for k, v in attrs).get("href")
            if href:
                self._href, self._text = href.strip(), []
        elif t == "img" and self._href is not None:
            alt = dict((k.lower(), v) for k, v in attrs).get("alt")
            if alt:
                self._text.append(alt)

    def handle_data(self, data):
        if self._href is not None:
            self._text.append(data)

    def handle_endtag(self, tag):
        if tag.lower() == "a" and self._href is not None:
            self._close()

    def _close(self):
        self.links.append((self._href, " ".join("".join(self._text).split())))
        self._href, self._text = None, []

    def close(self):
        super().close()
        if self._href is not None:
            self._close()


def analyze_links(body_html: Optional[str]) -> dict[str, Any]:
    """Analyse every web link in an HTML body. Returns a JSON-safe dict."""
    if not body_html:
        return {"available": False, "reason": "no HTML body to read links from",
                "links": [], "summary": {"total": 0, "with_flags": 0, "text_mismatch": 0, "truncated": False}}
    parser = _AnchorParser()
    try:
        parser.feed(body_html)
        parser.close()
    except Exception:
        pass  # keep whatever was read before the malformed part

    links, seen = [], set()
    for href, text in parser.links:
        key = (href, text)
        if key in seen:
            continue
        seen.add(key)
        res = analyze_url(href, text or None)
        if res["host"] is None and not res["flags"]:
            continue  # mailto:, anchors, relative paths
        links.append(res)

    truncated = len(links) > MAX_LINKS
    links = links[:MAX_LINKS]
    mismatch = sum(1 for l in links if {"text_shows_different_site", "text_names_brand_link_goes_elsewhere",
                                         "userinfo_in_url"} & set(l["flags"]))
    return {
        "available": True,
        "links": links,
        "summary": {"total": len(links), "with_flags": sum(1 for l in links if l["flags"]),
                    "text_mismatch": mismatch, "truncated": truncated},
        "resolution": "not_performed",
    }
