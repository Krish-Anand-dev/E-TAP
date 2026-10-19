"""
Evidence model for E-TAP reports (workstream B1 + B9).

Every finding in a report is one *evidence item* with an explicit origin:

  observed      facts E-TAP parsed or measured itself (headers, links,
                attachment structure, its own history)
  reputation    what an external provider said (VirusTotal, AbuseIPDB, WHOIS)
  ai_inferred   interpretation produced by a model (Gemini, the offline
                fallback heuristics, the metadata triage model)

and an explicit state, so "unknown" can never be mistaken for "safe":

  status        present | absent | unavailable   (unavailable = not checked
                or the check failed; it carries a reason)
  direction     raises_risk | lowers_risk | neutral
  weight        strong | weak

Observed and reputation items are built deterministically from the parsed
pipeline output -- no model is involved. AI findings are accepted only as
statements that cite those item ids; a statement whose citations do not
resolve is kept but flagged `ungrounded` instead of being presented as fact.

`build_evidence_report()` returns the payload that goes into the report as
`evidence_report`. It is JSON-safe and carries everything the three report
blocks need ("What we observed", "Why it matters", "What to do"), so no
client has to re-derive meaning from raw fields.

Nothing here performs I/O.
"""

from __future__ import annotations

import re
from typing import Any, Optional
from urllib.parse import urlsplit

from verdicts import (
    BAND_BY_LABEL,
    band_for_label,
    normalize_label,
)

SCHEMA_VERSION = 2

KIND_OBSERVED = "observed"
KIND_REPUTATION = "reputation"
KIND_AI = "ai_inferred"

STATUS_PRESENT = "present"
STATUS_ABSENT = "absent"          # looked, nothing there
STATUS_UNAVAILABLE = "unavailable"  # could not look / not looked

RAISES = "raises_risk"
LOWERS = "lowers_risk"
NEUTRAL = "neutral"

STRONG = "strong"
WEAK = "weak"

GROUND_EVIDENCE = "evidence"          # cites item ids that exist
GROUND_UNGROUNDED = "ungrounded"      # model statement with no valid citation
GROUND_MESSAGE = "message_content"    # content-only reading of the message text
GROUND_MODEL = "model"                # screening model output (no text claim)

STATE_HIGH_RISK = "high_risk_evidence"
STATE_UNCERTAIN = "suspicious_uncertain"
STATE_NONE_FOUND = "no_high_risk_found"

_AUTH_FAIL_VALUES = {"fail", "softfail", "key_not_found", "misaligned"}

_MAX_AI_FINDINGS = 8
_MAX_FLAGGED_PER_SECTION = 10


# ---------------------------------------------------------------------------
# small helpers
# ---------------------------------------------------------------------------

def _clip(text: Any, limit: int) -> str:
    s = " ".join(str(text if text is not None else "").split())
    return s if len(s) <= limit else s[: limit - 1] + "…"


def _display_url(url: Any) -> str:
    """URL for display: no query string or fragment (they can carry tokens)."""
    raw = str(url or "")
    try:
        parts = urlsplit(raw)
    except ValueError:
        return _clip(raw, 90)
    if not parts.scheme or not parts.netloc:
        return _clip(raw, 90)
    shown = f"{parts.scheme}://{parts.netloc}{parts.path}"
    if parts.query or parts.fragment:
        shown += "?…"
    return _clip(shown, 90)


def _item(
    id_: str,
    kind: str,
    category: str,
    title: str,
    *,
    source: str,
    detail: str = "",
    status: str = STATUS_PRESENT,
    direction: str = NEUTRAL,
    weight: str = WEAK,
    why: str = "",
    data: Optional[dict] = None,
    **extra: Any,
) -> dict:
    item = {
        "id": id_,
        "kind": kind,
        "category": category,
        "title": _clip(title, 160),
        "detail": _clip(detail, 400),
        "status": status,
        # only a present finding can push the verdict either way
        "direction": direction if status == STATUS_PRESENT else NEUTRAL,
        "weight": weight,
        "source": source,
        "why": _clip(why, 400),
    }
    if data:
        item["data"] = data
    item.update(extra)
    item.update({
        'raw_observation': data if data else (detail if kind != KIND_AI else None),
        'normalized_explanation': why or title,
        'confidence': 'unknown' if status == STATUS_UNAVAILABLE else ('inferred' if kind == KIND_AI else 'not_calibrated'),
        'provenance_type': 'inferred' if kind == KIND_AI else ('external' if kind == KIND_REPUTATION else 'observed'),
        'source_type': 'AI' if kind == KIND_AI else ('reputation' if kind == KIND_REPUTATION else 'static'),
        'supports': list(extra.get('evidence_ids') or []),
        'contradicts': [],
    })
    return item


def _humanize(code: str) -> str:
    text = re.sub(r"[_\-]+", " ", str(code)).strip()
    return text[:1].upper() + text[1:] if text else "Unnamed indicator"


# ---------------------------------------------------------------------------
# observed: headers
# ---------------------------------------------------------------------------

def _describe_flag(code: str) -> tuple[str, str, str]:
    """(title, weight, why) for a header red-flag code."""
    if code == "reply_to_domain_mismatch":
        return (
            "Reply-To points to a different domain than the sender",
            WEAK,
            "Replies would go somewhere other than the address that sent the email. "
            "Scammers use this, but some legitimate services and mailing lists do too.",
        )
    if code == "no_received_headers":
        return (
            "No mail-routing (Received) headers",
            WEAK,
            "Delivered mail normally carries routing headers. Their absence can mean the "
            "message was altered or rebuilt.",
        )
    if code == "punycode_domain":
        return (
            "Sender domain uses punycode (encoded international characters)",
            WEAK,
            "Encoded domains can hide look-alike characters, although some legitimate "
            "international domains use them.",
        )
    if code == "homograph_attack_suspected":
        return (
            "Sender domain mixes look-alike characters from different alphabets",
            STRONG,
            "Look-alike characters are used to make a fake domain resemble a real one.",
        )
    if code == "no_sender_domain":
        return ("Sender address has no usable domain", WEAK, "The sender cannot be tied to a domain.")
    m = re.match(r"^lookalike_of_(.+)$", code)
    if m:
        return (
            f"Sender domain looks like a lookalike of {m.group(1)}",
            STRONG,
            "Lookalike domains imitate a well-known brand to make the sender look genuine.",
        )
    m = re.match(r"^display_name_claims_(.+?)_but_domain_is_(.+)$", code)
    if m:
        return (
            f"Display name claims “{m.group(1)}” but the sender domain is {m.group(2)}",
            STRONG,
            "The name you see in your mailbox suggests one organisation while the address "
            "belongs to another.",
        )
    return (_humanize(code), WEAK, "Flagged by header analysis.")


def _header_items(headers: dict, input_mode: Optional[str]) -> list[dict]:
    items: list[dict] = []
    if not isinstance(headers, dict):
        headers = {}

    sender = headers.get("sender_email")
    if sender:
        name = headers.get("display_name")
        items.append(_item(
            "hdr.sender", KIND_OBSERVED, "headers",
            "Sender address",
            source="header_forensics",
            detail=f"{name} <{sender}>" if name else str(sender),
        ))

    spf, dkim, dmarc = (headers.get(k) for k in ("spf", "dkim", "dmarc"))
    vals = {"spf": spf, "dkim": dkim, "dmarc": dmarc}
    headers_missing = (
        headers.get("available") is False
        or all(v in (None, "not_available") for v in vals.values())
    )
    if headers_missing:
        reason = headers.get("unavailable_reason") or (
            "Original message headers were not available, so these checks were not run."
        )
        items.append(_item(
            "hdr.auth", KIND_OBSERVED, "headers",
            "Sender authentication (SPF / DKIM / DMARC) was not checked",
            source="header_forensics",
            status=STATUS_UNAVAILABLE,
            detail=reason,
            why="Without the original headers we cannot tell whether the sending domain "
                "really sent this message.",
        ))
    else:
        shown = " · ".join(
            f"{k.upper()}: {v if v else 'not present'}" for k, v in vals.items()
        )
        bad = [v for v in vals.values() if v in _AUTH_FAIL_VALUES]
        if bad:
            items.append(_item(
                "hdr.auth", KIND_OBSERVED, "headers",
                "Sender authentication failed",
                source="header_forensics",
                detail=shown,
                direction=RAISES,
                weight=STRONG if "fail" in bad else WEAK,
                why="These checks test whether the sending domain authorised this message. "
                    "A failure suggests the sender may be forged or the message altered.",
                data=dict(vals),
            ))
        elif all(v == "pass" for v in vals.values()):
            items.append(_item(
                "hdr.auth", KIND_OBSERVED, "headers",
                "Sender authentication passed",
                source="header_forensics",
                detail=shown,
                direction=LOWERS,
                weight=WEAK,
                why="A pass shows the sending domain authorised this message. It does not "
                    "show that the content or the request is safe; attackers also use "
                    "domains they control.",
                data=dict(vals),
            ))
        else:
            items.append(_item(
                "hdr.auth", KIND_OBSERVED, "headers",
                "Sender authentication is incomplete",
                source="header_forensics",
                detail=shown,
                why="Some checks are missing or inconclusive, so authentication does not "
                    "settle where this message came from.",
                data=dict(vals),
            ))

    seen: set[str] = set()
    for code in headers.get("red_flags") or []:
        code = str(code)
        if code in seen or re.match(r"^(spf|dkim|dmarc)_", code):
            continue  # authentication flags are covered by hdr.auth
        seen.add(code)
        title, weight, why = _describe_flag(code)
        items.append(_item(
            f"hdr.flag.{re.sub(r'[^a-z0-9]+', '_', code.lower())[:60]}",
            KIND_OBSERVED, "headers", title,
            source="header_forensics",
            direction=RAISES, weight=weight, why=why,
            data={"code": code},
        ))
    return items


# ---------------------------------------------------------------------------
# observed: attachments and links
# ---------------------------------------------------------------------------

def _attachment_items(attachments: list, input_mode: Optional[str], *, qr_traced: bool = False) -> list[dict]:
    items: list[dict] = []
    if input_mode == "quick_content_check":
        items.append(_item(
            "att.scope", KIND_OBSERVED, "attachments",
            "Attachments were not inspected",
            source="input_scope",
            status=STATUS_UNAVAILABLE,
            detail="This analysis used the text visible in the mail client, which does not include files.",
            why="A harmless-looking message can still carry a dangerous file.",
        ))
        return items

    atts = [a for a in (attachments or []) if isinstance(a, dict)]
    if not atts:
        items.append(_item(
            "att.none", KIND_OBSERVED, "attachments",
            "No attachments in the message",
            source="attachment_forensics",
            status=STATUS_ABSENT,
        ))
        return items

    for n, att in enumerate(atts):
        name = att.get("filename") or f"attachment {n + 1}"
        sha = att.get("sha256")
        base_data = {"filename": name, **({"sha256": sha} if sha else {})}
        found = False

        if att.get("type_mismatch"):
            found = True
            items.append(_item(
                f"att.{n}.type_mismatch", KIND_OBSERVED, "attachments",
                f"{name}: file type does not match its label",
                source="attachment_forensics",
                detail=f"Declared as {att.get('declared_type') or 'unknown'}, content looks like "
                       f"{att.get('actual_type') or 'unknown'}.",
                direction=RAISES, weight=STRONG,
                why="Files disguised as a different type are a common way to get someone to run them.",
                data=base_data,
            ))
        if att.get("has_macro"):
            found = True
            risky = bool(att.get("macro_behavior")) and bool(att.get("suspicious"))
            items.append(_item(
                f"att.{n}.macro", KIND_OBSERVED, "attachments",
                f"{name}: contains macros",
                source="attachment_forensics",
                detail="Static inspection only; the file was not run.",
                direction=RAISES, weight=STRONG if risky else WEAK,
                why="Macros can run code when the document is opened. Many legitimate "
                    "documents use them, so this matters most alongside other signs.",
                data=base_data,
            ))
        for flag in att.get("flags") or []:
            if not isinstance(flag, str) or flag in {"type_mismatch", "has_macro"}:
                continue
            if qr_traced and flag.startswith("hidden QR code"):
                continue  # replaced by destination-based qr.* items
            found = True
            items.append(_item(
                f"att.{n}.flag.{re.sub(r'[^a-z0-9]+', '_', flag.lower())[:40]}",
                KIND_OBSERVED, "attachments",
                f"{name}: {_humanize(flag).lower()}",
                source="attachment_forensics",
                direction=RAISES, weight=WEAK,
                why="Flagged by static attachment inspection.",
                data=base_data,
            ))
        for q, qr in enumerate(att.get("qr_urls") or []):
            found = True
            if qr_traced:
                continue
            items.append(_item(
                f"att.{n}.qr.{q}", KIND_OBSERVED, "attachments",
                f"{name}: image contains a QR code",
                source="attachment_forensics",
                detail=f"Decodes to {_display_url(qr)}",
                why="A QR code hides its destination from the eye. The decoded address is "
                    "analysed like any other link.",
                data=base_data,
            ))
        if not found:
            items.append(_item(
                f"att.{n}.clean", KIND_OBSERVED, "attachments",
                f"{name}: no static red flags",
                source="attachment_forensics",
                detail="Static checks only; the file was not opened or run.",
                why="Static checks cannot see what a file does when opened.",
                data=base_data,
            ))
    return items


def _link_items(iocs: dict, input_mode: Optional[str]) -> list[dict]:
    items: list[dict] = []
    urls = [u for u in ((iocs or {}).get("urls") or []) if u]
    if input_mode == "quick_content_check":
        items.append(_item(
            "link.scope", KIND_OBSERVED, "links",
            "Link destinations were not inspected",
            source="input_scope",
            status=STATUS_UNAVAILABLE,
            detail="Only the visible text of the message was available, so the real address "
                   "behind a link may differ from what is shown.",
            why="Displayed link text can point somewhere different from the actual destination.",
        ))
    if urls:
        items.append(_item(
            "link.count", KIND_OBSERVED, "links",
            f"{len(urls)} link{'s' if len(urls) != 1 else ''} found in the message",
            source="ioc_extraction",
            detail="; ".join(_display_url(u) for u in urls[:3]) + (" …" if len(urls) > 3 else ""),
            why="Links are the main way phishing messages move people to a fake site.",
            data={"count": len(urls)},
        ))
    else:
        items.append(_item(
            "link.none", KIND_OBSERVED, "links",
            "No links found in the message text",
            source="ioc_extraction",
            status=STATUS_ABSENT,
        ))
    return items


# ---------------------------------------------------------------------------
# link text vs destination (B5) and QR trace (B6)
# ---------------------------------------------------------------------------

_MAX_LINK_ITEMS = 5

_FLAG_WORDS = {
    "text_shows_different_site": "the text shown names a different site than the link goes to",
    "text_names_brand_link_goes_elsewhere": "the text names a well-known brand but the link goes elsewhere",
    "userinfo_in_url": "the address hides the real site behind a fake name before an @ sign",
    "lookalike_domain": "the domain looks like a well-known brand's",
    "homograph_suspected": "the domain mixes look-alike characters from different alphabets",
    "punycode_host": "the domain uses an encoded international form",
    "ip_address_host": "the link goes to a bare IP address instead of a name",
    "url_shortener": "the link uses a URL shortener, which hides the destination",
    "redirect_parameter_to_other_site": "the link contains a redirect to another site",
    "non_standard_port": "the link uses an unusual port",
    "non_web_scheme": "the link runs a script or embeds data instead of opening a site",
}
_STRONG_FLAGS = {"userinfo_in_url", "homograph_suspected", "non_web_scheme"}


def _host_label(link: dict) -> str:
    return _clip(link.get("host") or "(no host)", 80)


def _link_risk(link: dict) -> tuple[str, str]:
    """(direction, weight) for one analysed link. Weak unless the signal is hard to explain innocently."""
    flags = set(link.get("flags") or [])
    risky = flags - {"plain_http"}
    if not risky:
        return NEUTRAL, WEAK
    if risky & _STRONG_FLAGS:
        return RAISES, STRONG
    mismatch = {"text_shows_different_site", "text_names_brand_link_goes_elsewhere"} & risky
    # a mismatch that also looks like a fake (lookalike, bare IP, shortener) is strong;
    # on its own it also happens with legitimate tracking redirects
    if mismatch and risky & {"lookalike_domain", "ip_address_host", "url_shortener"}:
        return RAISES, STRONG
    return RAISES, WEAK


def _link_analysis_items(link_analysis: Optional[dict], iocs: dict, input_mode: Optional[str]) -> list[dict]:
    items: list[dict] = []
    if input_mode == "quick_content_check":
        return items  # link.scope already says link targets were not available
    la = link_analysis or {}
    has_urls = bool((iocs or {}).get("urls"))
    if not la.get("available"):
        if has_urls:
            items.append(_item(
                "link.text_check", KIND_OBSERVED, "links",
                "Link text could not be compared with where the links go",
                source="link_analysis", status=STATUS_UNAVAILABLE,
                detail=la.get("reason") or "No HTML body in this message.",
                why="Without the HTML, the text a reader sees for each link is not available.",
            ))
        return items

    links = la.get("links") or []
    flagged = [l for l in links if set(l.get("flags") or []) - {"plain_http"}]
    for i, link in enumerate(flagged[:_MAX_LINK_ITEMS]):
        direction, weight = _link_risk(link)
        flags = [f for f in link["flags"] if f in _FLAG_WORDS]
        shown = link.get("display_text") or ""
        if link.get("display_host"):
            title = f"A link says “{_clip(link['display_host'], 50)}” but goes to {_host_label(link)}"
        elif "text_names_brand_link_goes_elsewhere" in flags:
            title = f"A link mentioning {_clip((link.get('details') or {}).get('brand_named', 'a brand'), 40)} goes to {_host_label(link)}"
        else:
            title = f"Link to {_host_label(link)} looks unusual"
        details = "; ".join(_FLAG_WORDS[f] for f in flags)
        inferred = (link.get("details") or {}).get("inferred_target_host")
        if inferred:
            details += f". Inferred, not observed: it appears to redirect to {_clip(inferred, 60)}"
        items.append(_item(
            f"link.flag.{i}", KIND_OBSERVED, "links", title,
            source="link_analysis", detail=_clip(details[:1].upper() + details[1:], 400),
            direction=direction, weight=weight,
            why=("The address a reader sees is not where the link goes. Phishing messages often "
                 "hide the real site this way."
                 if weight == STRONG else
                 "This can be a sign of a disguised link, but legitimate mail also uses tracking "
                 "and redirect links, so weigh it with the other evidence."),
            data={"host": link.get("host"), "flags": link.get("flags")},
        ))
    if len(flagged) > _MAX_LINK_ITEMS:
        items.append(_item(
            "link.flag.more", KIND_OBSERVED, "links",
            f"{len(flagged) - _MAX_LINK_ITEMS} more unusual links not listed",
            source="link_analysis", direction=RAISES, weight=WEAK,
        ))
    if links and not flagged:
        items.append(_item(
            "link.text_ok", KIND_OBSERVED, "links",
            f"Link text matched the destination for {len(links)} link{'s' if len(links) != 1 else ''}",
            source="link_analysis",
            why="This only compares what the message says with where the link points. "
                "It does not show that the destination is safe.",
        ))
    if links or has_urls:
        items.append(_item(
            "link.resolution", KIND_OBSERVED, "links",
            "Where the links finally lead was not checked",
            source="link_analysis", status=STATUS_UNAVAILABLE,
            detail="E-TAP reads the address in the message. It does not follow redirects or visit the page.",
            why="A link can redirect elsewhere after it is clicked.",
        ))
    return items


def _qr_items(qr_trace: Optional[dict]) -> list[dict]:
    items: list[dict] = []
    for n, entry in enumerate((qr_trace or {}).get("entries") or []):
        name = _clip(entry.get("source_attachment") or f"image {n + 1}", 60)
        status = entry.get("status")
        if not entry.get("checked"):
            reason = {
                "decoder_unavailable": "no QR decoder is installed on the server",
                "image_unreadable": "the image could not be opened",
            }.get(status, "the scan failed")
            items.append(_item(
                f"qr.{n}.unchecked", KIND_OBSERVED, "attachments",
                f"{name}: could not be checked for a QR code",
                source="qr_trace", status=STATUS_UNAVAILABLE, detail=f"Reason: {reason}.",
                why="If the image holds a QR code, its destination is unknown.",
            ))
            continue
        if not entry.get("decoded"):
            items.append(_item(
                f"qr.{n}.none", KIND_OBSERVED, "attachments",
                f"{name}: no QR code found",
                source="qr_trace", status=STATUS_ABSENT,
            ))
            continue
        for q, dec in enumerate(entry["decoded"]):
            if dec.get("kind") != "url":
                items.append(_item(
                    f"qr.{n}.{q}.text", KIND_OBSERVED, "attachments",
                    f"{name}: QR code holds text, not a web address",
                    source="qr_trace",
                    why="It does not open a website, though some phone apps act on QR text.",
                ))
                continue
            link = dec["link"]
            direction, weight = _link_risk(link)
            flags = [f for f in link["flags"] if f in _FLAG_WORDS]
            if dec["link"].get("personalised"):
                flags.append("personalised")
            words = [(_FLAG_WORDS.get(f) or "the address carries a value that looks specific to one recipient")
                     for f in flags]
            detail = (f"Decoded address: {_display_url(link['href'])}. "
                      + ("; ".join(words)[:1].upper() + "; ".join(words)[1:] + ". " if words else
                         "No link red flags were seen in the address itself. ")
                      + "Redirects were not followed.")
            if dec["link"].get("personalised") and direction == NEUTRAL:
                direction, weight = RAISES, WEAK
            items.append(_item(
                f"qr.{n}.{q}", KIND_OBSERVED, "attachments",
                f"{name}: QR code leads to {_host_label(link)}",
                source="qr_trace", detail=detail, direction=direction, weight=weight,
                why="A QR code hides its destination from the eye, and phones often skip the "
                    "protection a computer has. A QR code alone is not a warning sign: the "
                    "address it holds is what is judged.",
                data={"host": link.get("host"), "flags": link.get("flags"), "image": name},
            ))
    return items


# ---------------------------------------------------------------------------
# reputation
# ---------------------------------------------------------------------------

_UNAVAILABLE_REASON = {
    "not_configured": "provider API key is not configured",
    "rate_limited": "provider rate limit reached",
    "rate_limited_internal": "provider rate limit reached",
    "error": "request failed",
    "private_or_reserved": "private or reserved address, not looked up",
    "skipped_privacy": "not sent to VirusTotal because the link looks like it holds personal or secret values",
}

_SECTIONS = (
    ("url_reputation", "url", "URL"),
    ("ip_reputation", "ip", "IP address"),
    ("domain_info", "domain", "domain"),
    ("hash_reputation", "hash", "file hash"),
)


def _unavailable_reason(info: Any, section: str) -> str:
    if not isinstance(info, dict):
        return "unexpected provider response"
    status = info.get("status")
    if status in _UNAVAILABLE_REASON:
        return _UNAVAILABLE_REASON[status]
    if section == "domain_info":
        return "WHOIS lookup failed or timed out"
    return "lookup did not return an answer"


def _reputation_items(threat_intel: Optional[dict]) -> list[dict]:
    ti = threat_intel or {}
    if not ti:
        return [_item(
            "rep.none", KIND_REPUTATION, "reputation",
            "No reputation data recorded for this analysis",
            source="threat_intel", status=STATUS_UNAVAILABLE,
            why="Unknown reputation is not the same as a clean reputation.",
        )]
    if ti.get("lookup_mode") == "offline_placeholder":
        return [_item(
            "rep.offline", KIND_REPUTATION, "reputation",
            "Reputation of links, domains, IPs and files was not checked",
            source="threat_intel", status=STATUS_UNAVAILABLE,
            detail="Threat-intelligence lookups were switched off for this analysis.",
            why="Without reputation lookups we cannot say whether anything in this message "
                "is already known to be malicious. That is not the same as clean.",
        )]

    items: list[dict] = []
    for key, tag, noun in _SECTIONS:
        data = ti.get(key) or {}
        if not isinstance(data, dict) or not data:
            continue
        flagged: list[tuple[str, dict]] = []
        unavailable: list[str] = []
        clean = unseen = young = aged = 0
        young_list: list[tuple[str, int]] = []

        for indicator, info in data.items():
            if key == "domain_info":
                if not isinstance(info, dict) or info.get("error"):
                    unavailable.append(_unavailable_reason(info, key))
                    continue
                age = info.get("age_days")
                if isinstance(age, int) and age >= 0:
                    if age < 30:
                        young_list.append((indicator, age))
                    else:
                        aged += 1
                else:
                    unavailable.append("registration date not available")
                continue

            if not isinstance(info, dict) or info.get("error"):
                unavailable.append(_unavailable_reason(info, key))
            elif info.get("malicious") is True:
                flagged.append((indicator, info))
            elif info.get("malicious") is False:
                clean += 1
            elif str(info.get("status", "")).startswith("not previously scanned"):
                unseen += 1
            else:
                unavailable.append(_unavailable_reason(info, key))

        for i, (indicator, info) in enumerate(flagged[:_MAX_FLAGGED_PER_SECTION]):
            label = _display_url(indicator) if tag == "url" else _clip(indicator, 80)
            if tag == "ip":
                score = info.get("abuse_confidence_score")
                detail = (
                    f"AbuseIPDB confidence {score}%, {info.get('reports')} report(s)"
                    if score is not None else "Reported by AbuseIPDB"
                )
                weight = STRONG if isinstance(score, (int, float)) and score >= 75 else WEAK
                why = "This address has been reported for abusive activity."
            else:
                count = info.get("malicious_engine_count")
                total = info.get("total_engines")
                detail = (
                    f"{count} of {total} security engines flagged it"
                    if count is not None and total else "Flagged by VirusTotal"
                )
                weight = STRONG if (count is None or count >= 3) else WEAK
                why = (
                    "Several independent engines agree, which is stronger than a single detection."
                    if weight == STRONG else
                    "Only a few engines flagged it. A low-count detection is often a false "
                    "positive, so weigh it with the other evidence."
                )
            items.append(_item(
                f"rep.{tag}.flagged.{i}", KIND_REPUTATION, "reputation",
                f"Flagged {noun}: {label}",
                source="virustotal" if tag != "ip" else "abuseipdb",
                detail=detail, direction=RAISES, weight=weight, why=why,
            ))
        if len(flagged) > _MAX_FLAGGED_PER_SECTION:
            items.append(_item(
                f"rep.{tag}.flagged.more", KIND_REPUTATION, "reputation",
                f"{len(flagged) - _MAX_FLAGGED_PER_SECTION} more flagged {noun}s not listed",
                source="threat_intel", direction=RAISES, weight=WEAK,
            ))

        for i, (indicator, age) in enumerate(young_list[:_MAX_FLAGGED_PER_SECTION]):
            items.append(_item(
                f"rep.domain.young.{i}", KIND_REPUTATION, "reputation",
                f"Domain registered {age} day{'s' if age != 1 else ''} ago: {_clip(indicator, 60)}",
                source="whois", direction=RAISES, weight=WEAK,
                why="Newly registered domains are common in phishing, but plenty of "
                    "legitimate new sites exist too.",
            ))
        if aged and not young_list:
            items.append(_item(
                "rep.domain.aged", KIND_REPUTATION, "reputation",
                f"{aged} domain{'s' if aged != 1 else ''} registered for 30+ days",
                source="whois",
                why="Age alone does not make a domain trustworthy.",
            ))
        if clean:
            items.append(_item(
                f"rep.{tag}.clean", KIND_REPUTATION, "reputation",
                f"{clean} {noun}{'s' if clean != 1 else ''}: no provider flagged",
                source="virustotal" if tag != "ip" else "abuseipdb",
                direction=LOWERS, weight=WEAK,
                why="Nothing was flagged at the time of the check. That does not prove it is "
                    "safe: new malicious pages are often not detected yet.",
            ))
        if unseen:
            items.append(_item(
                f"rep.{tag}.unseen", KIND_REPUTATION, "reputation",
                f"{unseen} {noun}{'s' if unseen != 1 else ''}: no record at the provider",
                source="virustotal",
                status=STATUS_UNAVAILABLE,
                why="Unknown is not safe. Brand-new phishing links often have no record yet.",
            ))
        if unavailable:
            top = max(set(unavailable), key=unavailable.count)
            items.append(_item(
                f"rep.{tag}.unavailable", KIND_REPUTATION, "reputation",
                f"{len(unavailable)} {noun} lookup{'s' if len(unavailable) != 1 else ''} unavailable",
                source="threat_intel", status=STATUS_UNAVAILABLE,
                detail=f"Reason: {top}.",
                why="These could not be checked, so they are neither flagged nor cleared.",
            ))
    return items


# ---------------------------------------------------------------------------
# observed: E-TAP's own history
# ---------------------------------------------------------------------------

def _correlation_items(correlation: Optional[dict]) -> list[dict]:
    c = correlation or {}
    items: list[dict] = []
    related = c.get("related_emails") or []
    shared = c.get("shared_infrastructure") or []
    if related:
        items.append(_item(
            "corr.related", KIND_OBSERVED, "history",
            f"{len(related)} similar earlier message{'s' if len(related) != 1 else ''} in E-TAP history",
            source="correlation",
            why="Seeing the same indicators again suggests a pattern. It does not by "
                "itself say the pattern is harmful: check how the earlier ones were judged.",
            data={"count": len(related)},
        ))
    if shared:
        items.append(_item(
            "corr.shared", KIND_OBSERVED, "history",
            "Shares infrastructure with earlier messages",
            source="correlation",
            detail=_clip(", ".join(str(s) for s in shared[:5]), 200),
        ))
    if c.get("campaign_id"):
        items.append(_item(
            "corr.campaign", KIND_OBSERVED, "history",
            f"Grouped into campaign {c['campaign_id']}",
            source="correlation",
        ))
    return items


# ---------------------------------------------------------------------------
# public: deterministic ledger
# ---------------------------------------------------------------------------

def build_evidence_ledger(
    *,
    headers: Optional[dict] = None,
    attachments: Optional[list] = None,
    iocs: Optional[dict] = None,
    threat_intel: Optional[dict] = None,
    correlation: Optional[dict] = None,
    input_mode: Optional[str] = None,
    link_analysis: Optional[dict] = None,
    qr_trace: Optional[dict] = None,
) -> list[dict]:
    """Observed + reputation items. Deterministic; no model involved."""
    items: list[dict] = []
    items += _header_items(headers or {}, input_mode)
    items += _link_items(iocs or {}, input_mode)
    items += _link_analysis_items(link_analysis, iocs or {}, input_mode)
    items += _attachment_items(attachments or [], input_mode, qr_traced=qr_trace is not None)
    items += _qr_items(qr_trace)
    items += _reputation_items(threat_intel)
    items += _correlation_items(correlation)
    return items


def compact_ledger(items: list[dict]) -> list[dict]:
    """Slim copy of the ledger to put in front of the model (ids it may cite)."""
    return [
        {
            "id": it["id"],
            "kind": it["kind"],
            "title": it["title"],
            "detail": it.get("detail", ""),
            "status": it["status"],
            "direction": it["direction"],
            "weight": it["weight"],
        }
        for it in items
    ]


# ---------------------------------------------------------------------------
# AI items
# ---------------------------------------------------------------------------

def _is_model_provider(provider: Optional[str]) -> bool:
    return bool(provider) and provider.startswith("gemini")


def _ai_items(
    final_assessment: dict,
    content: dict,
    valid_ids: set[str],
    triage: Optional[dict],
) -> list[dict]:
    items: list[dict] = []
    provider = (final_assessment or {}).get("provider")
    content = content or {}

    # Screening model (XGBoost): a statement about metadata only.
    if (triage or {}).get("gemini_skipped"):
        conf = (triage or {}).get("triage_confidence")
        pct = f"{round(conf * 100)}%" if isinstance(conf, (int, float)) else "high"
        items.append(_item(
            "ai.triage", KIND_AI, "screening",
            "Passed automatic metadata screening",
            source="metadata_triage",
            detail=f"{pct} benign confidence. This screening looks at sender and "
                   "infrastructure metadata only.",
            direction=LOWERS, weight=WEAK,
            why="It does not read the message wording or follow links, so it cannot rule "
                "out a scam that uses a clean-looking sender.",
            grounding=GROUND_MODEL,
            evidence_ids=[],
        ))

    # Content-only reading (what the text alone suggests).
    content_source = "gemini" if _is_model_provider(content.get("provider")) else "offline_heuristic"
    cv = normalize_label(content.get("verdict") or content.get("content_verdict"))
    content_dir = RAISES if (cv and band_for_label(cv) != "safe") else NEUTRAL
    if (triage or {}).get("gemini_skipped"):
        reasons: list = []
    else:
        reasons = content.get("reasons") or []
    for n, reason in enumerate([r for r in reasons if r][:5]):
        items.append(_item(
            f"ai.content.{n}", KIND_AI, "content",
            _clip(reason, 160),
            source=content_source,
            direction=content_dir, weight=WEAK,
            why="Based on the wording of the message only; it was not confirmed by "
                "technical evidence." if content_source == "gemini" else
                "Matched by simple keyword rules, not by a language model.",
            grounding=GROUND_MESSAGE,
            evidence_ids=[],
        ))

    # Final interpretation: only model output carries claims worth grounding.
    if _is_model_provider(provider):
        findings = (final_assessment or {}).get("ai_findings") or []
        if findings:
            for n, f in enumerate([f for f in findings if isinstance(f, dict)][:_MAX_AI_FINDINGS]):
                cited = [i for i in (f.get("evidence_ids") or []) if isinstance(i, str)]
                valid = [i for i in cited if i in valid_ids]
                direction = f.get("direction")
                if direction not in (RAISES, LOWERS, NEUTRAL):
                    direction = NEUTRAL
                items.append(_item(
                    f"ai.finding.{n}", KIND_AI, "interpretation",
                    _clip(f.get("claim"), 160),
                    source="gemini",
                    detail=_clip(f.get("claim"), 400) if len(str(f.get("claim") or "")) > 160 else "",
                    direction=direction, weight=WEAK,
                    why=_clip(f.get("why_it_matters"), 400),
                    grounding=GROUND_EVIDENCE if valid else GROUND_UNGROUNDED,
                    evidence_ids=valid,
                ))
        else:
            # Older output without structured findings: keep the statements, never as grounded.
            for n, line in enumerate([s for s in ((final_assessment or {}).get("supporting_evidence") or []) if s][:6]):
                items.append(_item(
                    f"ai.finding.{n}", KIND_AI, "interpretation",
                    _clip(line, 160),
                    source="gemini",
                    grounding=GROUND_UNGROUNDED,
                    evidence_ids=[],
                ))
    return items


# ---------------------------------------------------------------------------
# conclusion, limitations, actions
# ---------------------------------------------------------------------------

def _limitations(
    headers: dict,
    threat_intel: dict,
    provenance: dict,
    input_mode: Optional[str],
    triage: Optional[dict],
) -> list[str]:
    out: list[str] = []
    if headers.get("available") is False or input_mode == "quick_content_check":
        out.append("Original email headers were not available, so sender authentication "
                   "and mail routing were not checked.")
    if input_mode == "quick_content_check":
        out.append("Link destinations and attachments were not inspected (visible text only).")
    mode = (threat_intel or {}).get("lookup_mode") or (provenance or {}).get("threat_intel_mode")
    if mode == "offline_placeholder":
        out.append("The reputation of links, domains, IPs and files was not checked.")
    elif mode == "live":
        n = (provenance or {}).get("threat_intel_unavailable") or 0
        total = (provenance or {}).get("threat_intel_lookups") or 0
        if n:
            out.append(f"{n} of {total} reputation lookups were unavailable.")
    if (provenance or {}).get("fallback_used"):
        out.append("The AI interpretation was unavailable, so a simpler offline check was used.")
    elif (triage or {}).get("gemini_skipped"):
        out.append("The AI content review was skipped; only metadata screening was applied.")
    return out


_BAND_STATE = {
    "danger": STATE_HIGH_RISK,
    "caution": STATE_UNCERTAIN,
    "safe": STATE_NONE_FOUND,
}

_STATE_TEXT = {
    STATE_HIGH_RISK: "High-risk evidence found.",
    STATE_UNCERTAIN: "Suspicious, but the evidence is not conclusive.",
    STATE_NONE_FOUND: "No high-risk indicators were found in the evidence available. "
                      "This is not a guarantee that the message is safe.",
}


def _confidence_level(confidence: Any, band: str, limitations: list[str]) -> str:
    try:
        c = float(confidence)
    except (TypeError, ValueError):
        c = 0.5
    level = "high" if c >= 0.8 else "medium" if c >= 0.55 else "low"
    if band != "danger" and limitations:
        if level == "high":
            level = "medium"
        if len(limitations) >= 3:
            level = "low"
    return level


_WEIGHT_ORDER = {STRONG: 0, WEAK: 1}
_KIND_ORDER = {KIND_OBSERVED: 0, KIND_REPUTATION: 1, KIND_AI: 2}


def _rank(items: list[dict], direction: str) -> list[dict]:
    pool = [
        i for i in items
        if i["status"] == STATUS_PRESENT and i["direction"] == direction
        and i.get("grounding") not in (GROUND_UNGROUNDED,)
    ]
    return sorted(pool, key=lambda i: (_WEIGHT_ORDER[i["weight"]], _KIND_ORDER[i["kind"]]))


def _headline(band: str, top: list[dict], limitations: list[str]) -> str:
    reasons = "; ".join(i["title"].rstrip(".") for i in top[:2])
    if band == "danger":
        base = "This email shows strong signs of phishing."
        return f"{base} Main reasons: {reasons}." if reasons else base
    if band == "caution":
        base = "This email is suspicious and should be verified before you act on it."
        if reasons:
            return f"{base} Main concerns: {reasons}."
        return f"{base} No single strong indicator stood out; the overall risk score is elevated."
    base = "No high-risk indicators were found in the evidence available."
    if limitations:
        return f"{base} This is not a guarantee: {limitations[0][:1].lower() + limitations[0][1:]}"
    return f"{base} This is not a guarantee of safety."


def _what_to_do(
    band: str,
    items: list[dict],
    limitations: list[str],
    final_assessment: dict,
) -> dict:
    steps: list[dict] = []

    # Evidence-specific steps first.
    for it in items:
        if it["status"] != STATUS_PRESENT:
            continue
        if it["id"].startswith("att.") and it["direction"] == RAISES:
            name = (it.get("data") or {}).get("filename")
            if name and not any(s["ref"] == f"att:{name}" for s in steps):
                steps.append({"text": f"Do not open the attachment “{name}”.", "basis": "evidence", "ref": f"att:{name}"})
        elif it["id"].startswith("qr.") and it["direction"] == RAISES:
            steps.append({"text": "Do not scan the QR code. Type the site's address yourself instead.", "basis": "evidence", "ref": it["id"]})
        elif it["id"] == "hdr.flag.reply_to_domain_mismatch":
            steps.append({"text": "Do not reply to this message: replies would go to a different domain than the sender.", "basis": "evidence", "ref": it["id"]})

    if band == "danger":
        policy = [
            "Do not click links, scan QR codes, open attachments or reply.",
            "Report it to your IT or security team (or your mail provider's phishing report), then delete it.",
            "If you already clicked, opened a file or entered a password: change that password from the official website (not from the email), review recent sign-in activity, and tell your IT or security contact. Clicking alone does not necessarily mean your device is affected.",
        ]
    elif band == "caution":
        policy = [
            "Do not act on the request yet. Confirm it with the sender through a separate, trusted channel, such as a phone number or address you already have.",
            "Avoid links and attachments until it is confirmed; type the website address yourself.",
            "If you are unsure, send it to your IT or security contact for review.",
        ]
    else:
        policy = [
            "No high-risk indicators were found, but that is not proof of safety.",
            "Be careful with unexpected requests for passwords, payments or verification codes; confirm them through another channel.",
        ]
        if limitations:
            policy.append("For a fuller check, analyse the original email file (.eml) with reputation lookups enabled.")
    steps += [{"text": t, "basis": "policy", "ref": None} for t in policy]

    ai_suggestions: list[str] = []
    if _is_model_provider((final_assessment or {}).get("provider")):
        for a in (final_assessment.get("recommended_actions") or [])[:4]:
            if not a:
                continue
            if band != "safe" and re.search(r"\bno (immediate )?action\b|deliver normally", str(a), re.I):
                continue
            ai_suggestions.append(_clip(a, 200))
    return {"steps": steps, "ai_suggestions": ai_suggestions}


# ---------------------------------------------------------------------------
# public: full report payload
# ---------------------------------------------------------------------------

def build_evidence_report(
    *,
    decision: dict,
    final_assessment: Optional[dict] = None,
    content_classification: Optional[dict] = None,
    headers: Optional[dict] = None,
    attachments: Optional[list] = None,
    iocs: Optional[dict] = None,
    threat_intel: Optional[dict] = None,
    correlation: Optional[dict] = None,
    triage: Optional[dict] = None,
    provenance: Optional[dict] = None,
    input_mode: Optional[str] = None,
    reconstructed: bool = False,
    link_analysis: Optional[dict] = None,
    qr_trace: Optional[dict] = None,
) -> dict:
    final_assessment = final_assessment or {}
    provenance = provenance or {}
    headers = headers or {}
    threat_intel = threat_intel or {}
    input_mode = input_mode or provenance.get("input_mode")

    ledger = build_evidence_ledger(
        headers=headers, attachments=attachments, iocs=iocs,
        threat_intel=threat_intel, correlation=correlation, input_mode=input_mode,
        link_analysis=link_analysis, qr_trace=qr_trace,
    )
    valid_ids = {i["id"] for i in ledger}
    items = ledger + _ai_items(final_assessment, content_classification or {}, valid_ids, triage)

    label = decision.get("verdict")
    band = decision.get("verdict_band") or BAND_BY_LABEL.get(label, "caution")
    limitations = _limitations(headers, threat_intel, provenance, input_mode, triage)

    risk_items = _rank(items, RAISES)
    calming_items = _rank(items, LOWERS)
    top_reasons = [i["id"] for i in risk_items[:3]]
    contradicting = [i["id"] for i in calming_items[:2]] if band != "safe" else []

    state = _BAND_STATE.get(band, STATE_UNCERTAIN)
    sections = {
        "observed": [i["id"] for i in items if i["kind"] == KIND_OBSERVED and i["status"] != STATUS_UNAVAILABLE],
        "reputation": [i["id"] for i in items if i["kind"] == KIND_REPUTATION and i["status"] != STATUS_UNAVAILABLE],
        "ai_inferred": [i["id"] for i in items if i["kind"] == KIND_AI],
        "not_checked": [i["id"] for i in items if i["status"] == STATUS_UNAVAILABLE],
    }

    ai_summary = None
    if _is_model_provider(final_assessment.get("provider")) and final_assessment.get("explanation"):
        ai_summary = {
            "text": _clip(final_assessment["explanation"], 1200),
            "source": final_assessment.get("provider"),
            "model": final_assessment.get("model"),
        }

    return {
        "schema_version": SCHEMA_VERSION,
        "reconstructed": bool(reconstructed),
        "conclusion": {
            "label": label,
            "band": band,
            "risk_score": decision.get("risk_score"),
            "confidence": final_assessment.get("confidence"),
            "confidence_level": _confidence_level(final_assessment.get("confidence"), band, limitations),
            "evidence_state": state,
            "state_text": _STATE_TEXT[state],
            "limitations": limitations,
            "reconciled": bool(decision.get("reconciled")),
        },
        "headline": _headline(band, risk_items, limitations),
        "top_reasons": top_reasons,
        "contradicting": contradicting,
        "evidence": items,
        "sections": sections,
        "ai_summary": ai_summary,
        "what_to_do": _what_to_do(band, items, limitations, final_assessment),
        "counts": {
            "total": len(items),
            "observed": sum(1 for i in items if i["kind"] == KIND_OBSERVED),
            "reputation": sum(1 for i in items if i["kind"] == KIND_REPUTATION),
            "ai_inferred": sum(1 for i in items if i["kind"] == KIND_AI),
            "unavailable": len(sections["not_checked"]),
            "ungrounded_ai": sum(1 for i in items if i.get("grounding") == GROUND_UNGROUNDED),
        },
    }


def build_for_stored_record(doc: dict, decision: dict) -> dict:
    """
    Rebuild an evidence report for a record saved before `evidence_report`
    existed. Marked `reconstructed` so the UI can say so; whatever the stored
    record never kept (full correlation, original provenance) is simply absent.
    """
    fa = doc.get("final_assessment") or {}
    provenance = doc.get("analysis_provenance") or {}
    return build_evidence_report(
        decision=decision,
        final_assessment=fa,
        content_classification=doc.get("content_analysis") or {},
        headers=doc.get("header_analysis") or {},
        attachments=(doc.get("attachment_analysis") or {}).get("attachments") or [],
        iocs=doc.get("ioc_analysis") or {},
        threat_intel=doc.get("threat_intel_analysis") or {},
        correlation={"campaign_id": doc.get("campaign_id")} if doc.get("campaign_id") else {},
        triage=doc.get("triage") or {},
        provenance=provenance,
        input_mode=provenance.get("input_mode"),
        reconstructed=True,
        link_analysis=doc.get("link_analysis"),
        qr_trace=doc.get("qr_trace"),
    )
