"""
header_forensics.py

THIS is the Stage B entry point. Call analyze_headers(parsed_email) with
a ParsedEmail object from Stage A (email_parser.parse_email/parse_any),
and get back a complete header forensics verdict — sender info, SPF/DKIM/
DMARC results, originating IP, and a consolidated list of red flags.

Usage:
    from email_parser import parse_email
    from forensics.header_forensics import analyze_headers

    parsed = parse_email("suspicious.eml")
    analysis = analyze_headers(parsed)
    print(analysis["red_flags"])
"""

from dataclasses import dataclass, field, asdict
from typing import List, Optional, Dict

from .received_chain import find_originating_ip, get_received_chain_summary, build_origin_analysis
from .auth_results import evaluate_authentication
from .domain_similarity import analyze_domain
from email.utils import parseaddr

def _extract_domain(email_address: Optional[str]) -> Optional[str]:
    if not email_address:
        return None

    _, parsed_address = parseaddr(email_address)

    if "@" not in parsed_address:
        return None

    domain = parsed_address.rsplit("@", 1)[1].strip().lower()

    return domain or None


@dataclass
class HeaderAnalysis:
    # --- sender identity (matches the original Stage B plan's field names) ---
    sender_email: Optional[str] = None
    display_name: Optional[str] = None
    reply_to: Optional[str] = None

    # --- auth verdicts (top-level, matches plan) ---
    spf: Optional[str] = None
    dkim: Optional[str] = None
    dmarc: Optional[str] = None

    # --- IP / routing ---
    originating_ip: Optional[str] = None
    received_chain: List[str] = field(default_factory=list)
    hops: List[Dict] = field(default_factory=list)            # structured hops, oldest first
    origin_analysis: Dict = field(default_factory=dict)       # where did it really come from (or: why we can't tell)

    # --- everything else (enrichment beyond the original plan sketch) ---
    auth_details: Dict = field(default_factory=dict)      # full spf/dkim/dmarc details incl. source (header vs live DNS)
    domain_analysis: Dict = field(default_factory=dict)    # punycode/homograph/lookalike/display-name-mismatch results
    reply_to_mismatch: bool = False

    # --- evidence availability ---
    # False when the original transport headers were never available (e.g. a
    # message rebuilt from visible Gmail text). Routing and SPF/DKIM/DMARC are
    # then reported as "not_available" instead of being guessed.
    available: bool = True
    unavailable_reason: Optional[str] = None

    red_flags: List[str] = field(default_factory=list)
    risk_indicator_count: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


NOT_AVAILABLE = "not_available"


def analyze_headers(parsed_email, headers_available: bool = True) -> dict:
    """
    parsed_email: a ParsedEmail object from Stage A (email_parser).
    Returns a plain dict (JSON-serializable) — the Stage B output that
    the team API layer and the frontend will consume.

    headers_available=False means the caller only had a reconstruction of the
    message (no Received / Authentication-Results / DKIM-Signature headers).
    Routing and authentication checks are skipped -- running them, including
    the live-DNS fallback, against headers that do not exist would produce
    misleading SPF/DKIM/DMARC results. Sender-identity checks that only need
    the From address (lookalike domains, Reply-To mismatch) still run.
    """
    data = parsed_email.to_dict() if hasattr(parsed_email, "to_dict") else parsed_email
    all_headers = data.get("all_headers", {})

    result = HeaderAnalysis(
        sender_email=data.get("from_email"),
        display_name=data.get("from_display_name"),
        reply_to=data.get("reply_to"),
    )

    from_domain = _extract_domain(result.sender_email)
    reply_to_domain = _extract_domain(result.reply_to)

    if headers_available:
        # --- Received chain / originating IP ---
        result.originating_ip = find_originating_ip(all_headers)
        result.received_chain = get_received_chain_summary(all_headers)
        _oa = build_origin_analysis(all_headers)
        result.hops = _oa["hops"]
        result.origin_analysis = _oa["origin"]

        if not all_headers.get("Received"):
            result.red_flags.append("no_received_headers")  # itself suspicious — legitimate mail always has at least one hop

        # --- SPF / DKIM / DMARC ---
        auth = evaluate_authentication(all_headers, from_domain, result.originating_ip)
        result.spf = auth["spf"]["verdict"]
        result.dkim = auth["dkim"]["verdict"]
        result.dmarc = auth["dmarc"]["verdict"]
        result.auth_details = auth

        if result.spf in ("fail", "softfail"):
            result.red_flags.append(f"spf_{result.spf}")
        if result.dkim in ("fail", "key_not_found", "misaligned"):
            result.red_flags.append(f"dkim_{result.dkim}")
        if result.dmarc == "fail":
            result.red_flags.append("dmarc_fail")
    else:
        reason = (
            "Original message headers were not available (content reconstructed "
            "from the visible email), so routing and SPF/DKIM/DMARC were not evaluated."
        )
        result.available = False
        result.unavailable_reason = reason
        result.spf = result.dkim = result.dmarc = NOT_AVAILABLE
        result.auth_details = {"available": False, "reason": reason}

    # --- Reply-To mismatch ---
    if reply_to_domain and from_domain and reply_to_domain != from_domain:
        result.reply_to_mismatch = True
        result.red_flags.append("reply_to_domain_mismatch")

    # --- Domain spoofing / lookalike / homograph ---
    domain_result = analyze_domain(from_domain, result.display_name)
    result.domain_analysis = domain_result
    result.red_flags.extend(domain_result.get("flags", []))

    result.risk_indicator_count = len(result.red_flags)

    return result.to_dict()
