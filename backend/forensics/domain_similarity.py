"""
domain_similarity.py

Detects domain-level spoofing signals:
  - Punycode domains (xn--... — often used to disguise homograph attacks)
  - Homograph/mixed-script domains (mixing Latin with lookalike Cyrillic
    or other Unicode characters, e.g. "аpple.com" using Cyrillic 'а')
  - Typosquatting against known brands (via edit-distance similarity)
  - Display name vs actual domain mismatch (e.g. "PayPal Support"
    display name but sender domain has nothing to do with paypal.com)

None of this requires network access — it's pure string/Unicode analysis,
so it's fast and always available even if DNS lookups (used elsewhere for
SPF/DKIM/DMARC) fail or are rate-limited.
"""

import re
import unicodedata
from difflib import SequenceMatcher
from typing import Optional, Dict, List

from .brand_domains import COMMONLY_IMPERSONATED_DOMAINS, get_brand_root


def levenshtein_distance(a: str, b: str) -> int:
    """Standard edit-distance calculation — no external dependency needed."""
    if a == b:
        return 0
    if len(a) == 0:
        return len(b)
    if len(b) == 0:
        return len(a)

    prev_row = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        curr_row = [i]
        for j, cb in enumerate(b, 1):
            cost = 0 if ca == cb else 1
            curr_row.append(min(
                prev_row[j] + 1,       # deletion
                curr_row[j - 1] + 1,   # insertion
                prev_row[j - 1] + cost  # substitution
            ))
        prev_row = curr_row
    return prev_row[-1]


def similarity_ratio(a: str, b: str) -> float:
    """0.0 to 1.0 similarity score using difflib (fast, good enough for this use)."""
    return SequenceMatcher(None, a, b).ratio()


def is_punycode(domain: str) -> bool:
    """Punycode-encoded domains contain an 'xn--' label — a common technique
    to register visually-deceptive internationalized domain names."""
    return any(label.startswith("xn--") for label in domain.lower().split("."))


def decode_punycode(domain: str) -> Optional[str]:
    """Attempt to decode a punycode domain back to its Unicode form, so we
    can inspect what it actually LOOKS like to a human reader."""
    try:
        return domain.encode("ascii").decode("idna")
    except Exception:
        return None


def has_mixed_scripts(text: str) -> bool:
    """
    Detects if a string mixes Latin characters with non-Latin lookalike
    characters (e.g. Cyrillic 'а' U+0430 which looks identical to Latin
    'a' U+0061). This is the classic homograph attack signature — a domain
    that LOOKS like "apple.com" but uses different Unicode code points.

    Simplified heuristic: flag if the string contains characters from more
    than one Unicode script AND at least one of those scripts is commonly
    used for homograph attacks (Cyrillic, Greek).
    """
    scripts_seen = set()
    for ch in text:
        if not ch.isalpha():
            continue
        try:
            name = unicodedata.name(ch)
        except ValueError:
            continue

        if "CYRILLIC" in name:
            scripts_seen.add("CYRILLIC")
        elif "GREEK" in name:
            scripts_seen.add("GREEK")
        elif "LATIN" in name:
            scripts_seen.add("LATIN")

    # suspicious if it mixes Latin with Cyrillic/Greek — legitimate domains
    # essentially never do this intentionally
    return len(scripts_seen) > 1 and "LATIN" in scripts_seen


def find_lookalike_brand(domain: str, threshold: float = 0.80) -> Optional[Dict]:
    """
    Compares the given domain's "brand root" against every entry in our
    curated brand list. Returns the best match if similarity is high
    enough but NOT an exact match (exact match = legitimately that brand,
    not a lookalike of it).

    Returns:
        {"brand": "paypal.com", "similarity": 0.92, "edit_distance": 1}
        or None if nothing suspicious found.
    """
    candidate_root = get_brand_root(domain)
    best_match = None
    best_score = 0.0

    for brand_domain in COMMONLY_IMPERSONATED_DOMAINS:
        brand_root = get_brand_root(brand_domain)

        if candidate_root == brand_root:
            # exact match on the brand root — this domain probably IS
            # the real brand (or at least isn't a typosquat of it)
            continue

        score = similarity_ratio(candidate_root, brand_root)
        if score >= threshold and score > best_score:
            best_score = score
            best_match = {
                "brand": brand_domain,
                "similarity": round(score, 3),
                "edit_distance": levenshtein_distance(candidate_root, brand_root),
            }

    return best_match


def display_name_mentions_brand(display_name: Optional[str]) -> List[str]:
    """
    Checks if a sender's display name mentions a known brand by name
    (e.g. display name = "PayPal Security Team") — used to cross-check
    against the actual sending domain.

    NOTE: this only checks for the brand word being PRESENT — it does NOT
    by itself mean impersonation. A legitimate business called "Office
    Supply Hub" contains the word "office" but isn't impersonating
    office.com. See requires_impersonation_signal() below, which is the
    function that actually decides whether a mismatch is worth flagging.
    """
    if not display_name:
        return []

    mentioned = []
    lowered = re.sub(r"[^a-z0-9\s]", " ", display_name.lower())
    words = lowered.split()

    # build match candidates: individual words AND adjacent-word pairs
    # joined together (so "HDFC Bank" -> "hdfc", "bank", "hdfcbank" — this
    # catches multi-word brand names like "hdfcbank" without falling back
    # to unsafe raw substring matching, which is what caused "office" to
    # false-positive match inside the single token "officesupplyhub")
    candidates = set(words)
    for i in range(len(words) - 1):
        candidates.add(words[i] + words[i + 1])

    for brand_domain in COMMONLY_IMPERSONATED_DOMAINS:
        brand_root = get_brand_root(brand_domain)
        if len(brand_root) >= 4 and brand_root in candidates:
            mentioned.append(brand_domain)

    return mentioned


# Words that commonly accompany a brand name in a genuine impersonation
# attempt ("PayPal Support", "Amazon Billing", "HDFC Bank Customer Care").
# A brand name appearing WITHOUT any of these is much more likely to be a
# coincidental match against an ordinary business name (e.g. "Office
# Supply Hub", "Apple Valley Dental") than an actual impersonation.
IMPERSONATION_TRIGGER_WORDS = {
    "support", "security", "team", "service", "services", "billing",
    "account", "accounts", "verify", "verification", "alert", "alerts",
    "notification", "notifications", "help", "care", "admin",
    "administrator", "department", "desk", "helpdesk", "customer",
    "update", "updates", "confirm", "confirmation", "suspended",
    "suspension", "recovery", "secure", "official", "notice",
}


def requires_impersonation_signal(display_name: Optional[str]) -> bool:
    """Returns True if the display name contains a role/trigger word
    commonly paired with brand impersonation attempts."""
    if not display_name:
        return False
    lowered = re.sub(r"[^a-z0-9\s]", " ", display_name.lower())
    tokens = set(lowered.split())
    return bool(tokens & IMPERSONATION_TRIGGER_WORDS)


def analyze_domain(sender_domain: str, display_name: Optional[str] = None) -> Dict:
    """
    Main entry point — runs every domain-spoofing check and returns one
    combined result dict. This is what header_forensics.py calls.
    """
    result = {
        "domain": sender_domain,
        "is_punycode": False,
        "decoded_punycode": None,
        "homograph_suspected": False,
        "lookalike_brand": None,
        "display_name_brand_mentions": [],
        "display_name_domain_mismatch": False,
        "flags": [],
    }

    if not sender_domain:
        result["flags"].append("no_sender_domain")
        return result

    # --- punycode / homograph ---
    if is_punycode(sender_domain):
        result["is_punycode"] = True
        decoded = decode_punycode(sender_domain)
        result["decoded_punycode"] = decoded
        result["flags"].append("punycode_domain")
        if decoded and has_mixed_scripts(decoded):
            result["homograph_suspected"] = True
            result["flags"].append("homograph_attack_suspected")
    elif has_mixed_scripts(sender_domain):
        # domain itself (not punycode-encoded) contains mixed scripts —
        # rare but possible depending on mail client handling
        result["homograph_suspected"] = True
        result["flags"].append("homograph_attack_suspected")

    # --- typosquat / lookalike brand ---
    lookalike = find_lookalike_brand(sender_domain)
    if lookalike:
        result["lookalike_brand"] = lookalike
        result["flags"].append(f"lookalike_of_{lookalike['brand']}")

    # --- display name says one brand, domain says another ---
    brand_mentions = display_name_mentions_brand(display_name)
    result["display_name_brand_mentions"] = brand_mentions
    if brand_mentions and requires_impersonation_signal(display_name):
        actual_root = get_brand_root(sender_domain)
        for mentioned_brand in brand_mentions:
            if get_brand_root(mentioned_brand) != actual_root:
                result["display_name_domain_mismatch"] = True
                result["flags"].append(
                    f"display_name_claims_{mentioned_brand}_but_domain_is_{sender_domain}"
                )

    return result
