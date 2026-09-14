"""
brand_domains.py

A curated reference list of domains that are frequently impersonated in
phishing campaigns. Used by domain_similarity.py to flag lookalike/typosquat
domains — e.g. "paypa1.com" or "hdfcbank-verify.com" scoring high similarity
against "paypal.com" or "hdfcbank.com" respectively.

This list is intentionally India-weighted (major banks, government portals)
since this platform targets Indian users/analysts, plus the global brands
most commonly abused in phishing worldwide.

Feel free to extend this list — it's just data, no code changes needed
elsewhere when you add new entries.
"""

COMMONLY_IMPERSONATED_DOMAINS = [
    # --- Global tech / payment ---
    "paypal.com", "amazon.com", "apple.com", "microsoft.com", "google.com",
    "facebook.com", "instagram.com", "whatsapp.com", "linkedin.com",
    "netflix.com", "dropbox.com", "docusign.com", "adobe.com", "ebay.com",
    "outlook.com", "office.com", "icloud.com",

    # --- Global banks ---
    "chase.com", "bankofamerica.com", "wellsfargo.com", "citibank.com",
    "hsbc.com", "barclays.co.uk",

    # --- Indian banks ---
    "hdfcbank.com", "icicibank.com", "sbi.co.in", "axisbank.com",
    "kotak.com", "pnbindia.in", "bankofbaroda.in", "canarabank.com",
    "unionbankofindia.co.in", "idbibank.in", "yesbank.in", "indusind.com",

    # --- Indian government / public services (high-value phishing targets) ---
    "irctc.co.in", "incometax.gov.in", "uidai.gov.in", "indiapost.gov.in",
    "epfindia.gov.in", "passportindia.gov.in", "digilocker.gov.in",
    "mygov.in", "gst.gov.in", "nic.in",

    # --- Indian payment / fintech (UPI ecosystem — heavily targeted) ---
    "paytm.com", "phonepe.com", "npci.org.in", "razorpay.com",
]


def get_brand_root(domain: str) -> str:
    """
    Strip the TLD/subdomain noise to get the 'core' brand name for
    similarity comparison — e.g. "hdfcbank.com" -> "hdfcbank".
    Simple heuristic: take the second-to-last label for standard domains,
    or handle .co.in / .gov.in style two-part TLDs.

    Returns "" for None/empty input rather than raising -- historical
    domain data pulled from the DB (see correlation/engine.py's
    _collect_fuzzy_domain_matches) can legitimately contain None if any
    stored document has a missing/null ioc_analysis.domains field
    (e.g. from an older partial/failed pipeline run), since MongoDB's
    distinct() includes null as one of the distinct values in that case.
    """
    if not domain:
        return ""

    parts = domain.lower().strip(".").split(".")
    if len(parts) < 2:
        return domain.lower()

    # handle common two-part TLDs like co.in, gov.in, org.in
    two_part_tlds = {"co.in", "gov.in", "org.in", "co.uk", "com.au"}
    last_two = ".".join(parts[-2:])
    if last_two in two_part_tlds and len(parts) >= 3:
        return parts[-3]

    return parts[-2]
