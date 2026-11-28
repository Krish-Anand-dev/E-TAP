"""Mailbox providers that millions of unrelated people share.

Two emails that both mention gmail.com are not linked by that, so these domains
are left out when emails are compared with earlier ones. Everything else about an
email (addresses reputation, links, files) is still compared as before.
"""

from __future__ import annotations

COMMON_MAIL_PROVIDERS = frozenset({
    "gmail.com", "googlemail.com",
    "outlook.com", "hotmail.com", "live.com", "msn.com",
    "yahoo.com", "yahoo.co.in", "yahoo.co.uk", "ymail.com", "rocketmail.com",
    "icloud.com", "me.com", "mac.com",
    "aol.com", "proton.me", "protonmail.com", "gmx.com", "zoho.com", "zoho.in", "rediffmail.com",
})


def is_common_provider(domain: object) -> bool:
    """True for a provider's domain or a host under it (mail.gmail.com)."""
    if not isinstance(domain, str):
        return False
    parts = domain.strip().lower().strip(".").split(".")
    return any(".".join(parts[i:]) in COMMON_MAIL_PROVIDERS for i in range(len(parts) - 1))
