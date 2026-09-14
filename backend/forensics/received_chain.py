"""
received_chain.py

Parses the Received: header chain to extract IP addresses and determine
the most likely ORIGINATING IP — i.e. the sender's actual public IP,
as opposed to internal relay hops or the recipient's own mail servers.

Why this is tricky: Received headers are PREPENDED by each mail server
as a message is relayed. That means:
  - all_headers["Received"][0]  = the MOST RECENT hop (closest to final
    delivery — often your own infrastructure, e.g. Postfix/fetchmail)
  - all_headers["Received"][-1] = the OLDEST hop (closest to the original
    sender)

So we walk the chain starting from the OLDEST hop and return the first
PUBLIC (non-private, non-loopback) IP we find — that's the point where
the message first touched the public internet, which is the strongest
signal of where it actually originated.
"""

import ipaddress
import re
from typing import List, Dict, Optional


# matches IPv4 addresses, optionally in brackets like [185.220.101.5]
IPV4_PATTERN = re.compile(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b")

# matches IPv6 addresses (simplified — good enough for extraction from headers)
IPV6_PATTERN = re.compile(r"\b([0-9a-fA-F]{1,4}(?::[0-9a-fA-F]{1,4}){7})\b")


def extract_ips_from_text(text: str) -> List[str]:
    """Pull every IPv4/IPv6-looking address out of a raw Received header string."""
    ips = []
    ips.extend(IPV4_PATTERN.findall(text))
    ips.extend(IPV6_PATTERN.findall(text))
    return ips


def is_public_ip(ip_str: str) -> bool:
    """
    Returns True if this IP is a real public internet address — i.e. NOT
    private (RFC1918), NOT loopback (127.0.0.1), NOT link-local, etc.
    Internal/private IPs tell us nothing about where an email actually
    came from on the internet.
    """
    try:
        ip_obj = ipaddress.ip_address(ip_str)
        return not (
            ip_obj.is_private
            or ip_obj.is_loopback
            or ip_obj.is_link_local
            or ip_obj.is_multicast
            or ip_obj.is_reserved
            or ip_obj.is_unspecified
        )
    except ValueError:
        return False


def parse_received_chain(all_headers: dict) -> List[Dict]:
    """
    Parses the raw Received header list into structured hop info.

    Returns a list of dicts, in the SAME ORDER as the original headers
    (index 0 = most recent hop, closest to final delivery):
        [
          {"raw": "...", "ips_found": ["185.220.101.5"], "public_ips": ["185.220.101.5"]},
          ...
        ]
    """
    received_headers = all_headers.get("Received", [])
    hops = []

    for raw_hop in received_headers:
        ips_found = extract_ips_from_text(raw_hop)
        public_ips = [ip for ip in ips_found if is_public_ip(ip)]
        hops.append({
            "raw": raw_hop,
            "ips_found": ips_found,
            "public_ips": public_ips,
        })

    return hops


def find_originating_ip(all_headers: dict) -> Optional[str]:
    """
    Returns the best guess at the sender's true originating public IP.

    Strategy: walk the Received chain from OLDEST hop to NEWEST (i.e.
    reverse of header order, since header[0] = newest). Return the first
    public IP encountered — this is the point where the message first
    became visible on the public internet, before it passed through any
    of the recipient's own internal/trusted relay infrastructure.
    """
    hops = parse_received_chain(all_headers)

    # walk from oldest (last in the list) to newest (first in the list)
    for hop in reversed(hops):
        if hop["public_ips"]:
            return hop["public_ips"][0]

    return None


def get_received_chain_summary(all_headers: dict) -> List[str]:
    """
    Returns a simplified list of raw Received header strings, in
    chronological order (oldest first) — this matches the "received_chain"
    field shape from the original Stage B plan (list of hop strings).
    """
    received_headers = all_headers.get("Received", [])
    return list(reversed(received_headers))  # oldest first, matches human-readable investigation order
