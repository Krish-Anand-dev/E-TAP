"""
Domain lookups for Stage E, via the python-whois library (no API key,
no signup, queries WHOIS servers directly).
"""

from __future__ import annotations
from datetime import datetime, timezone

try:
    import whois  # python-whois package
except ImportError:  # pragma: no cover - exercised in minimal local envs
    class _MissingWhois:
        @staticmethod
        def whois(domain: str):
            raise ImportError("python-whois is not installed")

    whois = _MissingWhois()

from .cache import TTLCache

_domain_cache = TTLCache(ttl_seconds=86400)  # domain age doesn't change hour to hour, cache longer


def _first(value):
    """python-whois sometimes returns a list for a field (multiple registrars
    reported historically) -- normalize to a single value."""
    if isinstance(value, list):
        return value[0] if value else None
    return value


import socket
import contextlib
import io
import sys


def get_domain_info(domain: str, timeout_seconds: float = 3.0) -> dict:
    """
    Look up registration age and registrar for a domain.
    Never raises -- returns an error marker dict on failure, since a
    single unresolvable/newly-created domain (often exactly the
    suspicious ones!) shouldn't crash the whole pipeline.
    """
    cache_key = f"whois:{domain}"
    cached = _domain_cache.get(cache_key)
    if cached is not None:
        return cached

    prev_timeout = socket.getdefaulttimeout()
    try:
        socket.setdefaulttimeout(timeout_seconds)
        # Suppress noisy third-party python-whois printouts ("Error trying to connect to socket...")
        with contextlib.redirect_stderr(io.StringIO()), contextlib.redirect_stdout(io.StringIO()):
            w = whois.whois(domain)
        creation_date = _first(w.creation_date)

        age_days = None
        if creation_date:
            if creation_date.tzinfo is None:
                creation_date = creation_date.replace(tzinfo=timezone.utc)
            age_days = (datetime.now(timezone.utc) - creation_date).days

        result = {
            "age_days": age_days,
            "registrar": _first(w.registrar),
            "creation_date": creation_date.isoformat() if creation_date else None,
            "country": _first(w.get("country")) if hasattr(w, "get") else None,
        }
    except Exception as e:
        # Common causes: domain doesn't exist, WHOIS server rate-limited us,
        # privacy-protected registration with no useful data, or socket timeout
        result = {"age_days": -1, "error": f"WHOIS lookup failed or timed out: {e}"}
    finally:
        socket.setdefaulttimeout(prev_timeout)

    _domain_cache.set(cache_key, result)
    return result
