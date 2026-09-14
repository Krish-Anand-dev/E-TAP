"""
Tiny in-memory cache for threat-intel lookups.

Exists specifically to protect VirusTotal's free tier (4 requests/min,
500/day) -- the same IOC can easily show up across multiple test emails
during development, and re-querying it every time burns quota for
nothing. Not persisted to disk; resets each time the process restarts,
which is fine for a hackathon demo but worth knowing.
"""

from __future__ import annotations
import time
from typing import Any


class TTLCache:
    def __init__(self, ttl_seconds: int = 3600):
        self._store: dict[str, tuple[float, Any]] = {}
        self._ttl = ttl_seconds

    def get(self, key: str) -> Any | None:
        entry = self._store.get(key)
        if entry is None:
            return None
        expires_at, value = entry
        if time.time() > expires_at:
            del self._store[key]
            return None
        return value

    def set(self, key: str, value: Any) -> None:
        self._store[key] = (time.time() + self._ttl, value)
