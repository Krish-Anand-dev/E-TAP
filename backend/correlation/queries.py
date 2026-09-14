"""
correlation.queries -- read-only "what's in the inventory" API.

This is deliberately separate from `engine.correlate_and_store`: nothing
in this file ever writes to the database. It exists for the dashboard
(Stage H, via Stage G's API) to ask questions like "show me the last 10
analyses", "show me everything from this week", "show me every email
that shared this IP/domain", and "show me this campaign's full detail" --
none of which have anything to do with processing a new email.

Every function returns plain dicts/lists (Mongo _id fields are
stringified) so this is safe to json.dumps directly for an API
response.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
from typing import Any, Optional

from db import connection, repository


def _serialize_analysis(doc: dict) -> dict:
    doc = dict(doc)
    doc["_id"] = str(doc["_id"])
    return doc


def _serialize_campaign(doc: dict) -> dict:
    doc = dict(doc)
    doc["_id"] = str(doc["_id"])
    return doc


def recent_analyses(limit: int = 10, db: Optional[Any] = None) -> list[dict]:
    """The last `limit` analyses, newest first. ("show past 10 analyses")"""
    db = db if db is not None else connection.get_db()
    return [_serialize_analysis(d) for d in repository.list_recent(db, limit=limit)]


def analyses_in_last_days(days: int = 7, db: Optional[Any] = None) -> list[dict]:
    """Every analysis performed in the last `days` days, newest first.
    ("show past analysis this week" -> analyses_in_last_days(7))"""
    db = db if db is not None else connection.get_db()
    since = datetime.now(timezone.utc) - timedelta(days=days)
    return [_serialize_analysis(d) for d in repository.list_since(db, since)]


def analyses_since(since: datetime, db: Optional[Any] = None) -> list[dict]:
    """Every analysis performed at or after an arbitrary timestamp."""
    db = db if db is not None else connection.get_db()
    return [_serialize_analysis(d) for d in repository.list_since(db, since)]


def analyses_by_ioc(ioc_type: str, value: str, db: Optional[Any] = None) -> list[dict]:
    """
    Every email whose IOC list contains this exact value.

    ioc_type is one of "ips", "domains", "urls", "hashes".
    ("show me all emails that had this IP/domain")
    """
    db = db if db is not None else connection.get_db()
    if ioc_type not in ("ips", "domains", "urls", "hashes"):
        raise ValueError(f"Unknown ioc_type: {ioc_type!r}")
    return [_serialize_analysis(d) for d in repository.find_by_ioc_exact(db, ioc_type, [value])]


def list_campaigns(
    include_merged: bool = False, limit: int = 100, db: Optional[Any] = None
) -> list[dict]:
    """Overview of every campaign, most recently updated first."""
    db = db if db is not None else connection.get_db()
    return [
        _serialize_campaign(c)
        for c in repository.list_campaigns(db, include_merged=include_merged, limit=limit)
    ]


def campaign_detail(campaign_id: str, db: Optional[Any] = None) -> Optional[dict]:
    """
    Full detail for one campaign: the campaign document plus the full
    analysis record for every member email.
    """
    db = db if db is not None else connection.get_db()
    campaign = repository.get_campaign(db, campaign_id)
    if campaign is None:
        return None

    members = [
        _serialize_analysis(doc)
        for member_id in campaign.get("members", [])
        if (doc := repository.get_analysis(db, member_id)) is not None
    ]

    result = _serialize_campaign(campaign)
    result["member_analyses"] = members
    return result
