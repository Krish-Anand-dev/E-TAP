"""
db.repository -- all reads/writes against Mongo live here.

`correlation.engine` (Stage F's matching/merging logic) and
`correlation.queries` (the "just show me the inventory" read API) are
both built entirely out of these functions. Nothing outside `db/`
should be constructing Mongo filters/updates directly -- that keeps the
collection names and document shapes defined in exactly one place
(`db.schema`).

Every function takes an explicit `db` argument rather than reaching for
`connection.get_db()` internally. Two reasons: it makes every function
trivially testable with a throwaway FakeDatabase, and it means nothing
in here silently depends on global state.
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Optional

from .fake_mongo import ReturnDocument as _FakeReturnDocument
from .schema import ANALYSES_COLLECTION, CAMPAIGNS_COLLECTION, COUNTERS_COLLECTION

try:
    from pymongo import ReturnDocument as _PymongoReturnDocument
except ImportError:
    _PymongoReturnDocument = None


def _return_document_after(db: Any) -> Any:
    """find_one_and_update's return_document sentinel differs between
    real pymongo and the fake backend; pick whichever one this db
    understands."""
    db = getattr(db, "_db", db)
    if _PymongoReturnDocument is not None:
        try:
            from pymongo.database import Database as _MongoDatabase
            if isinstance(db, _MongoDatabase):
                return _PymongoReturnDocument.AFTER
        except ImportError:
            pass
    return _FakeReturnDocument.AFTER


def _now() -> datetime:
    return datetime.now(timezone.utc)


# ---------------------------------------------------------------------------
# analyzed_emails
# ---------------------------------------------------------------------------

def find_analysis_by_message_id(db: Any, message_id: str) -> Optional[dict]:
    """Return an existing analysis with this message_id, if present."""
    if not message_id:
        return None
    return db[ANALYSES_COLLECTION].find_one({"message_id": message_id})


def insert_analysis(db: Any, doc: dict) -> str:
    """
    Insert (or, if `message_id` is set and already on file, update) an
    email's full analysis document. Returns the document's id as a str.

    Re-analyzing the same message_id (e.g. someone re-uploads the same
    .eml) updates the existing record in place instead of creating a
    duplicate entry / duplicate campaign membership.
    """
    collection = db[ANALYSES_COLLECTION]

    message_id = doc.get("message_id")
    if message_id:
        existing = collection.find_one({"message_id": message_id})
        if existing:
            collection.update_one(
                {"_id": existing["_id"]},
                {"$set": {k: v for k, v in doc.items() if k != "_id"}},
            )
            return str(existing["_id"])

    result = collection.insert_one(doc)
    return str(result.inserted_id)


def get_analysis(db: Any, email_id: str) -> Optional[dict]:
    """Fetch a single analyzed_emails document by its string id."""
    from bson import ObjectId
    collection = db[ANALYSES_COLLECTION]
    key = ObjectId(email_id) if ObjectId.is_valid(str(email_id)) else str(email_id)
    return collection.find_one({'_id': key}) or collection.find_one({'email_id': str(email_id)})


def update_analysis_fields(db: Any, email_id: str, fields: dict) -> bool:
    """Update selected fields on one analyzed email document."""
    doc = get_analysis(db, email_id)
    if doc is None:
        return False
    db[ANALYSES_COLLECTION].update_one(
        {"_id": doc["_id"]},
        {"$set": dict(fields)},
    )
    return True


def set_campaign_for_email(db: Any, email_id: str, campaign_id: str) -> None:
    doc = get_analysis(db, email_id)
    if doc is None:
        return
    db[ANALYSES_COLLECTION].update_one(
        {"_id": doc["_id"]}, {"$set": {"campaign_id": campaign_id}}
    )


VALID_IOC_TYPES = frozenset({"ips", "domains", "urls", "hashes"})


def find_by_ioc_exact(db: Any, ioc_type: str, values: list[str]) -> list[dict]:
    """
    Return every analyzed_emails document whose ioc_analysis[ioc_type]
    array contains at least one of `values`.

    ioc_type is strictly validated against VALID_IOC_TYPES to prevent field-injection.
    Values are sanitized to ensure no dict/operator injection occurs.
    """
    if ioc_type not in VALID_IOC_TYPES:
        raise ValueError(f"Invalid ioc_type: {ioc_type!r}")
    if not values:
        return []

    # Sanitize: ensure all values are strings, reject any non-scalar types (e.g. dict operators)
    clean_values = [str(v).strip() for v in values if isinstance(v, (str, int, float)) and str(v).strip()]
    if not clean_values:
        return []

    return list(db[ANALYSES_COLLECTION].find({f"ioc_analysis.{ioc_type}": {"$in": clean_values}}))


def get_all_domains(db: Any) -> list[str]:
    """Distinct domains seen across every stored analysis -- used as the
    comparison pool for fuzzy/typosquat matching."""
    return list(db[ANALYSES_COLLECTION].distinct("ioc_analysis.domains"))


def list_recent(db: Any, limit: int = 10) -> list[dict]:
    """Most recent analyses, newest first."""
    return list(db[ANALYSES_COLLECTION].find({}).sort("analyzed_at", -1).limit(limit))


def list_since(db: Any, since: datetime) -> list[dict]:
    """Every analysis performed at or after `since`, newest first."""
    return list(
        db[ANALYSES_COLLECTION]
        .find({"analyzed_at": {"$gte": since}})
        .sort("analyzed_at", -1)
    )


# ---------------------------------------------------------------------------
# campaigns
# ---------------------------------------------------------------------------

def next_campaign_id(db: Any) -> str:
    """
    Atomically hand out the next sequential campaign id
    ("campaign_001", "campaign_002", ...).

    Uses a single-document counter with $inc, which is atomic in real
    MongoDB (find_one_and_update on a single document is always
    atomic), so concurrent analyses won't hand out the same id.
    """
    doc = db[COUNTERS_COLLECTION].find_one_and_update(
        {"_id": "campaign_id"},
        {"$inc": {"seq": 1}},
        upsert=True,
        return_document=_return_document_after(db),
    )
    seq = doc["seq"]
    return f"campaign_{seq:03d}"


def create_campaign(
    db: Any,
    campaign_id: str,
    members: Optional[list[str]] = None,
    shared_infrastructure: Optional[list[str]] = None,
) -> dict:
    now = _now()
    doc = {
        "campaign_id": campaign_id,
        "members": list(members or []),
        "shared_infrastructure": list(shared_infrastructure or []),
        "merged_into": None,
        "created_at": now,
        "updated_at": now,
    }
    db[CAMPAIGNS_COLLECTION].insert_one(doc)
    return doc


def get_campaign(db: Any, campaign_id: str) -> Optional[dict]:
    return db[CAMPAIGNS_COLLECTION].find_one({"campaign_id": campaign_id})


def list_campaigns(db: Any, include_merged: bool = False, limit: int = 100) -> list[dict]:
    filt = {} if include_merged else {"merged_into": None}
    return list(db[CAMPAIGNS_COLLECTION].find(filt).sort("updated_at", -1).limit(limit))


def remove_member_from_campaign(db: Any, campaign_id: str, email_id: str) -> None:
    """Remove an email from a campaign's membership list."""
    db[CAMPAIGNS_COLLECTION].update_one(
        {"campaign_id": campaign_id},
        {"$pull": {"members": email_id}, "$set": {"updated_at": _now()}},
    )


def add_member_to_campaign(
    db: Any, campaign_id: str, email_id: str, new_shared_infra: list[str]
) -> None:
    db[CAMPAIGNS_COLLECTION].update_one(
        {"campaign_id": campaign_id},
        {
            "$addToSet": {
                "members": email_id,
                "shared_infrastructure": {"$each": list(new_shared_infra)},
            },
            "$set": {"updated_at": _now()},
        },
    )


def merge_campaigns(db: Any, primary_id: str, absorbed_ids: list[str]) -> dict:
    """
    Fold one or more existing campaigns into `primary_id`.

    Every analyzed_emails document currently pointing at an absorbed
    campaign gets repointed at the primary campaign, the primary
    campaign's members/shared_infrastructure absorb the merged-in
    campaigns' values, and each absorbed campaign document is marked
    `merged_into: primary_id` (kept around rather than deleted, so
    there's an audit trail of what got folded into what).

    Returns the updated primary campaign document.
    """
    primary = get_campaign(db, primary_id)
    if primary is None:
        primary = create_campaign(db, primary_id)

    all_members = set(primary.get("members", []))
    all_infra = set(primary.get("shared_infrastructure", []))

    for absorbed_id in absorbed_ids:
        if absorbed_id == primary_id:
            continue

        absorbed = get_campaign(db, absorbed_id)
        if absorbed is None:
            continue

        all_members.update(absorbed.get("members", []))
        all_infra.update(absorbed.get("shared_infrastructure", []))

        for doc in db[ANALYSES_COLLECTION].find({"campaign_id": absorbed_id}):
            db[ANALYSES_COLLECTION].update_one(
                {"_id": doc["_id"]}, {"$set": {"campaign_id": primary_id}}
            )

        db[CAMPAIGNS_COLLECTION].update_one(
            {"campaign_id": absorbed_id},
            {"$set": {"merged_into": primary_id, "updated_at": _now()}},
        )

    db[CAMPAIGNS_COLLECTION].update_one(
        {"campaign_id": primary_id},
        {
            "$set": {
                "members": sorted(all_members),
                "shared_infrastructure": sorted(all_infra),
                "updated_at": _now(),
            }
        },
        upsert=True,
    )

    return get_campaign(db, primary_id)
