"""
db.schema -- collection names and index definitions.

Mongo is schemaless, so this file isn't enforcing a schema in the SQL
sense -- it's just the one place that names the collections and the
indexes they need, so `db.repository` and `correlation.engine` aren't
sprinkling magic strings everywhere.

Collections
-----------
analyzed_emails
    One document per analyzed email. Roughly:
    {
        "_id": ObjectId(...),
        "message_id": "<abc123@mail.example.com>" | None,
        "subject": "...",
        "from_email": "...",
        "to_email": "..." | None,
        "email_date": "..." | None,
        "source_format": "eml" | "msg" | None,
        "analyzed_at": datetime,
        "header_analysis": {...} | None,        # Stage B output
        "attachment_analysis": {...} | None,     # Stage B2 output
        "threat_intel_analysis": {...} | None,       # Stage E output
        "content_analysis": {...} | None,            # Stage G level-1 result
        "final_assessment": {...} | None,            # Stage G level-2 result
        "mitre_attack": [...],
        "risk_score": 91,
        "verdict": "HIGH-RISK PHISHING",
        "ioc_analysis": {                        # Stage D output
            "ips": [...], "domains": [...], "urls": [...], "hashes": [...]
        },
        "campaign_id": "campaign_003",
    }

campaigns
    One document per correlated group of emails.
    {
        "_id": ObjectId(...),
        "campaign_id": "campaign_003",
        "members": ["<email_id str>", ...],
        "shared_infrastructure": ["185.x.x.x", "fake-bank.com", ...],
        "merged_into": None | "campaign_001",   # set if this campaign
                                                  # was absorbed into
                                                  # another one; kept
                                                  # around for audit
                                                  # rather than deleted
        "created_at": datetime,
        "updated_at": datetime,
    }

counters
    Single-purpose collection used to hand out sequential, human-
    readable campaign IDs ("campaign_001", "campaign_002", ...) via an
    atomic $inc.
    { "_id": "campaign_id", "seq": 7 }
"""

from __future__ import annotations

from typing import Any

ANALYSES_COLLECTION = "analyzed_emails"
CAMPAIGNS_COLLECTION = "campaigns"
COUNTERS_COLLECTION = "counters"


def ensure_indexes(db: Any) -> None:
    """
    Create the indexes this platform relies on. Idempotent -- safe to
    call every time a connection is established (MongoDB no-ops if the
    index already exists with the same spec).

    Skipped entirely for the in-memory FakeDatabase, which doesn't need
    indexes and doesn't implement create_index beyond a no-op stub.
    """
    analyses = db[ANALYSES_COLLECTION]
    # NOTE: the compound (owner_id, ...) indexes below are legacy. owner_id is no longer written,
    # so they behave like plain unique message_id / campaign_id indexes. Kept as-is so existing
    # Atlas deployments do not need an index migration.
    analyses.create_index([("owner_id", 1), ("message_id", 1)], unique=True, partialFilterExpression={"message_id": {"$type": "string"}}, name="owner_message")
    analyses.create_index("analyzed_at")
    analyses.create_index("campaign_id")
    analyses.create_index("ioc_analysis.ips")
    analyses.create_index("ioc_analysis.domains")
    analyses.create_index("ioc_analysis.urls")
    analyses.create_index("ioc_analysis.hashes")

    campaigns = db[CAMPAIGNS_COLLECTION]
    campaigns.create_index([("owner_id", 1), ("campaign_id", 1)], unique=True, name="owner_campaign")
    campaigns.create_index("merged_into")
