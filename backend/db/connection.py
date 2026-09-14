"""
db.connection -- gets you a database handle, real or fake.

Usage (production, once Mongo is actually running somewhere):
    export MONGODB_URI="mongodb://localhost:27017/phishing-investigator"

    from db.connection import get_db
    db = get_db()

Usage (local dev / tests, before Mongo is set up, or in CI without a
Mongo server):
    export USE_FAKE_DB=1

    from db.connection import get_db
    db = get_db()   # returns an in-memory FakeDatabase, same call sites work

The fake backend (`db.fake_mongo.FakeDatabase`) implements the small
subset of the pymongo Collection/Cursor API that `db.repository` and
`correlation.engine` actually use (find/find_one/insert_one/update_one/
find_one_and_update/count_documents/distinct/create_index, plus $in,
$gte, $lte, $set, $inc, $addToSet/$each). It is NOT a general pymongo
replacement and it is NOT persistent (everything lives in a plain Python
dict and is gone when the process exits) -- it exists purely so the rest
of the pipeline is runnable and testable before you've stood up a real
Mongo instance or in an environment without network access to one.

Swap to a real MongoDB the moment you have a connection string: just
unset USE_FAKE_DB (or don't set it) and set MONGODB_URI. No other code
in db/ or correlation/ needs to change.
"""

from __future__ import annotations

import os
from typing import Any, Optional

_db: Optional[Any] = None


def get_db() -> Any:
    """
    Return the shared database handle, creating it on first use.

    Returns a real pymongo Database if MONGO_URI/pymongo are available
    and USE_FAKE_DB isn't set; otherwise returns an in-memory
    FakeDatabase. The returned object exposes db[collection_name] just
    like pymongo does, so calling code never needs to know which one
    it got.
    """
    global _db
    if _db is not None:
        return _db

    if os.environ.get("USE_FAKE_DB") == "1":
        from .fake_mongo import FakeDatabase
        _db = FakeDatabase()
        return _db

    try:
        from pymongo import MongoClient
    except ImportError as exc:
        raise RuntimeError(
            "pymongo is not installed, so a real MongoDB connection can't be "
            "made. Run `pip install pymongo`, or set USE_FAKE_DB=1 to use the "
            "in-memory fallback for local development/testing."
        ) from exc

    uri = (
        os.environ.get("MONGODB_URI")
        or os.environ.get("MONGO_URI")
        or "mongodb://localhost:27017"
    )

    db_name = os.environ.get("MONGO_DB_NAME")
    if not db_name:
        try:
            from urllib.parse import urlparse
            path = urlparse(uri).path.strip("/")
            if path:
                db_name = path.split("?")[0]
        except Exception:
            db_name = None
    db_name = db_name or "phishing-investigator"

    try:
        client = MongoClient(uri, serverSelectionTimeoutMS=5000)
        # Verify connection with an active ping
        client.admin.command("ping")
        _db = client[db_name]
        from . import schema
        schema.ensure_indexes(_db)
        sanitized_host = uri.split("@")[-1] if "@" in uri else uri
        print(f"[MongoDB] Connected successfully to database '{db_name}' on {sanitized_host.split('?')[0]}")
    except Exception as exc:
        is_atlas = "mongodb+srv" in uri or ".mongodb.net" in uri
        sanitized_host = uri.split("@")[-1] if "@" in uri else uri
        print(f"[MongoDB Connection Error] Failed to connect to {sanitized_host.split('?')[0]}: {exc}")
        if is_atlas:
            print("[MongoDB Atlas Diagnostic Guidance]")
            print("  1. Verify IP whitelist in MongoDB Atlas: Network Access -> Add IP Address -> Add Current IP Address (or 0.0.0.0/0).")
            print("  2. Verify your Database User credentials in MONGODB_URI.")
            print("  3. Ensure special characters in password are URL-encoded (e.g. @ -> %40, # -> %23).")
        if os.environ.get("AUTO_FALLBACK_DB") == "1":
            print("[MongoDB] AUTO_FALLBACK_DB=1 is set. Falling back to in-memory FakeDatabase.")
            from .fake_mongo import FakeDatabase
            _db = FakeDatabase()
            return _db
        raise exc

    return _db


def set_db(db: Any) -> None:
    """
    Test hook: force get_db() to return a specific object from now on
    (e.g. a mongomock database, or a fresh FakeDatabase for test
    isolation). Not meant to be called from application code.
    """
    global _db
    _db = db


def reset_db() -> None:
    """Test hook: forget the cached handle so the next get_db() call
    re-reads env vars and reconnects/re-creates from scratch."""
    global _db
    _db = None
