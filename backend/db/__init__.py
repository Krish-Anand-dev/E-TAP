"""
db package -- persistence layer for the threat-email-platform.

Everything above this package (Stage F / correlation, and eventually
Stage G) talks to Mongo through `db.connection.get_db()` and the helper
functions in `db.repository`. Nothing outside this package should import
pymongo directly or know the collection names -- that's the whole point
of having a db layer.
"""

from .connection import get_db, set_db

__all__ = ["get_db", "set_db"]
