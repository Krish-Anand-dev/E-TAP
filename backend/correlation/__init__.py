"""
correlation package -- Stage F.

`engine.correlate_and_store(...)` is the one function the rest of the
pipeline calls: give it Stage D's ioc_analysis (plus whatever metadata
and earlier-stage results you have), and it compares against everything
already stored, assigns/creates a campaign, stores the new email's
record, and tells you what it found.

`queries` is a separate, read-only surface for the dashboard -- "what's
in the database" questions that have nothing to do with processing a
new email (recent analyses, analyses in a date range, everything that
shares a given IP/domain, campaign listings/detail).
"""

from .engine import correlate_and_store
from . import queries

__all__ = ["correlate_and_store", "queries"]
