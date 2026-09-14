"""
Backfill script for generating RAG vector embeddings on historical investigations in MongoDB.
Usage:
    python backend/rag/backfill_embeddings.py
"""

import os
import sys

# Ensure backend root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from dotenv import load_dotenv
load_dotenv(os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env")))
load_dotenv()

from db.connection import get_db
from rag.embeddings import build_summary, embed_text


def backfill(force: bool = False):
    db = get_db()
    collection = db["analyzed_emails"] if db["analyzed_emails"].find_one() else db["emails"]

    query = {} if force else {
        "$or": [
            {"rag_embedding": {"$exists": False}},
            {"rag_embedding": None},
            {"rag_summary": {"$exists": False}},
            {"rag_summary": None},
            {"rag_summary": {"$not": {"$regex": "MITRE ATT&CK"}}},
        ]
    }
    cursor = collection.find(query)
    docs = list(cursor)

    print(f"[*] Found {len(docs)} investigation document(s) needing vector embeddings / refresh.")
    if not docs:
        print("[+] All database records already indexed with fresh vector embeddings.")
        return

    updated = 0
    for doc in docs:
        email_id = doc.get("email_id") or str(doc.get("_id"))
        summary = build_summary(doc)
        vector = embed_text(summary)

        collection.update_one(
            {"_id": doc["_id"]},
            {"$set": {"rag_summary": summary, "rag_embedding": vector}},
        )
        updated += 1
        print(f"  [+] Indexed {email_id} ({updated}/{len(docs)})")

    print(f"\n[+] Successfully backfilled {updated} investigation records with RAG embeddings.")


if __name__ == "__main__":
    backfill()
