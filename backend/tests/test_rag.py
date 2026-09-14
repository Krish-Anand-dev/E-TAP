"""
Unit tests for Feature 3: RAG (Embeddings, Vector Search, and SOC Assistant Chat)
"""

import sys
import os
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from rag.embeddings import build_summary, embed_text
from rag.chat import search_similar_investigations, answer_query


class MockCollection:
    def __init__(self, docs):
        self._docs = docs

    def find(self, *args, **kwargs):
        return iter(self._docs)

    def find_one(self, *args, **kwargs):
        return self._docs[0] if self._docs else None


class MockDB:
    def __init__(self, docs):
        self._collection = MockCollection(docs)

    def __getitem__(self, name):
        return self._collection


class TestRAG(unittest.TestCase):

    def setUp(self):
        self.doc1 = {
            "email_id": "incident_001",
            "verdict": "PHISHING",
            "risk_score": 88,
            "email": {
                "subject": "URGENT: Payroll Verification Required",
                "from_email": "hr-payroll@spoofed-bank.com",
            },
            "correlation": {"campaign_id": "campaign_finance_01"},
            "iocs": {
                "ips": ["198.51.100.22"],
                "domains": ["spoofed-bank.com"],
                "urls": ["http://spoofed-bank.com/login"],
            },
            "mitre_attack": [{"technique_name": "Spearphishing Link"}],
            "ai_analysis": {
                "final_assessment": {
                    "explanation": "High-risk credential harvesting campaign targeting employee payroll."
                }
            },
        }
        self.doc2 = {
            "email_id": "incident_002",
            "verdict": "Likely Legitimate",
            "risk_score": 5,
            "email": {
                "subject": "Weekly Engineering Sync Minutes",
                "from_email": "dan@company.internal",
            },
            "correlation": {"campaign_id": "None"},
            "iocs": {"ips": ["10.0.0.1"], "domains": ["company.internal"], "urls": []},
            "mitre_attack": [],
            "ai_analysis": {
                "final_assessment": {
                    "explanation": "Routine internal meeting notes."
                }
            },
        }

    def test_build_summary(self):
        summary = build_summary(self.doc1)
        self.assertIn("incident_001", summary)
        self.assertIn("PHISHING", summary)
        self.assertIn("spoofed-bank.com", summary)
        self.assertIn("Spearphishing Link", summary)

    def test_embed_text(self):
        vec = embed_text("URGENT: Payroll Verification")
        self.assertIsInstance(vec, list)
        self.assertEqual(len(vec), 384)
        self.assertTrue(all(isinstance(x, float) for x in vec))

    def test_search_similar_investigations(self):
        # Attach pre-computed embeddings
        self.doc1["rag_summary"] = build_summary(self.doc1)
        self.doc1["rag_embedding"] = embed_text(self.doc1["rag_summary"])

        self.doc2["rag_summary"] = build_summary(self.doc2)
        self.doc2["rag_embedding"] = embed_text(self.doc2["rag_summary"])

        mock_db = MockDB([self.doc1, self.doc2])
        results = search_similar_investigations("payroll banking credentials", mock_db, limit=2)
        self.assertEqual(len(results), 2)
        # Incident 1 (payroll phish) should rank higher than incident 2 (engineering sync)
        self.assertEqual(results[0]["email_id"], "incident_001")
        self.assertGreater(results[0]["similarity"], results[1]["similarity"])

    def test_answer_query(self):
        self.doc1["rag_summary"] = build_summary(self.doc1)
        self.doc1["rag_embedding"] = embed_text(self.doc1["rag_summary"])
        mock_db = MockDB([self.doc1])

        res = answer_query("Did we see any payroll phishing emails?", mock_db)
        self.assertIn("answer", res)
        self.assertIn("sources", res)
        self.assertEqual(res["retrieved_count"], 1)
        self.assertEqual(res["sources"][0]["email_id"], "incident_001")


if __name__ == "__main__":
    unittest.main()
