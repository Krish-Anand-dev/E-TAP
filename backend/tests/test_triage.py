"""
Unit tests for Feature 1: Stage C' XGBoost Metadata Triage
"""

import sys
import os
import unittest
import numpy as np

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ai_engine.triage_model import extract_features, predict_triage, FEATURE_NAMES


class TestTriageModel(unittest.TestCase):

    def test_extract_features_normal(self):
        email = {"subject": "Normal weekly status update", "body_text": "Here is the summary.", "from_email": "alice@company.com"}
        header_analysis = {"spf": {"result": "pass"}}
        attachment_analysis = {"attachments": []}
        iocs = {"urls": ["https://company.com/portal"]}
        threat_intel = {"domain_info": {"company.com": {"age_days": 1500}}}

        feats = extract_features(email, header_analysis, attachment_analysis, iocs, threat_intel)
        self.assertEqual(feats.shape, (1, 6))
        # has_attachment: 0, num_urls: 1, domain_age: 1500, spf_pass: 1, subject_len > 0, urgent: 0
        self.assertEqual(feats[0][0], 0.0)
        self.assertEqual(feats[0][1], 1.0)
        self.assertEqual(feats[0][2], 1500.0)
        self.assertEqual(feats[0][3], 1.0)
        self.assertEqual(feats[0][5], 0.0)

    def test_extract_features_defensive_edge_cases(self):
        # Empty/None dictionaries must never crash and domain age must default safely to -1
        feats = extract_features(None, None, None, None, None)
        self.assertEqual(feats.shape, (1, 6))
        self.assertEqual(feats[0][0], 0.0)  # has_attachment
        self.assertEqual(feats[0][1], 0.0)  # num_urls
        self.assertEqual(feats[0][2], -1.0) # sender_domain_age_days default -1
        self.assertEqual(feats[0][3], 0.0)  # auth_spf_pass
        self.assertEqual(feats[0][4], 0.0)  # subject_length
        self.assertEqual(feats[0][5], 0.0)  # is_urgent_keyword_present

    def test_extract_features_urgent_keyword(self):
        email = {"subject": "URGENT: Your account has been suspended", "body_text": "Please login immediately to verify."}
        feats = extract_features(email, {}, {}, {})
        self.assertEqual(feats[0][5], 1.0)  # urgent detected

    def test_predict_triage_runs(self):
        feats = np.array([[0.0, 0.0, 3000.0, 1.0, 30.0, 0.0]], dtype=np.float32)
        res = predict_triage(feats)
        self.assertIn("available", res)
        if res["available"]:
            self.assertIn("label", res)
            self.assertIn("confidence", res)
            self.assertIn("is_safe", res)
            self.assertIn(res["label"], [0, 1])
            self.assertGreaterEqual(res["confidence"], 0.0)
            self.assertLessEqual(res["confidence"], 1.0)


if __name__ == "__main__":
    unittest.main()
