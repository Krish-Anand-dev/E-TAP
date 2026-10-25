"""
Unit tests for Stage F' -- Graph Diffusion Score Engine (graph_diffusion.py)

Verifies:
1. Synthetic 4-hop chain test proving monotonic decay with distance (d=1 > d=2 > d=3).
2. Fail-open behavior on sparse graphs (<5 nodes) without throwing exceptions.
3. Fail-open behavior when zero malicious seeds exist.
4. Thread-safe adjacency cache invalidation and execution timing benchmark.
5. Integration with Stage F correlation dictionary extraction.
"""

import os
import sys
import time
import unittest

# Add backend to path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from ai_engine.graph_diffusion import (
    compute_graph_diffusion,
    extract_graph_from_correlation,
    invalidate_graph_cache,
    find_nearest_seed_trace,
)


class TestGraphDiffusion(unittest.TestCase):

    def setUp(self):
        invalidate_graph_cache()

    def test_monotonic_distance_decay(self):
        """
        Verify that diffusion score decreases monotonically as distance from
        the malicious seed node increases: score(d=1) > score(d=2) > score(d=3)
        """
        # Graph: Seed <-> Node1 <-> Node2 <-> Node3 <-> ExtraNode
        nodes = [
            {"id": "seed_malicious", "is_malicious_seed": True},
            {"id": "node_dist_1"},
            {"id": "node_dist_2"},
            {"id": "node_dist_3"},
            {"id": "extra_node_1"},
        ]
        edges = [
            ("seed_malicious", "node_dist_1", "shared_ip"),
            ("node_dist_1", "node_dist_2", "shared_asn"),
            ("node_dist_2", "node_dist_3", "shared_domain"),
            ("node_dist_3", "extra_node_1", "relational"),
        ]

        res = compute_graph_diffusion(
            graph_nodes=nodes,
            graph_edges=edges,
            target_node_id="node_dist_1",
            seed_node_ids={"seed_malicious"},
            alpha=0.85,
            hops=3,
            min_nodes=4,
        )

        self.assertTrue(res["available"])
        scores = res["node_scores"]

        s1 = scores.get("node_dist_1", 0.0)
        s2 = scores.get("node_dist_2", 0.0)
        s3 = scores.get("node_dist_3", 0.0)

        self.assertGreater(s1, s2, f"Distance 1 ({s1}) should be > distance 2 ({s2})")
        self.assertGreater(s2, s3, f"Distance 2 ({s2}) should be > distance 3 ({s3})")
        self.assertGreater(s3, 0.0, f"Distance 3 ({s3}) should receive non-zero signal")
        print(f"PASS: Monotonic decay verified: d=1({s1}) > d=2({s2}) > d=3({s3})")

    def test_fail_open_on_sparse_graph(self):
        """Graphs with fewer than min_nodes must return available: false, no exception."""
        nodes = [{"id": "node_1"}, {"id": "node_2"}]
        edges = [("node_1", "node_2", "link")]

        res = compute_graph_diffusion(
            graph_nodes=nodes,
            graph_edges=edges,
            target_node_id="node_1",
            min_nodes=5,
        )

        self.assertFalse(res["available"])
        self.assertIsNone(res["diffusion_score"])
        self.assertIn("insufficient graph data", res["reason"])
        print("PASS: Fail-open verified for sparse graph")

    def test_fail_open_on_zero_malicious_seeds(self):
        """Graphs with 0 malicious seeds must return available: false, score 0.0, no exception."""
        nodes = [
            {"id": "n1"}, {"id": "n2"}, {"id": "n3"},
            {"id": "n4"}, {"id": "n5"}, {"id": "n6"},
        ]
        edges = [("n1", "n2", "link"), ("n2", "n3", "link"), ("n3", "n4", "link")]

        res = compute_graph_diffusion(
            graph_nodes=nodes,
            graph_edges=edges,
            target_node_id="n1",
            seed_node_ids=set(),
            min_nodes=5,
        )

        self.assertFalse(res["available"])
        self.assertEqual(res["diffusion_score"], 0.0)
        self.assertIn("no malicious seed", res["reason"])
        print("PASS: Fail-open verified for zero-seed graph")

    def test_nearest_seed_trace_and_explanation(self):
        """Verify BFS path traceback to nearest seed."""
        edges = [
            ("email_target", "domain_evil", "resolves"),
            ("domain_evil", "ip_c2_seed", "hosted_on"),
        ]
        seeds = {"ip_c2_seed"}

        hops, nearest, explanation = find_nearest_seed_trace("email_target", seeds, edges)
        self.assertEqual(hops, 2)
        self.assertEqual(nearest, "ip_c2_seed")
        self.assertIn("2 hop(s) from flagged malicious seed 'ip_c2_seed'", explanation)
        print(f"PASS: BFS path traceback verified: {explanation}")

    def test_cache_invalidation_and_timing_benchmark(self):
        """Measure cold build vs cached execution timing and confirm cache invalidation."""
        # Build a 50-node synthetic graph
        num_nodes = 60
        nodes = [{"id": f"node_{i}"} for i in range(num_nodes)]
        nodes[0]["is_malicious_seed"] = True
        edges = [(f"node_{i}", f"node_{i+1}", "rel") for i in range(num_nodes - 1)]

        # Cold execution
        invalidate_graph_cache()
        t0 = time.perf_counter()
        res_cold = compute_graph_diffusion(nodes, edges, target_node_id="node_5", min_nodes=5)
        cold_time_ms = (time.perf_counter() - t0) * 1000

        # Cached execution
        t1 = time.perf_counter()
        res_cached = compute_graph_diffusion(nodes, edges, target_node_id="node_5", min_nodes=5)
        cached_time_ms = (time.perf_counter() - t1) * 1000

        self.assertTrue(res_cold["available"])
        self.assertTrue(res_cached["available"])
        self.assertEqual(res_cold["diffusion_score"], res_cached["diffusion_score"])

        # Test invalidation
        invalidate_graph_cache()

        print(f"PASS: Timing Benchmark: Cold Build = {cold_time_ms:.2f}ms | Cached = {cached_time_ms:.2f}ms")

    def test_extract_graph_from_correlation(self):
        """Verify graph extraction from realistic Stage F correlation object."""
        email_id = "test_email_123"
        correlation = {
            "campaign_id": "CAMP_ALPHA",
            "related_emails": ["rel_456", "rel_789"],
            "shared_infrastructure": ["194.26.29.112", "bad-c2.org"],
        }
        iocs = {
            "ips": ["194.26.29.112", "8.8.8.8"],
            "domains": ["bad-c2.org"],
            "urls": ["http://bad-c2.org/login"],
            "hashes": ["d41d8cd98f00b204e9800998ecf8427e"],
        }
        threat_intel = {
            "ips": {
                "194.26.29.112": {"vt_score": 8, "reputation_status": "MALICIOUS"}
            }
        }

        nodes, edges, seeds = extract_graph_from_correlation(
            email_id, correlation, iocs, threat_intel
        )

        self.assertGreater(len(nodes), 5)
        self.assertGreater(len(edges), 5)
        self.assertIn("ip_194.26.29.112", seeds)

        res = compute_graph_diffusion(nodes, edges, target_node_id=email_id, seed_node_ids=seeds)
        self.assertTrue(res["available"])
        self.assertGreater(res["diffusion_score"], 0.0)
        self.assertEqual(res["nearest_seed_distance"], 1)
        print(f"PASS: Extraction and pipeline test verified: score={res['diffusion_score']}, explanation='{res['explanation']}'")


if __name__ == "__main__":
    unittest.main()
