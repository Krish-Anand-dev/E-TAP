"""
Stage F' -- Graph Diffusion Score Engine
Owner: Threat Intelligence & Correlation

Implements Label Propagation / Graph Diffusion using Personalized PageRank over
the Threat Graph topology.

Spreads known-malicious seed signal (from Stage E Threat Intelligence) outward
across multi-hop relational edges (IPs, domains, hashes, campaigns) via a
symmetrically normalized adjacency matrix.

Pure NumPy and SciPy (scipy.sparse) -- no PyTorch, no CUDA, no external APIs.
Guaranteed strictly fail-open: errors or sparse data return available: false
without failing the analysis pipeline.
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional, Set, Tuple

import numpy as np
import scipy.sparse as sp

logger = logging.getLogger("graph_diffusion")

# =====================================================================
# Configurable Thresholds & Hyperparameters (via Environment Variables)
# =====================================================================
SEED_VT_THRESHOLD = int(os.getenv("SEED_VT_THRESHOLD", "3"))
SEED_ABUSEIPDB_THRESHOLD = int(os.getenv("SEED_ABUSEIPDB_THRESHOLD", "50"))
DIFFUSION_ALPHA = float(os.getenv("DIFFUSION_ALPHA", "0.85"))
DIFFUSION_HOPS = int(os.getenv("DIFFUSION_HOPS", "3"))
DIFFUSION_MIN_NODES = int(os.getenv("DIFFUSION_MIN_NODES", "5"))

# =====================================================================
# Thread-safe Adjacency Cache
# =====================================================================
_cache_lock = threading.Lock()
_cached_fingerprint: Optional[str] = None
_cached_normalized_adj: Optional[sp.csr_matrix] = None
_cached_node_to_idx: Optional[Dict[str, int]] = None
_cached_nodes_list: Optional[List[str]] = None


def invalidate_graph_cache() -> None:
    """Invalidate precomputed adjacency cache when Stage F writes new correlation data."""
    global _cached_fingerprint, _cached_normalized_adj, _cached_node_to_idx, _cached_nodes_list
    with _cache_lock:
        _cached_fingerprint = None
        _cached_normalized_adj = None
        _cached_node_to_idx = None
        _cached_nodes_list = None
        logger.debug("[GraphDiffusion] Adjacency cache invalidated.")


def build_symmetric_normalized_adjacency(
    nodes: List[str], edges: List[Tuple[str, str, str]]
) -> Tuple[sp.csr_matrix, Dict[str, int]]:
    """
    Constructs the symmetrically normalized adjacency matrix with self-loops:
    A_norm = D_tilde^(-1/2) @ A_tilde @ D_tilde^(-1/2), where A_tilde = A + I
    Uses scipy.sparse for efficient O(E) sparse matrix operations.
    """
    n = len(nodes)
    node_to_idx = {node: i for i, node in enumerate(nodes)}

    rows: List[int] = []
    cols: List[int] = []
    data: List[float] = []

    # Undirected / bidirectional relationships
    for u, v, _label in edges:
        if u in node_to_idx and v in node_to_idx:
            i, j = node_to_idx[u], node_to_idx[v]
            rows.extend([i, j])
            cols.extend([j, i])
            data.extend([1.0, 1.0])

    # A + I (self-loops)
    rows.extend(range(n))
    cols.extend(range(n))
    data.extend([1.0] * n)

    a_tilde = sp.csr_matrix((data, (rows, cols)), shape=(n, n), dtype=np.float64)

    # Degree vector: d_i = sum_j a_tilde_ij
    deg = np.array(a_tilde.sum(axis=1)).flatten()
    deg[deg <= 0.0] = 1.0
    deg_inv_sqrt = 1.0 / np.sqrt(deg)

    # D_inv_sqrt @ A_tilde @ D_inv_sqrt
    d_mat = sp.diags(deg_inv_sqrt, format="csr")
    a_norm = d_mat.dot(a_tilde).dot(d_mat)

    return a_norm, node_to_idx


def _get_or_build_adjacency(
    nodes: List[str], edges: List[Tuple[str, str, str]]
) -> Tuple[sp.csr_matrix, Dict[str, int]]:
    """Retrieves cached normalized adjacency or computes it if cache is stale."""
    global _cached_fingerprint, _cached_normalized_adj, _cached_node_to_idx, _cached_nodes_list

    import hashlib
    import json
    from security import principal
    fingerprint = hashlib.sha256(json.dumps([principal.get(), nodes, edges], sort_keys=True).encode()).hexdigest()

    with _cache_lock:
        if (
            _cached_fingerprint == fingerprint
            and _cached_normalized_adj is not None
            and _cached_node_to_idx is not None
        ):
            return _cached_normalized_adj, _cached_node_to_idx

    # Build outside the lock to keep concurrent readers unblocked
    a_norm, node_to_idx = build_symmetric_normalized_adjacency(nodes, edges)

    with _cache_lock:
        _cached_fingerprint = fingerprint
        _cached_normalized_adj = a_norm
        _cached_node_to_idx = node_to_idx
        _cached_nodes_list = nodes

    return a_norm, node_to_idx


def find_nearest_seed_trace(
    target_node: str,
    seed_nodes: Set[str],
    edges: List[Tuple[str, str, str]],
    max_hops: int = 4,
) -> Tuple[Optional[int], Optional[str], Optional[str]]:
    """
    Breadth-First Search (BFS) to find the shortest path and edge types from
    the target node to any malicious seed node.
    Returns: (distance_in_hops, nearest_seed_id, explanation_str)
    """
    if target_node in seed_nodes:
        return 0, target_node, "Target node is itself an identified malicious seed"

    # Build adjacency list with edge labels: node -> [(neighbor, label)]
    adj: Dict[str, List[Tuple[str, str]]] = {}
    for u, v, label in edges:
        adj.setdefault(u, []).append((v, label))
        adj.setdefault(v, []).append((u, label))

    queue: List[Tuple[str, int, List[str]]] = [(target_node, 0, [])]
    visited: Set[str] = {target_node}

    while queue:
        curr, dist, path_labels = queue.pop(0)
        if dist >= max_hops:
            continue

        for neighbor, label in adj.get(curr, []):
            if neighbor in seed_nodes:
                hops = dist + 1
                edge_desc = ", ".join(path_labels + [label]) if (path_labels or label) else "relational link"
                explanation = f"{hops} hop(s) from flagged malicious seed '{neighbor}' via [{edge_desc}]"
                return hops, neighbor, explanation

            if neighbor not in visited:
                visited.add(neighbor)
                queue.append((neighbor, dist + 1, path_labels + [label]))

    return None, None, None


def compute_graph_diffusion(
    graph_nodes: List[Dict[str, Any]],
    graph_edges: List[Tuple[str, str, str]],
    target_node_id: str,
    seed_node_ids: Optional[Set[str]] = None,
    alpha: float = DIFFUSION_ALPHA,
    hops: int = DIFFUSION_HOPS,
    min_nodes: int = DIFFUSION_MIN_NODES,
) -> Dict[str, Any]:
    """
    Execute Personalized PageRank graph diffusion over the provided graph topology.

    Args:
        graph_nodes: List of dicts representing nodes (id, type, label, etc.)
        graph_edges: List of tuples (source_id, target_id, relation_label)
        target_node_id: ID of the primary node being scored (e.g. current email_id)
        seed_node_ids: Pre-identified set of malicious seed node IDs. If None, detected from nodes.
        alpha: Propagation retention coefficient (default 0.85).
        hops: Number of diffusion iterations (default 3).
        min_nodes: Minimum nodes required for statistically meaningful diffusion.

    Returns:
        Structured additive dict with diffusion score, contributing seeds, and trace explanation.
    """
    try:
        node_ids = [n["id"] if isinstance(n, dict) else str(n) for n in graph_nodes]

        # Fail-open check 1: Insufficient nodes in graph
        if len(node_ids) < min_nodes:
            return {
                "available": False,
                "diffusion_score": None,
                "reason": f"insufficient graph data (found {len(node_ids)} nodes, minimum {min_nodes} required)",
                "hops_used": hops,
                "nearest_seed_distance": None,
                "contributing_seeds": [],
                "node_scores": {},
                "explanation": "Threat graph has insufficient connected nodes for graph diffusion.",
            }

        # Resolve malicious seed indicators
        if seed_node_ids is None:
            seed_node_ids = set()
            for n in graph_nodes:
                if isinstance(n, dict):
                    # Check threat intel flags or seed indicators
                    is_seed = (
                        n.get("is_malicious_seed", False)
                        or (n.get("vt_score", 0) >= SEED_VT_THRESHOLD)
                        or (n.get("abuse_score", 0) >= SEED_ABUSEIPDB_THRESHOLD)
                        or (n.get("reputation_status") == "MALICIOUS")
                    )
                    if is_seed:
                        seed_node_ids.add(n["id"])

        # Fail-open check 2: No malicious seeds to propagate from
        if not seed_node_ids:
            return {
                "available": False,
                "diffusion_score": 0.0,
                "reason": "no malicious seed indicators in threat graph",
                "hops_used": hops,
                "nearest_seed_distance": None,
                "contributing_seeds": [],
                "node_scores": {nid: 0.0 for nid in node_ids},
                "explanation": "No confirmed malicious seed indicators exist in the correlated infrastructure.",
            }

        # Retrieve or compute normalized adjacency
        a_norm, node_to_idx = _get_or_build_adjacency(node_ids, graph_edges)

        # Seed signal vector y0: 1.0 for seeds, 0.0 for all others
        n = len(node_ids)
        y0 = np.zeros(n, dtype=np.float64)
        active_seeds: List[str] = []
        for s in seed_node_ids:
            if s in node_to_idx:
                y0[node_to_idx[s]] = 1.0
                active_seeds.append(s)

        if len(active_seeds) == 0:
            return {
                "available": False,
                "diffusion_score": 0.0,
                "reason": "seed nodes not found in active graph index",
                "hops_used": hops,
                "nearest_seed_distance": None,
                "contributing_seeds": [],
                "node_scores": {nid: 0.0 for nid in node_ids},
                "explanation": "Seed nodes do not intersect with current graph component.",
            }

        # Propagate: y_{t+1} = alpha * (A_norm @ y_t) + (1 - alpha) * y0
        y_curr = y0.copy()
        for _ in range(hops):
            y_next = alpha * a_norm.dot(y_curr) + (1.0 - alpha) * y0
            y_curr = y_next

        # Normalize outputs to [0.0, 1.0]
        max_val = np.max(y_curr)
        if max_val > 0:
            y_normalized = y_curr / max_val
        else:
            y_normalized = y_curr

        node_scores = {
            nid: round(float(y_normalized[node_to_idx[nid]]), 4)
            for nid in node_ids
            if nid in node_to_idx
        }

        target_score = node_scores.get(target_node_id, 0.0)

        # Trace shortest path to nearest contributing seed for human explainability
        min_dist, nearest_seed, explanation = find_nearest_seed_trace(
            target_node_id, set(active_seeds), graph_edges, max_hops=hops + 1
        )

        if not explanation:
            explanation = (
                f"Graph diffusion score of {round(target_score * 100, 1)}% derived via {hops}-hop "
                f"PageRank label propagation from {len(active_seeds)} malicious seed node(s)."
            )

        return {
            "available": True,
            "diffusion_score": round(float(target_score), 4),
            "hops_used": hops,
            "nearest_seed_distance": min_dist,
            "contributing_seeds": active_seeds,
            "node_scores": node_scores,
            "explanation": explanation,
        }

    except Exception as exc:
        logger.error(f"[GraphDiffusion] Unhandled exception during diffusion: {exc}", exc_info=True)
        return {
            "available": False,
            "diffusion_score": None,
            "reason": f"diffusion computation exception: {str(exc)}",
            "hops_used": hops,
            "nearest_seed_distance": None,
            "contributing_seeds": [],
            "node_scores": {},
            "explanation": "Graph diffusion engine encountered an unexpected numerical condition (failed open).",
        }


def extract_graph_from_correlation(
    email_id: str,
    correlation: Dict[str, Any],
    iocs: Dict[str, Any],
    threat_intel: Optional[Dict[str, Any]] = None,
) -> Tuple[List[Dict[str, Any]], List[Tuple[str, str, str]], Set[str]]:
    """
    Constructs node and edge lists from Stage F correlation data and Stage E threat intel
    so graph diffusion can operate directly on the real pipeline objects.
    """
    nodes: Dict[str, Dict[str, Any]] = {}
    edges: List[Tuple[str, str, str]] = []
    seeds: Set[str] = set()

    # Root email node
    nodes[email_id] = {"id": email_id, "type": "email", "name": "Current Email"}

    # Threat intel malicious indicators
    intel_data = threat_intel or {}

    # Campaign node
    camp_id = correlation.get("campaign_id")
    if camp_id:
        nodes[camp_id] = {"id": camp_id, "type": "campaign", "name": f"Campaign {camp_id}"}
        edges.append((email_id, camp_id, "part_of_campaign"))

    # Related emails
    for rel_id in correlation.get("related_emails") or []:
        nodes[rel_id] = {"id": rel_id, "type": "related_email", "name": f"Email {rel_id[:8]}"}
        edges.append((email_id, rel_id, "correlates_with"))
        if camp_id:
            edges.append((rel_id, camp_id, "part_of_campaign"))

    # IOC nodes: IPs, Domains, URLs, Hashes
    for ip in iocs.get("ips") or []:
        ip_node_id = f"ip_{ip}"
        nodes[ip_node_id] = {"id": ip_node_id, "type": "ip", "name": ip}
        edges.append((email_id, ip_node_id, "communicates_with_ip"))

        # Check if seed from Stage E ip_reputation or legacy ips dict
        ip_intel = (intel_data.get("ip_reputation") or intel_data.get("ips") or {}).get(ip, {})
        vt = ip_intel.get("vt_score") or ip_intel.get("virustotal_positives") or ip_intel.get("malicious_engine_count", 0)
        abuse = ip_intel.get("abuse_score") or ip_intel.get("abuse_confidence_score") or ip_intel.get("abuseipdb_score", 0)
        rep = ip_intel.get("reputation_status") or ip_intel.get("verdict", "")
        is_mal = ip_intel.get("malicious") is True
        if vt >= SEED_VT_THRESHOLD or abuse >= SEED_ABUSEIPDB_THRESHOLD or rep == "MALICIOUS" or is_mal:
            seeds.add(ip_node_id)
            nodes[ip_node_id]["is_malicious_seed"] = True

    for domain in iocs.get("domains") or []:
        dom_node_id = f"domain_{domain}"
        nodes[dom_node_id] = {"id": dom_node_id, "type": "domain", "name": domain}
        edges.append((email_id, dom_node_id, "resolves_domain"))

        dom_intel = (intel_data.get("domain_info") or intel_data.get("domains") or {}).get(domain, {})
        vt = dom_intel.get("vt_score") or dom_intel.get("virustotal_positives") or dom_intel.get("malicious_engine_count", 0)
        rep = dom_intel.get("reputation_status") or dom_intel.get("verdict", "")
        is_mal = dom_intel.get("malicious") is True
        if vt >= SEED_VT_THRESHOLD or rep == "MALICIOUS" or is_mal:
            seeds.add(dom_node_id)
            nodes[dom_node_id]["is_malicious_seed"] = True

    for url in iocs.get("urls") or []:
        url_node_id = f"url_{url[:40]}"
        nodes[url_node_id] = {"id": url_node_id, "type": "url", "name": url[:40]}
        edges.append((email_id, url_node_id, "contains_url"))

        url_intel = (intel_data.get("url_reputation") or intel_data.get("urls") or {}).get(url, {})
        vt = url_intel.get("vt_score") or url_intel.get("virustotal_positives") or url_intel.get("malicious_engine_count", 0)
        rep = url_intel.get("reputation_status") or url_intel.get("verdict", "")
        is_mal = url_intel.get("malicious") is True
        if vt >= SEED_VT_THRESHOLD or rep == "MALICIOUS" or is_mal:
            seeds.add(url_node_id)
            nodes[url_node_id]["is_malicious_seed"] = True

    for h in iocs.get("hashes") or []:
        hash_node_id = f"hash_{h[:16]}"
        nodes[hash_node_id] = {"id": hash_node_id, "type": "hash", "name": h[:16]}
        edges.append((email_id, hash_node_id, "payload_digest"))

        hash_intel = (intel_data.get("hash_reputation") or intel_data.get("hashes") or {}).get(h, {})
        vt = hash_intel.get("vt_score") or hash_intel.get("virustotal_positives") or hash_intel.get("malicious_engine_count", 0)
        rep = hash_intel.get("reputation_status") or hash_intel.get("verdict", "")
        is_mal = hash_intel.get("malicious") is True
        if vt >= SEED_VT_THRESHOLD or rep == "MALICIOUS" or is_mal:
            seeds.add(hash_node_id)
            nodes[hash_node_id]["is_malicious_seed"] = True

    # Shared infrastructure links
    for infra in correlation.get("shared_infrastructure") or []:
        infra_node_id = f"infra_{infra}"
        nodes[infra_node_id] = {"id": infra_node_id, "type": "shared_infra", "name": infra}
        edges.append((email_id, infra_node_id, "shares_infrastructure"))
        if camp_id:
            edges.append((infra_node_id, camp_id, "campaign_infrastructure"))

    return list(nodes.values()), edges, seeds
