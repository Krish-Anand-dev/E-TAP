"""
RAG Embeddings Engine
Uses sentence-transformers (all-MiniLM-L6-v2) to generate dense 384-dimensional
vector embeddings for investigated email artifacts and queries.
"""

from __future__ import annotations

import os
import re
import hashlib
import logging
from typing import Any, Optional
import numpy as np

logger = logging.getLogger("E-TAP.rag.embeddings")

_MODEL = None
_MODEL_LOADED = False
_EMBEDDING_DIM = 384


def _get_model():
    """Lazy-load the SentenceTransformer embedding model once at runtime."""
    global _MODEL, _MODEL_LOADED
    if not _MODEL_LOADED:
        _MODEL_LOADED = True
        # On Render or memory-constrained environments (<512MB RAM), avoid PyTorch OOM
        if os.getenv("RENDER") or os.getenv("USE_FALLBACK_EMBEDDINGS") == "1":
            logger.info("Running on Render or low-memory mode. Using fast deterministic fallback embedder.")
            _MODEL = None
            return None

        try:
            from sentence_transformers import SentenceTransformer
            model_name = os.getenv("RAG_EMBEDDING_MODEL", "all-MiniLM-L6-v2")
            logger.info("Loading SentenceTransformer model: %s...", model_name)
            _MODEL = SentenceTransformer(model_name)
            logger.info("SentenceTransformer model loaded successfully.")
        except Exception as exc:
            logger.warning("Could not load SentenceTransformer model (%s). Using fallback embedder.", exc)
            _MODEL = None
    return _MODEL


def _fallback_embed(text: str) -> list[float]:
    """Deterministic hash-based dense vector for testing when model is unavailable."""
    words = re.findall(r"\w+", text.lower())
    vec = np.zeros(_EMBEDDING_DIM, dtype=np.float32)
    for w in words:
        h = int(hashlib.md5(w.encode("utf-8")).hexdigest(), 16)
        idx = h % _EMBEDDING_DIM
        sign = 1.0 if ((h >> 8) & 1) else -1.0
        vec[idx] += sign
    norm = np.linalg.norm(vec)
    if norm > 0:
        vec = vec / norm
    return vec.tolist()


def embed_text(text: str) -> list[float]:
    """
    Generate a 384-dimensional vector embedding for the input text.

    Returns
    -------
    list[float]
    """
    clean_text = (text or "").strip()
    if not clean_text:
        return [0.0] * _EMBEDDING_DIM

    model = _get_model()
    if model is not None:
        try:
            embedding = model.encode(clean_text, convert_to_numpy=True)
            return embedding.astype(float).tolist()
        except Exception as exc:
            logger.warning("Model encode error: %s. Using fallback embedder.", exc)

    return _fallback_embed(clean_text)


def build_summary(investigation_doc: dict) -> str:
    """
    Build a concise, information-rich natural language summary of an investigation
    document for vector indexing and LLM prompt grounding.
    Supports both MongoDB stored documents and Stage H in-memory output.
    """
    if not investigation_doc:
        return ""

    email_id = investigation_doc.get("email_id") or str(investigation_doc.get("_id") or "Unknown")
    email = investigation_doc.get("email") or {}
    subject = investigation_doc.get("subject") or email.get("subject") or "(No Subject)"
    from_sender = (
        investigation_doc.get("from_email")
        or email.get("from_raw")
        or email.get("from_email")
        or "Unknown"
    )
    date_str = investigation_doc.get("email_date") or email.get("date") or ""

    verdict = investigation_doc.get("verdict") or "UNKNOWN"
    risk_score = investigation_doc.get("risk_score")
    risk_str = f"Risk Score: {risk_score}/100" if risk_score is not None else "Risk Score: N/A"

    correlation = investigation_doc.get("correlation") or {}
    campaign_id = investigation_doc.get("campaign_id") or correlation.get("campaign_id") or "Unassigned"

    iocs = investigation_doc.get("ioc_analysis") or investigation_doc.get("iocs") or {}
    ips = [str(x) for x in (iocs.get("ips") or [])[:4]]
    domains = [str(x) for x in (iocs.get("domains") or [])[:4]]
    urls = [str(x) for x in (iocs.get("urls") or [])[:4]]

    mitre = investigation_doc.get("mitre_attack") or []
    mitre_names = []
    for m in mitre:
        if isinstance(m, dict):
            tech_id = m.get("technique") or m.get("technique_id") or ""
            name = m.get("name") or m.get("technique_name") or ""
            label = f"{tech_id}: {name}".strip(": ") if tech_id or name else ""
            if label:
                mitre_names.append(label)
        elif isinstance(m, str):
            mitre_names.append(m)

    ai_analysis = investigation_doc.get("ai_analysis") or {}
    final_assessment = (
        investigation_doc.get("final_assessment")
        or ai_analysis.get("final_assessment")
        or {}
    )
    explanation = final_assessment.get("explanation") or final_assessment.get("assessment") or ""
    if len(explanation) > 280:
        explanation = explanation[:277] + "..."

    summary_parts = [
        f"Incident {email_id}: {verdict} ({risk_str}).",
        f"Campaign: {campaign_id}.",
        f"Sender: {from_sender} | Subject: '{subject}' {f'({date_str})' if date_str else ''}.",
    ]

    if ips:
        summary_parts.append(f"Originating/Associated IPs: {', '.join(ips)}.")
    if domains:
        summary_parts.append(f"Associated Domains: {', '.join(domains)}.")
    if urls:
        summary_parts.append(f"Sample URLs: {', '.join(urls)}.")
    if mitre_names:
        summary_parts.append(f"MITRE ATT&CK Tactics/Techniques: {', '.join(mitre_names)}.")
    if explanation:
        summary_parts.append(f"Assessment: {explanation}")

    return " ".join(summary_parts).strip()
