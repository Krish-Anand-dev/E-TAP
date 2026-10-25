"""
Stage C' -- Fast XGBoost Metadata Triage Pre-Filter
Owner: the team

A high-speed, lightweight pre-classification layer positioned between
Stage F (Correlation) and Stage G (Gemini). Evaluates numeric and boolean
metadata features to identify unambiguously benign emails and optionally
bypass the heavier generative AI Stage G call.

If the model artifact is missing or unreadable, Stage C' fails open
gracefully, letting the pipeline proceed to Gemini as normal.
"""

from __future__ import annotations

import os
import re
import logging
from typing import Any, Optional
import numpy as np

logger = logging.getLogger("E-TAP.triage")

# Strict canonical feature ordering shared with train_triage_model.py
FEATURE_NAMES = [
    "has_attachment",
    "num_urls_in_body",
    "sender_domain_age_days",
    "auth_spf_pass",
    "subject_length",
    "is_urgent_keyword_present",
]

_URGENT_KEYWORDS = {
    "urgent", "immediately", "immediate", "action required", "verify",
    "suspended", "suspension", "password", "invoice", "unauthorized",
    "confirm", "alert", "security update", "compromised", "login",
    "reset", "expires", "wire transfer", "bank", "billing", "overdue",
    "payment", "update required", "critical",
}

_MODEL_PATH = os.path.join(os.path.dirname(__file__), "models", "xgboost_phish_model.pkl")
_TRIAGE_MODEL = None
_TRIAGE_MODEL_LOADED = False


def _get_model():
    """Lazy-load the trained XGBoost model once at startup."""
    global _TRIAGE_MODEL, _TRIAGE_MODEL_LOADED
    if not _TRIAGE_MODEL_LOADED:
        _TRIAGE_MODEL_LOADED = True
        if os.path.exists(_MODEL_PATH):
            try:
                import joblib
                _TRIAGE_MODEL = joblib.load(_MODEL_PATH)
                logger.info("Loaded XGBoost metadata triage model from %s", _MODEL_PATH)
            except Exception as exc:
                logger.warning("Failed to load XGBoost triage model (%s): %s", _MODEL_PATH, exc)
                _TRIAGE_MODEL = None
        else:
            logger.info("XGBoost triage model artifact not found at %s. Running in fail-open mode.", _MODEL_PATH)
            _TRIAGE_MODEL = None
    return _TRIAGE_MODEL


def extract_features(
    email: dict,
    header_analysis: dict,
    attachment_analysis: dict,
    iocs: dict,
    threat_intel: Optional[dict] = None,
) -> np.ndarray:
    """
    Extract exactly the 6 canonical metadata features from pipeline outputs.
    Guarantees safe, defensive defaults for missing/unresolvable inputs.

    Returns
    -------
    np.ndarray
        Array of shape (1, 6) with float32 values.
    """
    email = email or {}
    header_analysis = header_analysis or {}
    attachment_analysis = attachment_analysis or {}
    iocs = iocs or {}
    threat_intel = threat_intel or {}

    # 1. has_attachment (0 or 1)
    attachments_list = attachment_analysis.get("attachments") or []
    has_attachment = 1.0 if len(attachments_list) > 0 else 0.0

    # 2. num_urls_in_body
    urls_list = iocs.get("urls") or []
    num_urls_in_body = float(len(urls_list))

    # 3. sender_domain_age_days (safe default: -1)
    sender_domain_age_days = -1.0
    domain_info = threat_intel.get("domain_info") or {}
    # Try finding the domain of the sender
    from_email = email.get("from_email") or ""
    sender_domain = from_email.split("@")[-1].strip().lower() if "@" in from_email else ""

    info = domain_info.get(sender_domain)
    if not info and domain_info:
        # Fall back to first domain record if specific sender not found
        info = next(iter(domain_info.values()), None)

    if isinstance(info, dict):
        raw_age = info.get("age_days")
        if isinstance(raw_age, (int, float)) and not np.isnan(raw_age) and raw_age >= 0:
            sender_domain_age_days = float(raw_age)

    # 4. auth_spf_pass (0 or 1)
    auth_spf_pass = 0.0
    spf = header_analysis.get("spf")
    if isinstance(spf, dict):
        if spf.get("result") == "pass":
            auth_spf_pass = 1.0
    elif isinstance(spf, str) and spf.lower() == "pass":
        auth_spf_pass = 1.0

    # 5. subject_length
    subject = email.get("subject") or ""
    subject_length = float(len(subject.strip()))

    # 6. is_urgent_keyword_present (0 or 1)
    is_urgent_keyword_present = 0.0
    combined_text = f"{subject} {email.get('body_text') or ''}".lower()
    for kw in _URGENT_KEYWORDS:
        if kw in combined_text:
            is_urgent_keyword_present = 1.0
            break

    features = np.array(
        [[
            has_attachment,
            num_urls_in_body,
            sender_domain_age_days,
            auth_spf_pass,
            subject_length,
            is_urgent_keyword_present,
        ]],
        dtype=np.float32,
    )
    return features


def predict_triage(features: np.ndarray) -> dict[str, Any]:
    """
    Evaluate feature vector against the triage model.

    Returns
    -------
    dict
        {
            "available": bool,
            "label": int (0 = benign, 1 = suspicious),
            "confidence": float (0.0 to 1.0),
            "is_safe": bool (True if label == 0),
        }
    """
    model = _get_model()
    if model is None:
        return {
            "available": False,
            "label": None,
            "confidence": 0.0,
            "is_safe": False,
        }

    try:
        # Predict probability: classes are [0: benign, 1: phish]
        if hasattr(model, "predict_proba"):
            probs = model.predict_proba(features)[0]
            # probs[0] = prob of benign, probs[1] = prob of phish
            pred = int(np.argmax(probs))
            conf = float(probs[pred])
        else:
            pred = int(model.predict(features)[0])
            conf = 1.0 if pred == 0 else 0.0

        return {
            "available": True,
            "label": pred,
            "confidence": round(conf, 4),
            "is_safe": (pred == 0),
        }
    except Exception as exc:
        logger.warning("Error running XGBoost triage inference: %s", exc)
        return {
            "available": False,
            "label": None,
            "confidence": 0.0,
            "is_safe": False,
        }
