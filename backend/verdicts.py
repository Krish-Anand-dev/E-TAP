"""
Single source of truth for E-TAP verdict labels, score thresholds and
display bands.

Before this module existed the same decision was made in four places with
different numbers (backend >=65, extension >=65, web UI >=70, history card
>60) and verdict strings came in several spellings ("Likely Legitimate",
"LIKELY LEGITIMATE", "Likely Malicious", ...). Everything now goes through
`finalize_verdict()`, and clients render the `verdict_band` it produces
instead of re-deriving it from the score.

The frontend keeps a mirror of THRESHOLDS in `frontend/src/utils/verdict.js`
for records that were stored before `verdict_band` existed. 
`backend/tests/test_verdicts.py` fails if the two drift apart.
"""

from __future__ import annotations

import re
from typing import Optional

# --- canonical labels, ordered least -> most severe -------------------------
LIKELY_LEGITIMATE = "LIKELY LEGITIMATE"
LOW_RISK = "LOW RISK"
SUSPICIOUS = "SUSPICIOUS"
LIKELY_PHISHING = "LIKELY PHISHING"
HIGH_RISK_PHISHING = "HIGH-RISK PHISHING"

CANONICAL_LABELS: tuple[str, ...] = (
    LIKELY_LEGITIMATE,
    LOW_RISK,
    SUSPICIOUS,
    LIKELY_PHISHING,
    HIGH_RISK_PHISHING,
)

# Minimum risk score (0-100) for each label. Keep in sync with
# frontend/src/utils/verdict.js (enforced by tests/test_verdicts.py).
THRESHOLDS: dict[str, int] = {
    LIKELY_LEGITIMATE: 0,
    LOW_RISK: 20,
    SUSPICIOUS: 40,
    LIKELY_PHISHING: 65,
    HIGH_RISK_PHISHING: 85,
}

# label -> UI band. Three colours only: safe / caution / danger.
BAND_BY_LABEL: dict[str, str] = {
    LIKELY_LEGITIMATE: "safe",
    LOW_RISK: "safe",
    SUSPICIOUS: "caution",
    LIKELY_PHISHING: "danger",
    HIGH_RISK_PHISHING: "danger",
}

_SEVERITY = {label: i for i, label in enumerate(CANONICAL_LABELS)}

# Every spelling that models, the offline fallback or older code produced.
# Keys are normalised with _key(); anything not listed falls back to the score.
_SYNONYMS: dict[str, str] = {
    "likely legitimate": LIKELY_LEGITIMATE,
    "legitimate": LIKELY_LEGITIMATE,
    "clean": LIKELY_LEGITIMATE,
    "safe": LIKELY_LEGITIMATE,
    "low risk": LOW_RISK,
    "suspicious": SUSPICIOUS,
    "likely phishing": LIKELY_PHISHING,
    "likely malicious": LIKELY_PHISHING,
    "phishing": LIKELY_PHISHING,
    "malicious": LIKELY_PHISHING,
    "high risk phishing": HIGH_RISK_PHISHING,
    "highly suspicious malicious": HIGH_RISK_PHISHING,
    "highly suspicious": HIGH_RISK_PHISHING,
    "high risk": HIGH_RISK_PHISHING,
}


def _key(text: str) -> str:
    return re.sub(r"[^a-z]+", " ", text.lower()).strip()


def label_for_score(score: Optional[float]) -> str:
    """Canonical label implied by a 0-100 risk score."""
    s = _clamp(score)
    label = LIKELY_LEGITIMATE
    for candidate in CANONICAL_LABELS:
        if s >= THRESHOLDS[candidate]:
            label = candidate
    return label


def band_for_label(label: str) -> str:
    return BAND_BY_LABEL.get(label, "caution")


def band_for_score(score: Optional[float]) -> str:
    return band_for_label(label_for_score(score))


def normalize_label(raw: Optional[str]) -> Optional[str]:
    """Map any known spelling to a canonical label, or None if unrecognised."""
    if not raw or not isinstance(raw, str):
        return None
    if raw in _SEVERITY:
        return raw
    return _SYNONYMS.get(_key(raw))


def _clamp(score: Optional[float]) -> int:
    try:
        return max(0, min(100, int(round(float(score)))))
    except (TypeError, ValueError):
        return 0


def finalize_verdict(raw_label: Optional[str], score: Optional[float]) -> dict:
    """
    Reconcile a (possibly free-text) verdict with the numeric score.

    The more severe of the two wins, so a "Likely Legitimate" label can never
    be shown next to a score that the thresholds call dangerous. When they
    disagree `reconciled` is True and `original_label` keeps what was
    submitted, so nothing is hidden.
    """
    risk = _clamp(score)
    score_label = label_for_score(risk)
    given = normalize_label(raw_label)

    if given is None:
        label = score_label
        reconciled = False
    else:
        label = max(given, score_label, key=_SEVERITY.__getitem__)
        reconciled = label != given

    return {
        "verdict": label,
        "verdict_band": band_for_label(label),
        "risk_score": risk,
        "reconciled": reconciled,
        "original_label": raw_label if (reconciled or given is None) and raw_label else None,
    }
