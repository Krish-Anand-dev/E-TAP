"""Pure metric helpers (no pipeline imports) so they can be unit-tested."""
from __future__ import annotations

import math


def wilson(k: int, n: int, z: float = 1.96):
    """95% Wilson score interval for k/n. (None, None) when n == 0."""
    if n == 0:
        return (None, None)
    p = k / n
    d = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / d
    half = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return (max(0.0, centre - half), min(1.0, centre + half))


def confusion(rows, predicted_positive):
    """
    rows: iterable of dicts with `label` ("benign"/"malicious").
    predicted_positive: row -> bool. Positive class = malicious.
    """
    tp = fp = tn = fn = 0
    for r in rows:
        pos = bool(predicted_positive(r))
        mal = r["label"] == "malicious"
        if mal and pos:
            tp += 1
        elif mal:
            fn += 1
        elif pos:
            fp += 1
        else:
            tn += 1
    return tp, fp, tn, fn


def rates(tp, fp, tn, fn):
    neg, pos = fp + tn, tp + fn
    out = {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "n_benign": neg, "n_malicious": pos,
        "false_positive_rate": (fp / neg) if neg else None,
        "false_negative_rate": (fn / pos) if pos else None,
    }
    out["fpr_ci95"] = wilson(fp, neg)
    out["fnr_ci95"] = wilson(fn, pos)
    return out


def threshold_sweep(rows, key="risk_score", lo=0, hi=100, step=5):
    """FP/FN at every `step`; flagged means score >= threshold. Read-only."""
    sweep = []
    for t in range(lo, hi + 1, step):
        r = rates(*confusion(rows, lambda x, t=t: (x.get(key) or 0) >= t))
        sweep.append({"threshold": t, "fp": r["fp"], "fn": r["fn"],
                      "false_positive_rate": r["false_positive_rate"],
                      "false_negative_rate": r["false_negative_rate"]})
    return sweep


def by_category(rows, predicted_positive):
    """Per-category: how many were flagged. Works for ham and spam folders."""
    cats = {}
    for r in rows:
        c = cats.setdefault(r["category"], {"label": r["label"], "n": 0, "flagged": 0})
        c["n"] += 1
        c["flagged"] += 1 if predicted_positive(r) else 0
    return cats
