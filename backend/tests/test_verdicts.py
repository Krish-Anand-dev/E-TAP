"""
Tests for backend/verdicts.py -- the single source of truth for verdict
labels, thresholds and UI bands. Also guards the JS mirror used by the web UI
for records saved before `verdict_band` existed.

Run:  python tests/test_verdicts.py   (or pytest)
"""
import os
import re
import sys

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

import verdicts as v


def test_label_boundaries():
    cases = {
        0: v.LIKELY_LEGITIMATE, 19: v.LIKELY_LEGITIMATE,
        20: v.LOW_RISK, 39: v.LOW_RISK,
        40: v.SUSPICIOUS, 64: v.SUSPICIOUS,
        65: v.LIKELY_PHISHING, 84: v.LIKELY_PHISHING,
        85: v.HIGH_RISK_PHISHING, 100: v.HIGH_RISK_PHISHING,
    }
    for score, label in cases.items():
        assert v.label_for_score(score) == label, (score, v.label_for_score(score), label)


def test_bad_scores_do_not_crash():
    assert v.label_for_score(None) == v.LIKELY_LEGITIMATE
    assert v.label_for_score("abc") == v.LIKELY_LEGITIMATE
    assert v.label_for_score(-5) == v.LIKELY_LEGITIMATE
    assert v.label_for_score(250) == v.HIGH_RISK_PHISHING


def test_spellings_normalise():
    assert v.normalize_label("Likely Legitimate") == v.LIKELY_LEGITIMATE
    assert v.normalize_label("LIKELY LEGITIMATE") == v.LIKELY_LEGITIMATE
    assert v.normalize_label("Likely Malicious") == v.LIKELY_PHISHING
    assert v.normalize_label("Highly Suspicious / Malicious") == v.HIGH_RISK_PHISHING
    assert v.normalize_label("Suspicious") == v.SUSPICIOUS
    assert v.normalize_label("something new the model invented") is None
    assert v.normalize_label(None) is None


def test_likely_malicious_is_never_safe_styled():
    # Regression: the old UI matched case-sensitively on 'MALICIOUS', so
    # "Likely Malicious" at a low score rendered as safe.
    out = v.finalize_verdict("Likely Malicious", 30)
    assert out["verdict_band"] == "danger", out
    assert out["verdict"] == v.LIKELY_PHISHING


def test_legit_label_cannot_hide_high_score():
    out = v.finalize_verdict("Likely Legitimate", 72)
    assert out["verdict"] == v.LIKELY_PHISHING
    assert out["verdict_band"] == "danger"
    assert out["reconciled"] is True
    assert out["original_label"] == "Likely Legitimate"  # nothing hidden


def test_severe_label_is_not_softened_by_low_score():
    out = v.finalize_verdict("Likely Malicious", 10)
    assert out["verdict"] == v.LIKELY_PHISHING and out["reconciled"] is False


def test_unknown_label_falls_back_to_score():
    out = v.finalize_verdict("???", 45)
    assert out["verdict"] == v.SUSPICIOUS and out["verdict_band"] == "caution"
    assert out["original_label"] == "???"


def test_consistent_label_is_untouched():
    out = v.finalize_verdict("LIKELY LEGITIMATE", 5)
    assert out["reconciled"] is False and out["original_label"] is None


def test_js_mirror_matches_python():
    path = os.path.join(os.path.dirname(__file__), "..", "..", "frontend", "src", "utils", "verdict.js")
    src = open(path, encoding="utf-8").read()
    block = re.search(r"export const THRESHOLDS = \[(.*?)\];", src, re.S).group(1)
    js = {label: int(n) for n, label in re.findall(r"\[(\d+),\s*'([^']+)'\]", block)}
    assert js == v.THRESHOLDS, (js, v.THRESHOLDS)
    js_bands = dict(re.findall(r"'([A-Z\- ]+)':\s*'(safe|caution|danger)'", src))
    assert js_bands == v.BAND_BY_LABEL, (js_bands, v.BAND_BY_LABEL)


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn()
            print("PASS:", name)
    print("All verdict tests passed.")
