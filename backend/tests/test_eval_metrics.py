"""
Tests for backend/eval: metric maths and corpus loading. No pipeline, no
network, no optional dependencies.

Run from backend/:  python tests/test_eval_metrics.py
"""
import json
import os
import sys
import tempfile

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from eval import metrics
from eval.corpus import BENIGN, MALICIOUS, load_corpus


def _rows():
    # 4 ham (scores 10, 30, 70, 90), 4 spam (scores 20, 60, 80, 95)
    return ([{"label": "benign", "category": "easy_ham", "risk_score": s} for s in (10, 30, 70, 90)]
            + [{"label": "malicious", "category": "spam", "risk_score": s} for s in (20, 60, 80, 95)])


def test_confusion_and_rates():
    tp, fp, tn, fn = metrics.confusion(_rows(), lambda r: r["risk_score"] >= 65)
    assert (tp, fp, tn, fn) == (2, 2, 2, 2)
    r = metrics.rates(tp, fp, tn, fn)
    assert r["false_positive_rate"] == 0.5 and r["false_negative_rate"] == 0.5


def test_empty_class_gives_none_not_zero():
    r = metrics.rates(0, 0, 0, 0)
    assert r["false_positive_rate"] is None and r["false_negative_rate"] is None
    assert metrics.wilson(0, 0) == (None, None)


def test_wilson_known_values():
    lo, hi = metrics.wilson(0, 10)
    assert lo == 0.0 and 0.25 < hi < 0.31          # 0/10 -> upper ~0.278
    lo, hi = metrics.wilson(13, 15)
    assert 0.62 < lo < 0.63 and 0.96 < hi < 0.97


def test_sweep_is_monotonic_and_matches_confusion():
    sweep = metrics.threshold_sweep(_rows(), step=5)
    fps = [x["fp"] for x in sweep]; fns = [x["fn"] for x in sweep]
    assert fps == sorted(fps, reverse=True)       # raising the threshold never adds FPs
    assert fns == sorted(fns)                     # ...and never removes FNs
    at65 = next(x for x in sweep if x["threshold"] == 65)
    assert (at65["fp"], at65["fn"]) == (2, 2)
    assert sweep[0]["fp"] == 4 and sweep[0]["fn"] == 0   # threshold 0 flags everything


def test_by_category():
    cats = metrics.by_category(_rows(), lambda r: r["risk_score"] >= 65)
    assert cats["easy_ham"] == {"label": "benign", "n": 4, "flagged": 2}
    assert cats["spam"] == {"label": "malicious", "n": 4, "flagged": 2}


def test_corpus_labels_dedupe_and_skip():
    with tempfile.TemporaryDirectory() as root:
        def put(folder, name, obj):
            os.makedirs(os.path.join(root, folder), exist_ok=True)
            with open(os.path.join(root, folder, name), "w") as fh:
                json.dump(obj, fh)
        put("20030228_easy_ham", "a.json", {"subject": "a"})
        put("20030228_hard_ham", "b.json", {"subject": "b"})
        put("20030228_spam", "c.json", {"subject": "c"})
        put("20050311_spam_2", "c_copy.json", {"subject": "c"})   # exact duplicate
        put("misc", "d.json", {"subject": "d"})                   # no label -> skipped
        put("ham_spam_mix", "e.json", {"subject": "e"})           # ambiguous -> skipped
        samples, skipped, dups = load_corpus(root)
        by = {s.sample_id: s for s in samples}
        assert len(samples) == 3
        assert by[os.path.join("20030228_easy_ham", "a.json")].label == BENIGN
        assert by[os.path.join("20030228_hard_ham", "b.json")].category == "hard_ham"
        assert by[os.path.join("20030228_spam", "c.json")].label == MALICIOUS
        assert len(dups) == 1 and len(skipped) == 2


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_") and callable(fn):
            fn(); print("PASS:", name)
    print("All eval tests passed.")
