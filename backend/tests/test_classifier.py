"""
test_classifier.py

Manual integration test for Stage C (AI Content Classification, the team).

Runs the REAL analyze_email() -- Stage A parses a real sample file, and
Stage C's own Gemini-backed classification logic runs unmodified against
it. This does not mock or stub any Stage C logic; it needs a working
GEMINI_API_KEY configured locally (see CONTEXT.md, section 14) since
ai_engine.main raises a clear error on import if one isn't set.

Samples (not committed):
    - Known-phishing sample: locally supplied EPVME corpus
      (samples/EPVME_1/1/*.eml).
    - Known-legitimate sample: locally supplied manifest-labeled email
      corpus (samples/email_dataset/set_01/eml/set01_001.eml).

Raw .eml/.msg artifacts and external corpora are excluded from Git by
.gitignore. Supply authorized fixtures locally before running this optional
manual model integration check; a fresh clone does not contain these files.

This mirrors the existing pipeline test pattern (see test_single_email.py,
test_b2_against_krish_fixture.py): sys.path is extended so backend/'s
packages import cleanly, Stage A parses the raw file, the relevant
stage's real entry point is called, and the result is printed as JSON
for human review. Stage C's verdict/category output is model-generated
and not perfectly deterministic, so this test checks response SHAPE
(the things that must always hold) with asserts, and prints a soft
WARNING (not a hard failure) if the semantic verdict looks inverted.

Usage (run from backend/, with GEMINI_API_KEY configured in your local
.env -- see CONTEXT.md, section 14):
    python tests/test_classifier.py
"""

import sys
import os
import json

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from email_parser import parse_any
from ai_engine.main import analyze_email, calculate_content_risk


PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))

# Known-phishing sample: expected as a locally supplied, ignored corpus.
EPVME_PHISHING_DIR = os.path.join(PROJECT_ROOT, "samples", "EPVME_1", "1")

# Known-legitimate sample: locally supplied manifest-labeled benign fixture.
# Raw sample files are deliberately not committed (see root .gitignore).
BENIGN_SAMPLE_PATH = os.path.join(
    PROJECT_ROOT, "samples", "email_dataset", "set_01", "eml", "set01_001.eml"
)


def _pick_phishing_sample() -> str:
    """Deterministically pick one EPVME_1 sample (first by filename)."""
    filenames = sorted(
        f for f in os.listdir(EPVME_PHISHING_DIR) if f.lower().endswith(".eml")
    )
    if not filenames:
        raise FileNotFoundError(
            f"No local EPVME .eml samples found under {EPVME_PHISHING_DIR}. "
            "The raw corpus is excluded from Git; supply authorized local fixtures "
            "before running this optional Gemini integration check."
        )
    return os.path.join(EPVME_PHISHING_DIR, filenames[0])


def _classify_file(file_path: str, expected_label: str) -> dict:
    """Stage A -> Stage C on one sample file, returns the combined result."""
    parsed = parse_any(file_path)
    parsed_dict = parsed.to_dict()

    analysis = analyze_email(parsed_dict)
    content_risk_score = calculate_content_risk(analysis.categories)

    result = {
        "file": os.path.relpath(file_path, PROJECT_ROOT),
        "expected_label": expected_label,
        "subject": parsed_dict.get("subject"),
        "verdict": analysis.content_verdict,
        "content_risk_score": content_risk_score,
        "confidence": analysis.confidence,
        "attack_type": analysis.attack_type,
        "categories": [
            {"name": c.name, "weight": c.weight} for c in analysis.categories
        ],
        "reasons": analysis.reasons,
        "suspicious_indicators": analysis.suspicious_indicators,
    }

    # --- shape checks: things that must always hold regardless of the
    # model's specific judgment call ---
    assert isinstance(result["verdict"], str) and result["verdict"], (
        "Stage C output is missing a non-empty 'verdict'"
    )
    assert 0.0 <= result["confidence"] <= 1.0, "confidence out of [0, 1] range"
    assert isinstance(result["categories"], list), "categories must be a list"
    for category in result["categories"]:
        assert 0 <= category["weight"] <= 100, (
            f"category weight out of range: {category}"
        )
    assert 0 <= result["content_risk_score"] <= 100, "content_risk_score out of range"

    return result


def main():
    phishing_path = _pick_phishing_sample()

    print(f"\n{'=' * 60}")
    print(f"KNOWN-PHISHING SAMPLE (EPVME_1): {os.path.basename(phishing_path)}")
    print("=" * 60)
    phishing_result = _classify_file(phishing_path, expected_label="phishing")
    print(json.dumps(phishing_result, indent=2, ensure_ascii=False))
    if phishing_result["content_risk_score"] < 50:
        print(
            "  [WARNING] known-phishing sample scored low "
            f"({phishing_result['content_risk_score']}) -- worth a manual look, "
            "but not treated as a hard failure since Stage C's judgment is "
            "model-generated, not deterministic."
        )

    print(f"\n{'=' * 60}")
    print(f"KNOWN-LEGITIMATE SAMPLE (fallback fixture): {os.path.basename(BENIGN_SAMPLE_PATH)}")
    print("=" * 60)
    benign_result = _classify_file(BENIGN_SAMPLE_PATH, expected_label="benign")
    print(json.dumps(benign_result, indent=2, ensure_ascii=False))
    if benign_result["content_risk_score"] >= 50:
        print(
            "  [WARNING] known-legitimate sample scored high "
            f"({benign_result['content_risk_score']}) -- worth a manual look, "
            "but not treated as a hard failure since Stage C's judgment is "
            "model-generated, not deterministic."
        )

    print("\nAll structural checks passed for both samples.")


if __name__ == "__main__":
    main()
