# AI Engine — Stage G + Legacy Content Classifier

The original Stage C content classifier is retained as reusable Level 1
logic inside Stage G. It analyzes only `subject`, `body_text`, and
`body_html` against the fixed 30-category phishing/threat taxonomy in
`prompts.py`.

Stage G then performs Level 2 final interpretation over the complete
pipeline evidence:

```text
email content
headers
attachments
IOCs
threat intelligence
correlation
content classification
```

The final assessment returns a risk score, verdict, explanation,
supporting evidence, recommended actions, and evidence-bound MITRE ATT&CK
mappings.

## Entry Points

Full Stage G:

```python
from ai_engine.stage_g import analyze_with_stage_g

ai_analysis = analyze_with_stage_g(complete_context)
```

Legacy content-only classifier:

```python
from ai_engine.main import analyze_email

analysis = analyze_email(parsed_email_dict)
```

The full pipeline should call `analyze_with_stage_g()`, not the old
content-only classifier directly.

## Gemini Configuration

Add this to your local `.env` to enable Gemini:

```text
GEMINI_API_KEY=your-own-key-here
GEMINI_MODEL=gemini-1.5-flash
```

Never commit `.env` or hard-code a key.

Importing `ai_engine` does not require a key. If `GEMINI_API_KEY` is empty,
Stage G returns an explicit `offline_fallback` result so the end-to-end
pipeline can still be run locally.

## Output Shape

```json
{
  "content_classification": {
    "verdict": "Likely Malicious",
    "content_risk_score": 90,
    "confidence": 0.87,
    "attack_type": "Credential Phishing",
    "categories": [{"name": "Credential Phishing", "weight": 90}],
    "reasons": ["..."],
    "suspicious_indicators": ["..."]
  },
  "final_assessment": {
    "verdict": "HIGH-RISK PHISHING",
    "risk_score": 94,
    "confidence": 0.82,
    "explanation": "...",
    "evidence_assessments": [],
    "supporting_evidence": [],
    "mitre_attack": []
  },
  "mitre_attack": []
}
```

## Files

- `prompts.py` — content-only taxonomy and prompt reused from Stage C
- `schemas.py` — Pydantic schemas for content and final assessments
- `main.py` — legacy content-only Gemini classifier
- `stage_g.py` — final interpretation, offline fallback scoring, and MITRE mapping
