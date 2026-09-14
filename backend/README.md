# Backend

The backend now exposes one complete analysis path:

```text
uploaded .eml/.msg
  -> Stage A parser
  -> Stage B header forensics
  -> Stage B2 attachment forensics (+ OpenCV/OCR/QR scanning)
  -> Stage D IOC extraction (with QR-URL provenance tagging)
  -> Stage E threat intelligence
  -> Stage F correlation + MongoDB persistence
  -> Stage C' fast XGBoost metadata triage pre-filter (conditional skip)
  -> Stage G content classification + final Gemini interpretation + MITRE mapping
  -> Stage H final JSON response (+ non-blocking background RAG embedding)
```

## Advanced AI/ML Pipeline Modules

### 1. Image Forensics (QR Code & OCR Decomposition)
- **Module**: `forensics/image_forensics.py`
- Enriches Stage B2 image attachments by detecting hidden QR codes (`pyzbar` + `cv2.QRCodeDetector`) and extracting image text (`pytesseract`).
- Concealed URLs are automatically fed into Stage D with provenance tag `source: "qr_code"`, and extracted OCR text is concatenated to `body_text` for Gemini reasoning.
- Note: System-level binaries `tesseract-ocr` and `libzbar0` are optional. If missing, the module degrades gracefully without disrupting the pipeline.

### 2. Stage C' XGBoost Metadata Triage Gatekeeper
- **Module**: `ai_engine/triage_model.py` & `ai_engine/train_triage_model.py`
- Fast pre-classification filter running over 6 numerical/boolean metadata features before Stage G.
- If an email is predicted benign with confidence above `TRIAGE_SAFE_THRESHOLD` (default `0.90`), the pipeline skips the heavy Gemini call, returning an instant synthesized verdict.
- **Notice**: A synthetic baseline model is provided for scaffolding. For production calibration, run `python ai_engine/train_triage_model.py` against real Enron/CEAS corpora.

### 3. RAG SOC Analyst Assistant (Vector Search & Chat)
- **Module**: `rag/embeddings.py` & `rag/chat.py`
- Endpoint: `POST /chat` (e.g. `{"question": "Did we see any payroll phishing attacks?"}`)
- Uses `sentence-transformers` (`all-MiniLM-L6-v2`) to embed investigation summaries.
- **Search Default**: In-memory cosine similarity over MongoDB records (`numpy` / `scikit-learn`).
- **Opt-in Cloud Vector Search**: Set `USE_ATLAS_VECTOR_SEARCH=1` to use MongoDB Atlas Vector Search.
- **Non-blocking Write**: Stage H persists embeddings via a fire-and-forget background worker thread without adding latency to `/analyze`.


## Configuration

Use the root `.env.example` as the template:

```text
MONGODB_URI=mongodb://localhost:27017/phishing-investigator
USE_FAKE_DB=0
THREAT_INTEL_LIVE=0
ABUSEIPDB_API_KEY=
VIRUSTOTAL_API_KEY=
GEMINI_API_KEY=
GEMINI_MODEL=gemini-1.5-flash
```

Stage E live lookups are disabled unless `THREAT_INTEL_LIVE=1`.
Stage G uses Gemini when `GEMINI_API_KEY` is present and returns explicit
offline fallback analysis when it is not.

## API

Start the server:

```bash
uvicorn app:app --reload --port 5000
```

Analyze an email:

```bash
curl -X POST "http://localhost:5000/analyze" -F "file=@C:\path\to\suspicious.eml"
```

The response is shaped for the frontend dashboard:

```json
{
  "email_id": "...",
  "risk_score": 94,
  "verdict": "HIGH-RISK PHISHING",
  "email": {},
  "headers": {},
  "attachments": [],
  "iocs": {},
  "threat_intel": {},
  "correlation": {},
  "ai_analysis": {
    "content_classification": {},
    "final_assessment": {},
    "mitre_attack": []
  },
  "mitre_attack": [],
  "stage_status": {}
}
```

## CLI

Run the same complete pipeline without HTTP:

```bash
python run_pipeline.py C:\path\to\suspicious.eml
```

For local smoke tests without MongoDB or API keys:

```bash
$env:USE_FAKE_DB="1"
$env:THREAT_INTEL_LIVE="0"
python tests/test_pipeline_offline.py
```
