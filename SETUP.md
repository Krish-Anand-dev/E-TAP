# Threat Email Analysis Platform — Local Setup

This guide runs the complete local backend pipeline:

```text
.eml / .msg
   ↓
A  Ingestion
   ↓
B / B2  Header + Attachment Forensics
   ↓
D  IOC Extraction
   ↓
E  Threat Intelligence
   ↓
F  Correlation + MongoDB Persistence
   ↓
G  Gemini Content Classification + Final Assessment + MITRE ATT&CK
   ↓
H  FastAPI JSON API
```

The frontend/reporting layer is separate from the core analysis pipeline. The canonical output is the JSON returned by `/analyze`.

## 1. Prerequisites

Install:

- Python 3.10+
- MongoDB Community Server
- Git
- Internet access for live Gemini / threat-intelligence lookups

The project already declares its Python dependencies in `backend/requirements.txt`.

## 2. Clone the repository

```bash
git clone <REPOSITORY_URL>
cd threat-email-platform
```

## 3. Create a virtual environment

### Windows PowerShell

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

If PowerShell blocks activation, run the project with the interpreter directly instead:

```powershell
.\.venv\Scripts\python.exe -m pip install -r backend\requirements.txt
```

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
```

## 4. Install dependencies

From the repository root:

```bash
python -m pip install -r backend/requirements.txt
```

The requirements include FastAPI, Uvicorn, MongoDB/PyMongo, `extract-msg` for `.msg` files, `google-genai` for Gemini, and the threat-intelligence dependencies.

## 5. Install and start MongoDB

Install MongoDB Community Server using the official MongoDB installer for your operating system.

For a standard local installation, MongoDB listens on:

```text
mongodb://localhost:27017
```

The application uses this database by default:

```text
phishing-investigator
```

### Windows

If MongoDB was installed as a Windows service, start it from `services.msc` or with the MongoDB service command appropriate to your installation.

Verify that MongoDB is reachable before starting the backend.

### Linux

For a package-managed installation, start the MongoDB service with your distribution's service manager, for example:

```bash
sudo systemctl start mongod
sudo systemctl status mongod
```

## 6. Configure environment variables

Copy the example file:

### Windows PowerShell

```powershell
Copy-Item .env.example .env
```

### Linux / macOS

```bash
cp .env.example .env
```

Then edit `.env`.

Recommended live configuration:

```dotenv
PORT=5000
MONGODB_URI=mongodb://localhost:27017/phishing-investigator
USE_FAKE_DB=0

THREAT_INTEL_LIVE=1
ABUSEIPDB_API_KEY=<YOUR_ABUSEIPDB_KEY>
VIRUSTOTAL_API_KEY=<YOUR_VIRUSTOTAL_KEY>

GEMINI_API_KEY=<YOUR_GEMINI_KEY>
GEMINI_MODEL=gemini-3.5-flash
```

### Important

Do **not** commit `.env` or any real API key to GitHub. `.env` is already ignored by `.gitignore`.

The actual API keys should be distributed separately through your team's chosen secret-sharing mechanism. They are intentionally not part of the repository.

## 7. Gemini configuration

Stage G uses the official `google-genai` Python SDK.

The model is selected through:

```dotenv
GEMINI_MODEL=gemini-3.8-flash
```

Do not assume that an older model name is available for every API key/project. If your assigned Gemini credentials only permit newer models, use a model explicitly enabled for those credentials.

If you are using a different supported Gemini model, only change `GEMINI_MODEL`; the Stage G architecture does not need to change.

## 8. Threat Intelligence configuration

Stage E is controlled by:

```dotenv
THREAT_INTEL_LIVE=1
```

With live mode enabled, the platform can use the configured external services for IP, domain, URL and hash enrichment.

If you do not have the external API keys yet, use:

```dotenv
THREAT_INTEL_LIVE=0
```

The pipeline will still run, but Stage E will return explicit offline placeholder results instead of live reputation data.

## 9. Start the API

From the `backend` directory:

### Windows PowerShell

```powershell
cd backend
python -m uvicorn app:app --reload --port 5000
```

### Linux / macOS

```bash
cd backend
python -m uvicorn app:app --reload --port 5000
```

Health check:

```text
GET http://localhost:5000/health
```

Expected response:

```json
{"status":"ok"}
```

## 10. Analyze an email through the API

### PowerShell

```powershell
curl.exe -X POST "http://localhost:5000/analyze" -F "file=@C:\path\to\suspicious.eml"
```

For a `.msg` file:

```powershell
curl.exe -X POST "http://localhost:5000/analyze" -F "file=@C:\path\to\suspicious.msg"
```

The endpoint returns the complete canonical analysis JSON.

## 11. Run without the HTTP server

From `backend/`:

```powershell
python run_pipeline.py "C:\path\to\suspicious.eml"
```

or:

```bash
python run_pipeline.py /path/to/suspicious.eml
```

This executes the same core pipeline used by the FastAPI endpoint.

## 12. Offline smoke test

For a test that does not require a running MongoDB server or external threat-intelligence APIs:

### Windows PowerShell

```powershell
$env:USE_FAKE_DB="1"
$env:THREAT_INTEL_LIVE="0"
python tests/test_pipeline_offline.py
```

### Linux / macOS

```bash
USE_FAKE_DB=1 THREAT_INTEL_LIVE=0 PYTHONPATH=. python tests/test_pipeline_offline.py
```

The fake database is process-local and is only for testing. It is not persistent storage.

## 13. Verify live Stage G

For a real Gemini run, confirm that the final response contains something equivalent to:

```json
"ai_analysis": {
  "content_classification": {
    "provider": "gemini"
  },
  "final_assessment": {
    "provider": "gemini"
  }
}
```

and:

```json
"stage_status": {
  "G": "gemini"
}
```

If Stage G reports `offline_fallback`, inspect the `fallback_reason` field. The fallback is intentionally explicit so a local demo is not mistaken for a live Gemini analysis.

## 14. Verify MongoDB persistence

After analyzing an email with `USE_FAKE_DB=0`, the backend should create/update documents in:

```text
phishing-investigator
├── analyzed_emails
├── campaigns
└── counters
```

The `analyzed_emails` collection stores the analysis history used by Stage F for future correlation.

The `campaigns` collection stores campaign membership and shared infrastructure.

## 15. What is stored

An analyzed email can contain:

- normalized email metadata
- header-forensics results
- attachment-forensics results
- extracted IOCs
- threat-intelligence enrichment
- content classification
- final risk score and verdict
- final evidence assessment
- MITRE ATT&CK mappings
- campaign/correlation information

Stage F persists the email even when there is no previous matching email, allowing that email to become historical evidence for future analyses.

## 16. Pipeline ownership / responsibilities

```text
A   Parse .eml / .msg and normalize the email (EmailObject)
B   Header / authentication / sender / Received-chain forensics
B2  Attachment forensics, OpenCV image preprocessing, PyZbar QR decoding, Tesseract OCR
D   IOC extraction & provenance tagging (source: "qr_code")
C'  Fast XGBoost Metadata Triage Pre-Filter (99.92% benchmark accuracy, 1.5ms latency)
E   External threat intelligence enrichment (VirusTotal, AbuseIPDB, ipinfo, WHOIS)
F   Historical IOC correlation + campaign assignment + persistence
G   Gemini interpretation + final verdict + MITRE ATT&CK Enterprise mapping
H   FastAPI orchestration, canonical JSON response + RAG vector indexing
I   Frontend reporting layer & SOC Analyst Assistant (RAG Chat Drawer)
```

Stage C is implemented as Stage C' (fast XGBoost metadata triage pre-filter), which evaluates 6 canonical features and bypasses Stage G on high-confidence benign emails (`>= 90%` confidence) to optimize latency and quota.

### AI/ML Subsystems & Verification

Run the unified 3-in-1 verification diagnostic script anytime:
```bash
python backend/verify_all_models.py
```

Run the unit test suite (14 passing tests):
```bash
python -m unittest tests/test_image_forensics.py tests/test_triage.py tests/test_rag.py tests/test_api_chat.py
```

## 17. Troubleshooting

### `ModuleNotFoundError: extract_msg`

Install the project requirements again:

```bash
python -m pip install -r backend/requirements.txt
```

### MongoDB connection failure

Check that MongoDB is running and that:

```dotenv
MONGODB_URI=mongodb://localhost:27017/phishing-investigator
```

points to the correct local MongoDB instance.

For a temporary offline smoke test, use:

```dotenv
USE_FAKE_DB=1
```

### Stage E says live lookups are disabled

Set:

```dotenv
THREAT_INTEL_LIVE=1
```

and provide the required API keys.

### Stage G falls back to offline mode

Check:

1. `GEMINI_API_KEY` is present.
2. `google-genai` is installed.
3. `GEMINI_MODEL` is a model available to the credentials being used.
4. The machine has network access to the Gemini API.
5. The `fallback_reason` in the response for the exact API error.

### `.eml` works but `.msg` does not

Make sure `extract-msg` is installed from `backend/requirements.txt`.

## 18. Security notes

- Never commit `.env`.
- Never commit API keys.
- Do not commit private email corpora or sensitive `.eml` / `.msg` files.
- Treat threat-intelligence API keys as secrets.
- Treat uploaded email content as potentially sensitive.
- Use the fake database only for local tests; use MongoDB for persistent correlation.
