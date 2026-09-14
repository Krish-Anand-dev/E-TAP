# PhishGuard — Automated Threat Email Analysis & Forensic Platform

An enterprise-grade, end-to-end cyber threat forensic platform for analyzing `.eml` and `.msg` email artifacts. Combines deterministic header forensics, computer vision (OCR & QR decoding), local machine learning triage (XGBoost), threat intelligence (VirusTotal/AbuseIPDB), graph campaign correlation, and Google Gemini AI with RAG.

```text
[Email Artifact] 
       │
       ▼
   Stage A (Parser / MIME Normalization)
       │
       ├─────────────────────────────────┐
       ▼                                 ▼
   Stage B (Header Forensics)       Stage B2 (OpenCV, PyZbar QR, OCR)
       │                                 │
       └────────────────┬────────────────┘
                        ▼
   Stage D (IOC Extraction & Provenance Tagging)
                        │
   Stage C' (Fast XGBoost Metadata Triage — 1.5ms)
                        │
   Stage E (Threat Intelligence: AbuseIPDB, VT, WHOIS)
                        │
   Stage F (MongoDB Graph Correlation & Campaign Engine)
                        │
   Stage G (Gemini 1.5 Analysis & MITRE ATT&CK Mapping)
                        │
   Stage H (Dossier Assembly + 384d RAG Vector Indexing)
                        │
                        ▼
       [Interactive React Glassmorphism Dashboard]
       [SOC Analyst Assistant Drawer — RAG Chat]
```

---

## Key Features & AI/ML Subsystems

1. **Computer Vision & Image Forensics (OpenCV + PyZbar + Tesseract)**:
   - Scans image attachments (`.png`, `.jpg`, `.jpeg`).
   - Decodes embedded QR codes (Quishing defense) and tags extracted URLs with `source: "qr_code"`.
   - Extracts rendered text via OCR to detect image-only phishing lures.

2. **Stage C' Fast Metadata Triage (XGBoost Classifier)**:
   - Evaluates 6 canonical metadata features (`has_attachment`, `num_urls_in_body`, `sender_domain_age_days`, `auth_spf_pass`, `subject_length`, `is_urgent_keyword_present`).
   - Trained on an 18,634-email benchmark dataset with **99.92% accuracy**.
   - Runs in **~1.5 milliseconds** locally on CPU; bypasses heavier generative AI calls on obvious high-confidence benign emails (`>= 90%` confidence).

3. **Stage G: Generative AI & MITRE ATT&CK Matrix Alignment**:
   - Uses Google Gemini for psychological manipulation analysis (urgency, authority, fear).
   - Maps technical telemetry directly to the **MITRE ATT&CK Enterprise Matrix** (e.g. `T1566.002 Spearphishing Link`, `T1598.003 Spearphishing Service`).
   - Automatic offline fallback to deterministic penalty algorithms if offline or without an API key.

4. **Feature 3: RAG SOC Analyst Assistant (Vector Search & Chat)**:
   - Embeds email threat dossiers into **384-dimensional dense vectors** via SentenceTransformers (`all-MiniLM-L6-v2`).
   - Supports **Single-File Deep Dive** (focuses exclusively on the opened dossier) and **All-Database Search** (brute-force cosine similarity or MongoDB Atlas Vector Search).
   - Strict factual grounding to eliminate hallucinations.

---

## Configuration

Copy `.env.example` to `.env` and configure:

```dotenv
PORT=5000
MONGODB_URI=mongodb+srv://<username>:<password>@<cluster>.mongodb.net/?appName=PhishGuard
USE_FAKE_DB=0
THREAT_INTEL_LIVE=1
ABUSEIPDB_API_KEY=your_abuseipdb_api_key
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GEMINI_API_KEY=your_gemini_api_key
GEMINI_MODEL=gemini-1.5-flash

# Optional Triage & RAG settings
TRIAGE_SAFE_THRESHOLD=0.90
USE_ATLAS_VECTOR_SEARCH=0
```

---

## Quick Start & Verification

### 1. Install Backend Dependencies
```bash
cd backend
python -m pip install -r requirements.txt
```

### 2. Run Unified Diagnostic Verification
Verify that all 3 AI/ML subsystems (OpenCV, XGBoost, and RAG) are operational:
```bash
cd backend
python verify_all_models.py
```

Run the unit test suite (14 passing tests):
```bash
python -m unittest tests/test_image_forensics.py tests/test_triage.py tests/test_rag.py tests/test_api_chat.py
```

### 3. Start the Backend API
```bash
cd backend
python -m uvicorn app:app --reload --port 5000
```

### 4. Start the React Frontend
```bash
cd frontend
npm install
npm run dev
```

Open [http://localhost:5173](http://localhost:5173) in your browser to view the investigation console!
