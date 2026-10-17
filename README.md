# E-TAP (Email-TAP)

**The one-tap email forensics and protection platform** — bridging the gap between cybersecurity professionals and everyday email users.

E-TAP is a defensive email-artifact analysis application. The current product consists of a React/Vite dashboard and a Python/FastAPI forensic backend. It analyzes uploaded `.eml` and `.msg` artifacts. **It is not a Gmail replacement or a full email client.** The browser extension is an experimental Gmail overlay.

## Current deployment

These are the team's current demo deployments. Update this section if the service URLs change.

- **Frontend:** <https://e-tap-lac.vercel.app/>
- **Backend health endpoint:** <https://etap-backend-od1c.onrender.com/health>
- **Interactive API documentation:** <https://etap-backend-od1c.onrender.com/docs>

The backend root `/` returns a small service index. `GET /health` is a liveness check only; `GET /ready` also checks database connectivity and returns HTTP 503 when the database is not ready. Use `/docs` for interactive API documentation.

> **Workflow C access model:** current source requires personal API keys and isolates investigations, RAG and campaigns by owner. The hosted deployment has not been verified against this source. See [WORKFLOW-C-README.md](WORKFLOW-C-README.md) for migration, limitations and the pre-deploy checklist.

## Capabilities

- Parse supported `.eml` and `.msg` artifacts and normalize message content.
- Inspect email headers and authentication-related results (SPF, DKIM, DMARC where evidence is available), received chains, and sender/domain indicators.
- Inspect attachments using SHA-256 hashing, file-signature/type checks, macro-oriented static analysis, and image OCR/QR analysis where applicable dependencies are available.
- Extract indicators of compromise (IOCs), including IPs, domains, URLs and hashes.
- Optionally enrich indicators through AbuseIPDB, VirusTotal, IP geolocation and WHOIS lookups.
- Run XGBoost metadata triage and optional Gemini-assisted assessment, including evidence-oriented explanations and MITRE ATT&CK mappings.
- Correlate analyses with previously stored indicators and campaign records in MongoDB.
- Display analysis reports, maps/graphs where relevant, and export reports from the frontend.
- Provide a SOC Assistant that can answer about the active report or search stored investigations.

Capabilities depend on the artifact, environment configuration, provider availability and API quotas. Results are triage assistance—not proof that an email is malicious or safe. Review the evidence before taking action.

## Architecture

```text
Browser (React/Vite dashboard)
        │ HTTP requests
        ▼
FastAPI backend (backend/app.py)
        ├── email parsing and forensic pipeline
        ├── optional external threat-intelligence and Gemini APIs
        ├── correlation and RAG/SOC Assistant
        └── MongoDB local server or MongoDB Atlas
```

## Repository layout

- `frontend/` — React/Vite dashboard and report views.
- `backend/` — FastAPI API, pipeline, forensic modules, database, threat-intelligence integrations and RAG assistant.
- `extension/` — experimental Manifest V3 Gmail overlay. Its committed source targets the current hosted demo URLs; see the extension section below for switching to local development.
- `samples/` — dataset manifests and sample-corpus notes. The raw `.eml`/`.msg` files referenced in the manifests are not committed.
- `DEPLOYMENT.md` — current Render/Vercel/Atlas deployment guide.
- `SETUP.md` — local development setup.
- `WORKFLOW-B-README.md` — the single consolidated record for Workflow B, including B0–B11 behavior, tests, limitations and the pre-Workflow-C gate.
- `work.md` — current project status and next actions (not a per-stage changelog).

## Run locally (Windows PowerShell)

Recommended prerequisites: Python 3.11, Node.js 20+, npm, and either a local MongoDB Community Server or a MongoDB Atlas database. MongoDB Compass is a GUI client; it does not run the MongoDB server itself.

From the repository root, create `.env` **only if it does not already exist**:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

Edit `.env`. For a no-key local smoke test, set `USE_FAKE_DB=1`, `THREAT_INTEL_LIVE=0`, and leave provider keys empty. The fake database is in-memory and loses its data when the backend process exits. For persistent data, set `USE_FAKE_DB=0` and configure a real MongoDB URI.

Install dependencies and start the backend in the first terminal:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
cd backend
python -m uvicorn app:app --host 127.0.0.1 --port 5000
```

In a second terminal, from the repository root:

```powershell
cd frontend
npm ci
npm run dev
```

Open <http://127.0.0.1:5173/>. In development, Vite proxies API routes to `http://127.0.0.1:5000`, so `VITE_API_BASE_URL` can remain unset locally. Check <http://127.0.0.1:5000/health> for the API health response.

If PowerShell blocks virtual-environment activation, run the venv's executables directly, for example `.venv\Scripts\python.exe -m pip install -r backend\requirements.txt`.

## MongoDB: local server, Compass and Atlas

- **Local database:** install and start MongoDB Community Server. Connect Compass to `mongodb://localhost:27017`, and set `MONGODB_URI=mongodb://localhost:27017/etap` plus `MONGO_DB_NAME=etap` in `.env`.
- **Cloud database:** create a MongoDB Atlas cluster and a least-privilege database user. Put the Atlas URI in the backend environment. Add the backend host's outbound addresses to Atlas Network Access as appropriate. Compass can connect to the same Atlas URI to inspect collections.
- Use `USE_FAKE_DB=0` and `AUTO_FALLBACK_DB=0` when you want to confirm the real database is being used; do not allow a silent in-memory fallback to hide a broken connection.
- Never commit `.env`, database URIs, passwords, API keys, or sensitive message artifacts. URL-encode reserved characters in passwords embedded in a MongoDB URI.

The application stores analysis and campaign data in the `etap` database (including `analyzed_emails`, `campaigns`, and `counters`). The History tab in the browser currently stores its display list in that browser's local storage; it is not a shared server-side list endpoint. Individual stored reports can be fetched by ID through `GET /investigations/{email_id}`.

## Provider API keys and privacy

Create fresh keys under your own provider accounts and store them only in the backend's local `.env` or the hosting provider's backend environment settings. Never put secrets in Vercel frontend environment variables or source code.

- `GEMINI_API_KEY` — enables Gemini-assisted assessment and chatbot generation where the code path calls the model.
- `GEMINI_MODEL` — model identifier accepted by the configured Gemini API key; the code default is `gemini-3.5-flash-lite`.
- `VIRUSTOTAL_API_KEY` — optional URL/file-hash reputation lookups.
- `ABUSEIPDB_API_KEY` — optional public-IP reputation lookups.
- `THREAT_INTEL_LIVE=1` — enables live lookups where implemented; `0` disables live threat-intelligence requests.

Live lookups may send IOCs or derived indicators to third-party services. Gemini prompts may include email-related content and forensic evidence. Review provider terms and the data sent before analyzing sensitive messages. A locally running dashboard does not mean all processing remains local.

## Main API endpoints

- `GET /` — small service index with links to health, readiness and docs.
- `GET /health` — liveness only; confirms the HTTP process can respond, not that MongoDB is reachable.
- `GET /ready` — readiness check with a database ping; returns HTTP 503 when the configured database is unavailable.
- `POST /analyze` — multipart upload with a `file` field containing an `.eml` or `.msg`; the backend enforces a 25 MB limit and rate-limits this endpoint.
- `POST /chat` — SOC Assistant request containing `question`, with optional `email_id` and `email_context` for active-report context.
- `GET /investigations/{email_id}` — fetch one stored investigation by its database ID/email ID.
- `/docs` — FastAPI-generated interactive API docs when enabled by the deployment.

## Gmail extension (experimental)

The extension is an early prototype, **not an official Gmail integration**. It adds an **Analyze this email** button above an opened message; nothing is read from the message or sent anywhere until you click it. On click it reconstructs a simplified plain-text `.eml` from the sender, subject and visible body and submits that to the configured API as a **Quick Content Check**. It does not access the original raw Gmail message: original headers (SPF/DKIM/DMARC, routing), link targets and attachments are reported as *not available*. For full forensics, upload the original `.eml`/`.msg` in the dashboard. The result banner shows whether threat intelligence was live or offline and whether Gemini or the offline fallback produced the assessment. Use only a dedicated test mailbox with non-sensitive messages.

To load it locally in Chrome or Brave:

1. Keep the local backend running.
2. Open `chrome://extensions` (or `brave://extensions`) and enable Developer mode.
3. Choose **Load unpacked** and select the repository's `extension/` folder.
4. Open the dedicated test mailbox and monitor the extension console and backend logs.

The committed extension targets the current hosted demo: `https://etap-backend-od1c.onrender.com` for the API and `https://e-tap-lac.vercel.app` for the dashboard. For local development, change `ETAP_API_BASE_URL` in `extension/background.js` to `http://127.0.0.1:5000` and `ETAP_APP_BASE_URL` in `extension/content.js` to `http://127.0.0.1:5173`, then reload the unpacked extension. Extension code changes are separate from website deployments.

Do not distribute this prototype to general users until consent, permissions, security review, authentication/access control, data minimization, error handling and provider policy compliance have been addressed.

## RAG/SOC Assistant notes

The assistant can use the active report as context, or retrieve up to five relevant historical investigation summaries from MongoDB and ask Gemini to formulate an answer. The default historical search is an in-memory cosine-similarity pass over stored records. On Render, `backend/rag/embeddings.py` deliberately uses a deterministic hash-based fallback embedder to avoid loading a large PyTorch model in the constrained instance; it is not equivalent to a trained semantic embedding model. `sentence-transformers` is optional and is not listed in `backend/requirements.txt`.

`USE_ATLAS_VECTOR_SEARCH=1` is an optional path only if the Atlas Vector Search index is configured as expected by `backend/rag/chat.py` (default index name `vector_index`, field `rag_embedding`, 384-dimensional vectors). It is not required for the default cosine-similarity search. Do not enable this setting without first creating and validating the matching Atlas index and stored embeddings.

## Deployment

See [DEPLOYMENT.md](DEPLOYMENT.md) for the deployed Render/Vercel/Atlas configuration and production safety notes. See [SETUP.md](SETUP.md) for expanded local instructions.

## Current limitations

- There is no Gmail OAuth/mailbox synchronization, sending, inbox management, or full Gmail parity.
- The extension reconstructs message content from the rendered Gmail DOM; it is not raw-message forensics.
- The browser History list is local to that browser's local storage, although analysis records are stored in MongoDB.
- The deployed RAG path uses fallback hash embeddings unless configured otherwise; retrieved content and answer quality must be validated.
- Live external services can fail, rate-limit requests, or receive IOCs/content-derived data.
- Automated verdicts can produce false positives and false negatives. Treat risk scores as triage, not certainty.
- Tauri desktop packaging and a managed local Python sidecar are future work, not part of the current hosted web deployment.

## Team Members

- Bhavit Anand
- Krish Anand
- Yashmit Kamal

## Project statement

E-TAP translates technical email-forensics findings into clear, evidence-backed explanations and practical next steps for ordinary users, while retaining deeper investigative detail for security practitioners.

## Workflow C setup changes

See [WORKFLOW-C-README.md](WORKFLOW-C-README.md) for the authoritative feature status, API routes, security model and limitations. Data routes require personal Bearer keys; set ETAP_API_KEYS digest entries, migrate ownerless records, and schedule retention purge before deployment. Configure the extension key in its options page. Browser history now lasts for the signed-in tab session; server deletion is a separate control. Node >=22.12 is required for the patched build tools. Quotas currently require a single backend worker. Live hosted behavior is not verified.
