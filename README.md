# E-TAP (Email-TAP)

**The one-tap email forensics and protection platform** — bridging the gap between cybersecurity professionals and everyday email users.

E-TAP is a defensive email-artifact analysis application. The current product consists of a React/Vite dashboard and a Python/FastAPI forensic backend. It analyzes uploaded `.eml` and `.msg` artifacts. **It is not a Gmail replacement or a full email client.** The browser extension is an experimental Gmail overlay.

## Current deployment

These are the team's current demo deployments. Update this section if the service URLs change.

- **Frontend:** <https://e-tap-lac.vercel.app/>
- **Backend health endpoint:** <https://etap-backend-od1c.onrender.com/health>
- **Interactive API documentation:** <https://etap-backend-od1c.onrender.com/docs>

The backend API does not define a homepage route, so opening the backend's bare URL may return `{"detail":"Not Found"}`. Use `/health` or `/docs` to check the service.

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
- `extension/` — experimental Manifest V3 Gmail overlay. Its source currently defaults to localhost URLs; see the extension section below before using it with the hosted deployment.
- `samples/` — dataset manifests and sample-corpus notes. The raw `.eml`/`.msg` files referenced in the manifests are not committed.
- `DEPLOYMENT.md` — current Render/Vercel/Atlas deployment guide.
- `SETUP.md` — local development setup.
- `work.md` — current project status and follow-up work.

## Run locally (Windows PowerShell)

For a single command that starts both services, installs dependencies on first
use, and automatically connects the frontend to a random available backend port:

```powershell
.\start-local.cmd --install --memory-db
```

Add your keys to the generated root `.env`: `GEMINI_API_KEY`,
`VIRUSTOTAL_API_KEY`, and `ABUSEIPDB_API_KEY`. `THREAT_INTEL_LIVE=1` keeps live
lookups enabled. Restart the launcher after editing `.env`. The dashboard opens
automatically; upload your `.eml`/`.msg` to receive the full pipeline report.
Both services bind to `127.0.0.1`. Press Ctrl+C to stop them.

`--memory-db` uses temporary storage and loses server-side investigations on
shutdown. For persistent history/correlation, configure local MongoDB or Atlas
in `.env` and omit `--memory-db`. Later launches can omit `--install`:

```powershell
.\start-local.cmd --memory-db
```

Use `--backend-port 5000` to prefer a specific backend port, or
`--frontend-port 5174` to prefer a different frontend port. Busy preferred ports
fall back to an available port; the launcher prints both actual URLs.
Python 3.10+ (3.11/3.12 recommended) and Node.js 20+ are required. On other
platforms use `python start-local.py --install --memory-db`.

### Manual two-terminal setup

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

- `GET /health` — returns `{"status":"ok"}`; this endpoint does not verify MongoDB health by itself.
- `POST /analyze` — multipart upload with a `file` field containing an `.eml` or `.msg`; the backend enforces a 25 MB limit and rate-limits this endpoint.
- `POST /chat` — SOC Assistant request containing `question`, with optional `email_id` and `email_context` for active-report context.
- `GET /investigations/{email_id}` — fetch one stored investigation by its database ID/email ID.
- `/docs` — FastAPI-generated interactive API docs when enabled by the deployment.

## Gmail extension (experimental)

The extension is an early prototype, **not an official Gmail integration**. It watches visible Gmail DOM content, reconstructs a simplified plain-text `.eml` from the sender, subject and visible body, and submits that reconstructed artifact to the configured API. It does not access the original raw Gmail message, reliably retain full original headers, or process original attachments as the user received them. It scans visible messages automatically, so use only a dedicated test mailbox with non-sensitive messages.

To load it locally in Chrome or Brave:

1. Keep the local backend running.
2. Open `chrome://extensions` (or `brave://extensions`) and enable Developer mode.
3. Choose **Load unpacked** and select the repository's `extension/` folder.
4. Open the dedicated test mailbox and monitor the extension console and backend logs.

The extension currently defaults to `http://127.0.0.1:5000` for the API and `http://127.0.0.1:5173` for the dashboard. To point it at the hosted service, update `ETAP_API_BASE_URL` in `extension/background.js` to `https://etap-backend-od1c.onrender.com` and `ETAP_APP_BASE_URL` in `extension/content.js` to `https://e-tap-lac.vercel.app`, verify the host permissions in `extension/manifest.json`, and reload the unpacked extension. The code change is separate from deploying the website.

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

## Team

- Bhavit Anand
- Krish Anand
- Yashmit Kamal

## Project statement

E-TAP translates technical email-forensics findings into clear, evidence-backed explanations and practical next steps for ordinary users, while retaining deeper investigative detail for security practitioners.
