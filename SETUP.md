# E-TAP — Local Setup

This guide runs the existing web application on a Windows development machine. It does not package a Tauri desktop app.

## Prerequisites

- Python 3.11 (recommended; the Docker image uses Python 3.11).
- Node.js >=22.12 and npm.
- For persistent local storage: MongoDB Community Server. MongoDB Compass is a GUI client, not the database server.
- Optional provider API keys for Gemini and live threat intelligence.

## 1. Create and configure `.env`

Run these commands from the repository root. The conditional avoids overwriting an existing `.env`:

```powershell
if (-not (Test-Path .env)) { Copy-Item .env.example .env }
```

Edit `.env` before starting the backend. For a first no-key test, use:

```dotenv
USE_FAKE_DB=1
AUTO_FALLBACK_DB=0
THREAT_INTEL_LIVE=0
GEMINI_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
```

The fake database is ephemeral and is cleared when the backend process exits. For persistent local MongoDB, use `USE_FAKE_DB=0` with `MONGODB_URI=mongodb://localhost:27017/etap` and `MONGO_DB_NAME=etap`. For Atlas, use the Atlas URI and ensure Network Access permits your development machine.

Keep real credentials in `.env` only. The root `.gitignore` excludes it; `.env.example` is the commit-safe template.

## 2. Install Python dependencies and start the backend

From the repository root:

```powershell
py -3.11 -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r backend\requirements.txt
cd backend
python -m uvicorn app:app --host 127.0.0.1 --port 5000
```

Check <http://127.0.0.1:5000/health> for liveness. It should return `{"status":"ok","check":"liveness"}`. Check <http://127.0.0.1:5000/ready> for database readiness; with a reachable real database it returns `{"status":"ready","checks":{"database":"ok"}}`. Startup logs remain useful for diagnosis.

If activation is blocked by PowerShell policy, use `.venv\Scripts\python.exe` directly for the install and Uvicorn commands.

## 3. Install and start the frontend

Open a second terminal at the repository root:

```powershell
cd frontend
npm ci
npm run dev
```

Open <http://127.0.0.1:5173/>. The Vite development proxy forwards `/analyze`, `/health`, `/ready`, `/chat`, and `/investigations` to `http://127.0.0.1:5000`. Leave `VITE_API_BASE_URL` unset in local development unless you intentionally want to bypass that proxy.

## 4. MongoDB Compass

### Local MongoDB

1. Install and start MongoDB Community Server.
2. In Compass, connect to `mongodb://localhost:27017`.
3. Set `MONGODB_URI=mongodb://localhost:27017/etap` and `MONGO_DB_NAME=etap` in `.env`.

### MongoDB Atlas

1. Create an Atlas database user with only the permissions needed for E-TAP.
2. Copy the Atlas connection string and use the `etap` database.
3. Add the development machine's current public IP in Atlas Network Access.
4. Connect Compass using the same URI to inspect `analyzed_emails`, `campaigns`, and `counters`.

Compass connects to a MongoDB server; it does not move or sync local data to Atlas. To migrate existing local records, export and import the appropriate collections separately. URL-encode reserved characters in a password embedded in the URI.

## 5. External APIs

Use fresh keys from your own provider accounts. Set them in `.env` locally and in the backend host's environment settings for deployment. Do not place secrets in frontend environment variables.

- `GEMINI_API_KEY` and `GEMINI_MODEL` enable Gemini-powered assessment/chat where used.
- `VIRUSTOTAL_API_KEY` enables URL/hash reputation lookup.
- `ABUSEIPDB_API_KEY` enables public-IP reputation lookup.
- `THREAT_INTEL_LIVE=1` enables live threat-intelligence lookups supported by the code; `0` keeps those lookups disabled.

Live queries transmit indicators to external services. Gemini prompts may contain email-derived text and evidence. Use synthetic test messages until your data-sharing and retention requirements have been reviewed.

## 6. Load the Gmail extension (experimental)

1. Start the backend.
2. Open `chrome://extensions` in Chrome or `brave://extensions` in Brave.
3. Enable Developer mode and click **Load unpacked**.
4. Select the repository's `extension/` folder.
5. Test with a dedicated, non-sensitive mailbox.

The committed `extension/background.js` targets the hosted Render API and `extension/content.js` links to the hosted Vercel dashboard. For local development, change those constants to `http://127.0.0.1:5000` and `http://127.0.0.1:5173`, confirm `manifest.json` host permissions, then reload the unpacked extension. The extension reads visible Gmail DOM content and constructs a simplified message; it does not recover the original raw message and its complete headers/attachments.

## Troubleshooting

- **Backend won't start:** activate `.venv`, reinstall `backend/requirements.txt`, and run Uvicorn from `backend/`.
- **MongoDB connection error:** check the URI, database user/password, percent-encoding of reserved password characters, and Atlas Network Access. Confirm startup logs say which database was connected.
- **Frontend says Engine Offline:** test `/health`, verify `VITE_API_BASE_URL` in the deployed build if applicable, and ensure the backend's `ALLOWED_ORIGINS` includes the exact browser origin.
- **CORS error:** update `ALLOWED_ORIGINS` on the backend, save/restart it, and use the exact scheme + hostname (no path or trailing slash).
- **Gemini or intelligence lookup fails:** test with the live integrations disabled first, then check provider model availability, credentials, network access and quota.
- **History differs between browsers:** the History page is currently backed by browser `sessionStorage`; it is not a shared all-investigations list from the server.

## Workflow C setup changes

See [WORKFLOW-C-README.md](WORKFLOW-C-README.md) for the authoritative feature status, API routes, access model and limitations. The API is open (no keys or sign-in; authentication is documented as future scope). Schedule the retention purge for idle periods. Browser history lasts for the tab session; server deletion is a separate control. Node >=22.12 is required for the patched build tools. Live hosted behavior is not verified.
