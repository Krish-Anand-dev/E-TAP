# E-TAP — Local Setup

This guide runs the existing web application on a Windows development machine. It does not package a Tauri desktop app.

## Single-command startup (recommended)

From the repository root:

```powershell
.\start-local.cmd --install --memory-db
```

This creates `.venv`, installs backend and frontend dependencies, creates `.env`
from `.env.example` if absent, and starts both services. It preserves existing
`.env` files. Python 3.10+ and Node.js 20+ must be installed. If the Windows Python
launcher is unavailable, use your Python 3.10+ executable to run
`start-local.py --install --memory-db` directly.

Fill these placeholders in the root `.env`, then restart:

```dotenv
GEMINI_API_KEY=
VIRUSTOTAL_API_KEY=
ABUSEIPDB_API_KEY=
THREAT_INTEL_LIVE=1
```

Provider keys stay on the backend. No frontend key configuration is necessary.
Empty keys allow fallback analysis, and the startup output identifies unconfigured
providers. Existing metadata triage can still skip Gemini for high-confidence
benign messages. Provider availability, quotas and the configured Gemini model
still determine whether live analysis succeeds.

The frontend prefers `http://127.0.0.1:5173`. The backend uses a random available
port. The launcher prints the actual URLs and opens the dashboard, where you can
upload an `.eml`/`.msg` and view/export its report. The frontend proxy forwards
analysis, health, chat and investigation requests to the selected backend.
The launcher overrides deployed `VITE_API_BASE_URL` values for this local session.

After the first install, run `.\start-local.cmd --memory-db`. Ctrl+C stops both
services. Optional arguments: `--no-browser`, `--backend-port 5000`,
`--frontend-port 5174`. If a preferred port is busy an available port is selected.

`--memory-db` is explicitly temporary: stored investigations and correlation data
are lost on shutdown. For persistent storage, run MongoDB locally or set an Atlas
URI in `.env`, use `USE_FAKE_DB=0`, and launch `.\start-local.cmd` without
`--memory-db`. The launcher checks the database before starting the services.

The manual setup below remains available when you prefer separate terminals.

## Prerequisites

- Python 3.11 (recommended; the Docker image uses Python 3.11).
- Node.js 20+ and npm.
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

Check <http://127.0.0.1:5000/health>. It should return `{"status":"ok"}`. Note that this health route confirms the HTTP process responds; check the backend startup logs separately to confirm a real MongoDB connection.

If activation is blocked by PowerShell policy, use `.venv\Scripts\python.exe` directly for the install and Uvicorn commands.

## 3. Install and start the frontend

Open a second terminal at the repository root:

```powershell
cd frontend
npm ci
npm run dev
```

Open <http://127.0.0.1:5173/>. The Vite development proxy forwards `/analyze`, `/health`, `/chat`, and `/investigations` to `http://127.0.0.1:5000`. Leave `VITE_API_BASE_URL` unset in local development unless you intentionally want to bypass that proxy.

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

By default, `extension/background.js` targets `http://127.0.0.1:5000`, and `extension/content.js` links to `http://127.0.0.1:5173`. The extension scrapes visible Gmail DOM content and constructs a simplified message; it does not recover the original raw message and its complete headers/attachments. To use the hosted deployments, change those two constants to the Render and Vercel URLs noted in `README.md`, confirm `manifest.json` host permissions, then reload the unpacked extension.

## Troubleshooting

- **Backend won't start:** activate `.venv`, reinstall `backend/requirements.txt`, and run Uvicorn from `backend/`.
- **MongoDB connection error:** check the URI, database user/password, percent-encoding of reserved password characters, and Atlas Network Access. Confirm startup logs say which database was connected.
- **Frontend says Engine Offline:** test `/health`, verify `VITE_API_BASE_URL` in the deployed build if applicable, and ensure the backend's `ALLOWED_ORIGINS` includes the exact browser origin.
- **CORS error:** update `ALLOWED_ORIGINS` on the backend, save/restart it, and use the exact scheme + hostname (no path or trailing slash).
- **Gemini or intelligence lookup fails:** test with the live integrations disabled first, then check provider model availability, credentials, network access and quota.
- **History differs between browsers:** the History page is currently backed by browser `localStorage`; it is not a shared all-investigations list from the server.
