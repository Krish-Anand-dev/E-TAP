# E-TAP — Deployment Guide

This guide documents the current web deployment. The React/Vite frontend and FastAPI backend are deployed separately; MongoDB Atlas holds shared backend records.

## Current team demo URLs

- **Frontend (Vercel):** <https://e-tap-lac.vercel.app/>
- **Backend (Render):** <https://etap-backend-od1c.onrender.com>
- **Backend health:** <https://etap-backend-od1c.onrender.com/health>
- **API docs:** <https://etap-backend-od1c.onrender.com/docs>

The backend root `/` returns a small service index. `GET /health` is a liveness probe only; `GET /ready` makes a database ping and returns HTTP 503 if the database is unavailable. Use `/ready` to check application readiness and inspect Render logs when it fails.

## Architecture

```text
Browser
  └── Vercel: React/Vite static frontend
        └── HTTPS API requests
              └── Render: FastAPI backend (Docker)
                    ├── MongoDB Atlas: etap database
                    └── Optional Gemini / VirusTotal / AbuseIPDB / IP geolocation / WHOIS lookups
```

## 1. MongoDB Atlas

1. Create an Atlas cluster and a dedicated database user with least-privilege access for E-TAP.
2. Set the database name to `etap` and keep the connection URI private.
3. In Atlas Network Access, allow the relevant Render outbound IP ranges for the service's region/plan. The development machine's IP allowlist entry alone does not allow Render to connect.
4. Do not permanently allow `0.0.0.0/0` solely to bypass network errors; use the narrowest workable rule.
5. Use `USE_FAKE_DB=0` and `AUTO_FALLBACK_DB=0` on Render to avoid hiding real database connection problems.

Collections created/used by the application include `analyzed_emails`, `campaigns`, and `counters`. MongoDB Compass can connect to Atlas to inspect these records; Compass itself is not a hosting service.

## 2. Deploy the backend to Render

The current service is named `etap-backend` and uses Docker.

- **Repository:** `bhavitanand/E-TAP`
- **Branch:** `main`
- **Root Directory:** `backend`
- **Docker Build Context Directory:** `backend` (relative to the repository root)
- **Dockerfile Path:** `backend/Dockerfile` (relative to the repository root)
- **Health Check Path:** `/health`
- **Docker Command / Pre-Deploy Command:** leave blank to use the Dockerfile's command
- **Instance:** Free for the initial demo, subject to its resource/sleep limits

Set environment variables in the Render service settings—never commit them. Required/commonly used variables:

```dotenv
MONGODB_URI=<private Atlas URI for the etap database>
MONGO_DB_NAME=etap
USE_FAKE_DB=0
AUTO_FALLBACK_DB=0
THREAT_INTEL_LIVE=1
GEMINI_API_KEY=<private key>
GEMINI_MODEL=gemini-3.5-flash-lite
GEMINI_REQUEST_TIMEOUT_MS=15000
THREAT_INTEL_MAX_LOOKUPS_PER_PROVIDER=2
VIRUSTOTAL_API_KEY=<private key>
ABUSEIPDB_API_KEY=<private key>
ALLOWED_ORIGINS=http://127.0.0.1:5173,http://localhost:5173,https://e-tap-lac.vercel.app
```

Use the model identifier verified for your Gemini account; the value above matches the current code default in `backend/ai_engine/main.py`. Do not manually set `PORT=5000` on Render: the Dockerfile uses Render's injected `PORT` when present and falls back to 5000 locally.

After deploying, confirm the logs show a successful MongoDB Atlas connection. Then test `/health`, upload a harmless/synthetic email through the frontend, and verify its record appears in Atlas. A successful `/health` alone is not proof of database health.

## 3. Deploy the frontend to Vercel

- Import `bhavitanand/E-TAP` from GitHub.
- **Root Directory:** `frontend`
- **Framework Preset:** Vite
- **Install Command:** `npm ci`
- **Build Command:** `npm run build`
- **Output Directory:** `dist`

Add this Vercel environment variable for Production (and Preview only if needed):

```dotenv
VITE_API_BASE_URL=https://etap-backend-od1c.onrender.com
```

The frontend API client reads `import.meta.env.VITE_API_BASE_URL`. Set it on Vercel to `https://etap-backend-od1c.onrender.com` (without `/health` and without a trailing slash). Do not place API keys or the MongoDB URI in Vercel; `VITE_` variables are embedded in client-side frontend code. Redeploy the frontend after changing the variable so the value is included in the new build.

## 4. CORS after deploying the frontend

Set the Render environment variable `ALLOWED_ORIGINS` to a comma-separated list of exact origins, including the deployed Vercel production domain and localhost origins needed for development. For the current team deployment:

```dotenv
ALLOWED_ORIGINS=http://127.0.0.1:5173,http://localhost:5173,https://e-tap-lac.vercel.app
```

If Vercel assigns a different production domain, use that exact hostname instead. Save the environment change and let Render restart/redeploy the service.

## 5. Extension deployment is separate

The extension is distributed separately from the hosted web application. The committed source already targets the current hosted URLs: `extension/background.js` calls the Render API and `extension/content.js` links to the Vercel dashboard. If testing locally, change those constants to localhost and reload the unpacked extension. Confirm that `extension/manifest.json` host permissions allow the selected hosts. The extension is experimental and reconstructs a simplified message from visible Gmail DOM content; it is not raw-message forensics or Gmail OAuth integration.

## 6. Production safety checklist

- Keep `.env`, API keys, credentials, local email artifacts and sensitive investigation exports out of Git.
- Rotate any credentials that were ever exposed in chat, logs, screenshots, commits or public repository history.
- Use least-privilege database credentials and narrow Atlas network access where feasible.
- Understand that live threat intelligence and Gemini may receive indicators or email-derived content.
- Monitor Render logs and provider quotas. Free instances can spin down and have constrained CPU/RAM. Each provider lookup has a bounded timeout; `GEMINI_REQUEST_TIMEOUT_MS` defaults to 15000 ms (clamped 1000–60000), and `THREAT_INTEL_MAX_LOOKUPS_PER_PROVIDER` defaults to 2 (clamped 1–20).
- Treat automated scores as triage, not proof. Test with both benign and suspicious artifacts. Provider coverage in each report distinguishes success, fallback, timeout, rate limits, configuration gaps and intentional policy/privacy skips; unavailable/skipped never means clean.
- The browser History view uses `sessionStorage`; it is not a server-wide history listing endpoint. The backend does expose `GET /investigations/{email_id}` for retrieving an individual stored investigation.
- Do not describe E-TAP as fully local-only, a guaranteed detector, or a full Gmail replacement.

## Workflow C setup changes

See [WORKFLOW-C-README.md](WORKFLOW-C-README.md) for the authoritative feature status, API routes, access model and limitations. The API is open (no keys or sign-in; authentication is documented as future scope). Schedule the retention purge for idle periods. Browser history lasts for the tab session; server deletion is a separate control. Node >=22.12 is required for the patched build tools. Live hosted behavior is not verified.
