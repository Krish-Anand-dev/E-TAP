# Render accounts: one always-on free service each

> **History from the original team's deployment.** The accounts and addresses below are not this repository's.
> The current backend is `https://etap-v8-backend.onrender.com`.

**Decision (2026-11-15):** E-TAP stays on the main Render account (`bhavitanand.007`), the only service
there. RCPT is deployed on the `bhavitanand.dev` account and the capstone on `anand.007bhavit`, each with
its own UptimeRobot ping, so all three stay awake. Nothing has to move for E-TAP. The rest of this page is
the recipe for putting a backend on a different account (it also covers moving E-TAP later).

## Where everything runs now (2026-11-16)

| Project | Render account | Address | Ping |
|---|---|---|---|
| E-TAP | `bhavitanand.007` (main) | `https://etap-clean-backend.onrender.com` | UptimeRobot, address `/`, 5 min |
| RCPT | `bhavitanand.dev` | `https://rcpt-v3-backend.onrender.com` (frontend `rcpt-v3.vercel.app`) | UptimeRobot, `/api/health`, 5 min |
| Capstone (DarkLens) | `anand.007bhavit` | `https://darklens-capstone.onrender.com` (serves its own dashboard) | UptimeRobot, `/docs`, 5 min |

**UptimeRobot checks with HEAD requests** (the HTTP method is a paid setting). A route that rejects HEAD
shows as "Down 405" even though the service is fine. E-TAP's `/` and RCPT's Express routes accept HEAD.
The capstone's FastAPI routes (`/` and `/api/health`) answer 405 to HEAD, but its built-in `/docs` page
answers 200, so the monitor uses `/docs`. E-TAP had a duplicate monitor on `/health`, which was deleted.

The old `etap-backend` and `RCPT-v3` on the main account are suspended (reversible) so only E-TAP spends
that account's 750 hours. The capstone is one Docker service from `bhavitanand/darkweb-threat-intel-capstone`
(Free, Singapore, no environment variables needed). It keeps its SQLite file inside the container, so data
resets on a restart or redeploy; the demo data reloads at startup. Add `ABUSECH_AUTH_KEY` only if live
feeds are wanted.

## RCPT-v3 (moving from the main account to `bhavitanand.dev`)

On 2026-11-15 the main account held three free services (`etap-clean-backend`, `RCPT-v3`, and an old
`etap-backend` from the older `bhavitanand/E-TAP` repo) sharing one 750-hour allowance (20 used so far
that month, Hobby plan, no card, so overruns suspend rather than charge).

New service on the dev account (the repo is public, so no GitHub link is needed):

| Setting | Value |
|---|---|
| Repository | `https://github.com/bhavitanand/RCPT-v3`, branch `main` |
| Name | a new one, e.g. `rcpt-v3-backend` (the old `rcpt-test-deploy` address is taken until the old service is deleted) |
| Runtime / region / plan | Node, Singapore, Free |
| Root directory | `backend` |
| Build / start | `npm install` / `node server.js` |
| Health check path | `/api/health` |
| Env: `PORT` | same value as the old service |
| Env: `ALLOWED_ORIGINS` | same value as the old service (the frontend's address) |
| Env: `GEMINI_MODEL` | same value as the old service |
| Env: `GEMINI_API_KEY`, `ETHERSCAN_API_KEY` | copy from the old service's Environment page (paste them yourself) |

**Status (2026-11-15):** the new service `rcpt-v3-backend` is created and live on the dev account at
`https://rcpt-v3-backend.onrender.com` (Free plan, Singapore, root `backend`; `/api/health` returns 200,
Bitcoin, Solana and Tron ready). Still to do: paste `ETHERSCAN_API_KEY`, `GEMINI_API_KEY`, `GEMINI_MODEL`
(optional, defaults to `gemini-3.5-flash-lite`) and `ALLOWED_ORIGINS` (the RCPT frontend's Vercel address)
into the new service's Environment page with "Add from .env"; point the frontend's `VITE_API_URL` at the
new address; add the UptimeRobot monitor; then suspend the old `RCPT-v3` service on the main account.
Render sets `PORT` itself, so it does not need to be copied.

Then: set the RCPT frontend's `VITE_API_URL` (read by `frontend/src/api.ts`) to the new address with no
trailing slash and redeploy it; add an UptimeRobot monitor on `https://<new-name>.onrender.com/api/health`
every 5 minutes; check the site works; and only then suspend or delete the old `RCPT-v3` service.
The old `etap-backend` (older E-TAP repo) can be suspended too if nothing uses it, so it never wakes and
spends hours.

Why: Render's free plan gives each **workspace** (account) 750 free instance hours a month. One
always-on service (kept awake by the UptimeRobot ping) uses about 720 to 744 hours, so only one
always-on free service fits per workspace. A second one would be suspended until next month.

What Render allows: a service **cannot be transferred** between workspaces. You recreate it in the
new workspace. The database (MongoDB Atlas), the frontend (Vercel) and the code do not move, so no data
is lost; only the backend's address changes.

## What changes when the backend moves

| Where | What to update |
|---|---|
| New Render service | Create it from `render.yaml` (Blueprint) or by hand; copy the environment variables |
| Render env `PUBLIC_API_URL` | the new `https://<new-name>.onrender.com` (used to check Twilio signatures; keep correct anyway) |
| Render env `ALLOWED_ORIGINS` | unchanged (the frontend address does not move) |
| Vercel `VITE_API_BASE_URL` | the new backend URL (no trailing slash), then **Redeploy** |
| Meta, WhatsApp, Configuration, Webhook | Callback URL `https://<new-name>.onrender.com/whatsapp/meta`, same verify token, **Verify and save** |
| UptimeRobot | edit the monitor to the new service root `/` (and delete the old service's monitor) |
| Repo defaults | `extension/config.js`, `extension/manifest.json`, `backend/sandbox_agent/config.py`, `backend/sandbox_agent/start-agent.cmd`, `render.yaml`, docs: replace `etap-clean-backend.onrender.com` |
| Gmail extension / sandbox agent | reload the unpacked extension; re-download the agent zip (it carries the server address) |

Nothing else references the old URL. Your WhatsApp link, reports and login sessions live in Atlas and
keep working (`AUTH_SECRET` must stay the same or sign-in codes and sessions become invalid).

## Steps (zero downtime)

1. **Sign in to the other Render account.** New, Blueprint (or New, Web Service).
2. **Source:** the repo `bhavitanand/E-TAP-clean` is public, so you can paste its URL without linking
   GitHub. For auto-deploy on every push, connect the GitHub account to this Render account instead
   (a manual deploy works without it).
3. **Name:** the name `etap-clean-backend` is taken while the old service exists, so pick a new one, for
   example `etap-clean-backend-2`. (Deleting the old service first frees the name but means downtime and
   no guarantee the name is released at once.) Region **Singapore**, plan **Free**, Docker, root
   directory `backend`. `render.yaml` already has these.
4. **Environment variables:** copy every variable from the old service (Environment page, reveal each
   value, or use "Add from .env"). They are: `MONGODB_URI`, `MONGO_DB_NAME`, `GEMINI_API_KEY`,
   `GEMINI_MODEL`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY`, `THREAT_INTEL_LIVE`, `ALLOWED_ORIGINS`,
   `PUBLIC_API_URL`, `PUBLIC_FRONTEND_URL`, `CLOUDINARY_*`, `AUTH_SECRET`, `BREVO_API_KEY`,
   `RESEND_API_KEY` (if used instead of Brevo), `LOGIN_FROM_EMAIL`, `LOGIN_FROM_NAME`, `META_PHONE_NUMBER_ID`, `META_ACCESS_TOKEN`, `META_APP_SECRET`,
   `META_VERIFY_TOKEN`, `WHATSAPP_REPLIES`, `WHATSAPP_BOT_NUMBER`. Set `PUBLIC_API_URL` to the new address.
5. **Check it:** open `https://<new-name>.onrender.com/health` (200) and `/auth/status` (`enabled: true`).
6. **Cut over, in this order:** Vercel `VITE_API_BASE_URL` and redeploy; Meta webhook callback and
   Verify and save; UptimeRobot monitor. Send "hi" to the bot and check Render's log shows
   `POST /whatsapp/meta 200` on the new service.
7. **Only then** suspend or delete the old service (so its hours stop counting on the old account).
8. Update the repo defaults listed above, push, and rebuild the extension.

## Atlas

Atlas must accept the new service. If its Network Access list is `0.0.0.0/0` (the usual setting for Render
free services, whose addresses change) nothing is needed; otherwise add the new service's outbound addresses.

## Two always-on services on two accounts

Each account has its own 750 hours, so E-TAP on one account and the capstone backend on another can both
stay awake 24/7 with UptimeRobot pings every 5 minutes. Keep each account to **one** always-on free web
service.
