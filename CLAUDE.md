# CLAUDE.md — working notes for E-TAP-clean

Loaded automatically by Claude Code. Keep it short, current and true.

## Read first
- `README.md` (overview), `CONTEXT.md` (full technical reference), `docs/whatsapp-bot.md`, `docs/demo-fallback.md`.

## This repo
- `github.com/bhavitanand/E-TAP-clean` (main). Backend on Render (`etap-clean-backend.onrender.com`, auto-deploys on push), frontend on Vercel (`e-tap-clean.vercel.app`), database on Atlas.
- Run tests from `backend/`: `python -m pytest tests -q --ignore=tests/test_threat_intel_live.py` (about 406 pass); frontend: `cd frontend && npm test && npx vite build`.

## Added in November 2026
- **Optional email-code sign-in**: `backend/login.py`, `frontend/src/api/auth.js`, `components/settings/AccountSignIn.jsx`. Never required to analyse; only tags `owner_email` and enables the "My reports" filter.
- **WhatsApp bot (static analysis only)**: `backend/whatsapp.py` (Meta Cloud API route plus a Twilio route), `heavy_gate.py` (one big analysis at a time), report link `?dossier=<email_id>`.
  - **Replies are blocked by Meta, not by our code** (2026-11-15): error 131031 "Business Account locked", because the WhatsApp business account is unverified (no legal business, no payment method). Publishing or unpublishing the app does not help. Do not claim the bot replies live; use `docs/demo-fallback.md`.
  - **One-way mode**: `backend/whatsapp_link.py` links a phone number (HMAC hash only) to an account by the person sending a one-time `ETAP-123456` code to the bot; forwarded messages from a linked number get `owner_email` and show under My reports. UI: Settings > WhatsApp (`components/settings/WhatsAppLink.jsx`). Set `WHATSAPP_REPLIES=0` on Render while Meta blocks replies. `FakeDatabase` gained `$gt`, `$lt` and top-level `$or` for it.
  - The Meta app must be subscribed to the WABA (`POST /{WABA}/subscribed_apps`), otherwise no real messages arrive.
  - Meta test token (`META_ACCESS_TOKEN`) is short-lived; a system-user token is the lasting fix. A token was shared in a chat on 2026-11-15; rotate it.
- **Privacy page**: `frontend/public/privacy.html`, themed like the app; Meta needs this URL.
- Keep-alive is UptimeRobot on `/health` (5 min); the GitHub workflow was removed.

## Gemini and the offline fallback
- On 2026-11-15 Google returned 503/504 on every model for one request, so a report fell back to `offline_fallback` (key was fine). Check Render logs for "Gemini model ... failed". Now: one retry on 503, dead model name removed, honest status text, offline rules catch fee-before-deadline scams. Re-analyse any `offline_fallback` report before showing it.
- Future scope: two-way WhatsApp after Meta verification (`WHATSAPP_REPLIES=1`, system-user token).

## User preferences
- Never commit or push unless asked in that turn. Never print `.env` contents or tokens.
- Ask before anything that writes to the real MongoDB (live analyses save a report) or resets the VM.
- Nothing may hinder a normal user: Standard analysis is the default and never waits on the sandbox.
- Non-technical users first, plain words, no emojis in the UI.
- The user never enters passwords through Claude; account creation, terms and publishing need explicit approval.
