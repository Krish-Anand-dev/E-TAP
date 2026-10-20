# CLAUDE.md — working notes for E-TAP (hosted edition)

Loaded automatically by Claude Code. Keep it short, current and true; update it whenever a change here would surprise the next session.

## Read first
- `README.md` — user-facing overview.
- `CONTEXT.md` — full technical reference (pipeline stages, API, data shapes, env vars, deployment, known gaps).

## Two repositories, one product
- **E-TAP** (this folder, `C:\Users\Krish Anand\Desktop\E-TAP`): hosted edition (Render backend, Vercel frontend, Atlas). No sandbox. The user commits and pushes here themselves (work branch `frontend_revamp_and_decluttering`, merged to `main` by the user).
- **E-TAPlocal** (`C:\Users\Krish Anand\Desktop\E-TAPlocal`): `E-TAP + VirtualBox sandbox`, run on the user's machine via `start-local.cmd`. It must stay **ahead** of E-TAP: every feature built here must also be applied there without breaking the sandbox. E-TAPlocal is never pushed. It has its own `CLAUDE.md`.
- Shared frontend/backend changes: implement here, then apply the same patch to E-TAPlocal (files are near-identical; E-TAPlocal adds sandbox bits in `pipeline.py`, `app.py`, `DashboardPage.jsx`, `reportSummary.js`, `sandbox.js`, `pdfGenerator.js`, `Header.jsx`, `vite.config.js`). A scripted patch with exact anchors applied to both `frontend/src` trees has worked well.

## User preferences
- Never commit or push unless asked in that turn. Never push E-TAPlocal at all.
- Non-technical users first, analysts second: plain names, big numbers, categories, bold section titles, no emojis (line icons from `components/common/Icon.jsx`).
- Don't show internal plumbing to users (provider status, privacy flows were removed from the report).
- Ask before anything that resets the user's VM or writes to their real MongoDB; test with the in-memory DB.

## Architecture in one breath
`backend/pipeline.py::_run_parsed_pipeline` runs A parse → B headers → B2 static attachments → (S sandbox planning, local only) → D IOCs + B5 links + B6 QR → E threat intel + hop geo → F correlation (stores the record) → F′ graph diffusion → C′ XGBoost triage → G Gemini (or offline fallback) → H verdict/evidence/privacy/provider status → persist → background RAG embedding. `progress(stage, state, detail)` callbacks feed the live timeline.
- `backend/analysis_jobs.py`: `POST /analyze/jobs` + `GET /analyze/jobs/{id}` (in-memory jobs, 9 stages: parse, headers, static_attachments, sandbox, indicators, reputation, history, ai, verdict). `POST /analyze` kept for the Gmail extension.
- `backend/verdicts.py`: single source of truth for labels/thresholds (0/20/40/65/85) and bands; mirrored in `frontend/src/utils/verdict.js` (test enforces parity).
- `backend/evidence.py`: evidence ledger + `evidence_report` (ids `hdr.*`, `att.*`, `qr.*`, `link.*`, `rep.*`, `corr.*`, `ai.*`).
- `backend/workflow_c.py`: retention, review workflow, share pack, baselines. `trusted_sender_check`: a trusted domain lowers risk by 25 **only** if SPF+DKIM+DMARC pass and no spoofing/attachment/reputation findings.
- `backend/rag/chat.py`: SOC assistant; offline answer is a readable summary when no Gemini key.

## Frontend (React 18 + Vite 8, light cream/navy/red theme)
- Styles: `styles/workspace.css` (base) + `styles/v2.css` (all revamp components; loaded last).
- Pages: `OverviewPage` (dashboard numbers from `GET /investigations`), `UploadPage` (live timeline; stages paced by `MIN_STAGE_MS`, `VITE_TIMELINE_PACING=off` disables; Re-analyze), `DashboardPage` (report: sticky tabs, `VerdictHero`, `RiskBreakdown`, `Remediation`, map, `EvidenceBreakdown` radar + MITRE, collapsible details, analyst tools last), `HistoryPage` (Reports: per-stage cards from `stageSummaries`), `SettingsPage` (trusted domains + retention).
- `components/common/TimelineCat.jsx`: animated SVG cat mascot on the Analyze timeline (one scene per stage: book, magnifier, PDF scratch, PDF tear, chain, laptop+globe, detective board, iron-cat suit, notebook). Positioned by `PipelineTimeline` next to the active row; drops with a bounce on each stage change; CSS keyframes `kc-*` in `v2.css`; hidden under 760 px and with reduced motion. Not yet ported to E-TAPlocal.
- `utils/reportSummary.js`: risk categories, key stats, per-stage summaries — the single place that turns a report into UI numbers.
- `context/InvestigationContext.jsx`: `startAnalysis` (job polling), `resetToken` (remounts Analyze page on New analysis), `sourceFiles` (uploaded File per email_id, memory only) + `requestReanalysis` / `rerunRequest` for Re-analyze.

## Run and test
- Backend: `cd backend && python -m uvicorn app:app --port 5000` (needs `.env`; this folder has none — tests use env vars). Frontend: `cd frontend && npm run dev` (proxy to 127.0.0.1:5000).
- Tests: `cd backend && python -m pytest tests -q --ignore=tests/test_threat_intel_live.py` (13 failures in `test_workflow_c_*` are pre-existing: old auth-era tests expect `security.py` etc. to be deleted); `cd frontend && npm test && npx vite build`; `node --test --test-isolation=none extension/tests/*.test.mjs`.
- Browser checks: the user often runs E-TAPlocal on 5000/5173. Don't kill those; run test servers on other ports (e.g. API 5010 with `ALLOWED_ORIGINS` set, UI via `vite build` with `VITE_API_BASE_URL` + `vite preview --port 5183`, output dir outside the repo).

## Known gaps worth remembering
- `dnspython` and `sentence-transformers` not in requirements; caches/limiters are in-process (one worker).
- Keep `CONTEXT.md` (last updated 2026-10-20) and `README.md` in step with any feature change, in both repos.
- Open API: no auth; legacy auth files (`security.py`, `db/scoped.py`, `provision_key.py`) remain but are unused.
