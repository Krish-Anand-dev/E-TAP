# CLAUDE.md — working notes for E-TAP (hosted edition)

Loaded automatically by Claude Code. Keep it short, current and true; update it whenever a change here would surprise the next session.

## Read first
- `README.md` — user-facing overview.
- `CONTEXT.md` — full technical reference (pipeline stages, API, data shapes, env vars, deployment, known gaps).

## One codebase (from 2026-10-24)
- **E-TAP** (this folder) is the only codebase going forward: hosted on Render (backend), Vercel (frontend) and Atlas. The user commits and pushes here themselves (work branch `frontend_revamp_and_decluttering`, merged to `main` by the user).
- **E-TAPlocal** (the old sandbox edition, a separate folder that is not part of this checkout) is **reference only**. Its sandbox code now lives in `backend/sandbox/` and `backend/sandbox_agent/`; do not keep it in sync and never push it.
- The user keeps two copies of the repo (GitHub Desktop and a projects folder, with older versions beside it in `E-TAP-v1`/`v2`/`v3` style folders) and copies files between them after fetching origin. Do not assume one copy is the git working tree; check before running git commands.
- Next feature: dynamic attachment analysis through a user-paired sandbox agent (`SANDBOX_BACKEND=agent`). Decision record: `Development notes and iterations/2026-10-24 Sandbox agent direction.md`.
- `Development notes and iterations/` records the project's history, research and decisions; add a dated entry there for each major iteration. Personal or strategy notes go in the untracked `CLAUDE.local.md`, never in tracked files.

## User preferences
- **First priority: nothing we build may hinder a normal user.** Standard (static) analysis is the default and must never wait on the sandbox. The choice between Standard and Deeper is shown up front, in the extension banner and on the Analyze page, with what Deeper needs written out (the team decided against hiding it: adding Deeper after a Standard run means re-running the whole pipeline, including rate-limited VirusTotal lookups). Dynamic analysis is an opt-in for people who own a VM.
- Never commit or push unless asked in that turn.
- Never print `.env` contents (real keys and the guest password live there).
- Non-technical users first, analysts second: plain names, big numbers, categories, bold section titles, no emojis (line icons from `components/common/Icon.jsx`).
- Don't show internal plumbing to users (provider status, privacy flows were removed from the report).
- Ask before anything that resets the user's VM or writes to their real MongoDB; test with the in-memory DB.

## Architecture in one breath
`backend/pipeline.py::_run_parsed_pipeline` runs A parse → B headers → B2 static attachments → S sandbox planning (`_sandbox_plan`) → D IOCs + B5 links + B6 QR → E threat intel + hop geo → F correlation (stores the record) → F′ graph diffusion → C′ XGBoost triage → G Gemini (or offline fallback) → H verdict/evidence/privacy/provider status → persist → S submit (`_submit_to_sandbox`, background) → background RAG embedding. `progress(stage, state, detail)` callbacks feed the live timeline.
- Stage S (deeper attachment analysis, built 2026-10-24): `sandbox/` (server: `SANDBOX_BACKEND` agent|virtualbox|replay|none, `agent_queue.py` pairing + Mongo job queue, `analysis.py` shared rule evaluation + scoring, `worker.py` local VM queue), `sandbox_agent/` (the user-side agent, stdlib only: `cli.py`, `runner.py` = the one VM run used by agent and local worker, `vbox.py`, DPAPI-sealed config), `sandbox_api.py` (router; `/sandbox/{id}` is declared last). Agent status is truthful: `online` = agent seen or mid-run, `ready` = online + VM health ok (health rides on each `jobs/next` poll from `recon.vm_health`), `problem` = why not. Setup must verify the guest login against the real VM (`cli.verify_guest`; `AgentConfig.is_set_up` requires `login_verified`). `SANDBOX_BACKEND` defaults to `agent`. Every backend runs only on request: `deep_analysis=1` (+ `X-ETAP-Sandbox-Token` for agent mode). Standard is the default everywhere; Deeper is optional (a card next to Standard on the Analyze page and in the extension banner) and pairs inline (`SandboxPairing compact`). Expired jobs and orphaned samples are swept on enqueue and by `start_housekeeping` (agent_queue.py). Score only goes up (65 / 85 floors).
- Deeper analysis pre-run: `utils/attachmentPreview.js` previews the staged .eml's attachments in the browser (its openable-type list mirrors `sandbox/policy.py`; a test fails if they drift) and `analyze()` in `UploadPage` makes a fresh sandbox check before starting, offering Run standard / Run deeper anyway / Cancel. The timeline row says why nothing was opened.
- Frontend sandbox bits: `utils/sandbox.js`, `components/report/SandboxPanel.jsx`, `DashboardPage` `sec-sandbox` + 4 s polling, `reportSummary.js` `hasSandbox`/`sandboxItems`/`sandboxStage`, `api/sandbox.js` (token in localStorage), Upload page deeper toggle, `components/settings/SandboxPairing.jsx`. Extension 1.6.1: `content.js` shows **Standard analysis** and **Deeper attachment analysis** cards on the banner (one click each, requirement written on the Deeper card, no sandbox request until a card is clicked); `sandbox-pairing.js`; pairing panel in `analysis.html`, shown only once the original .eml exists.
- Testing the agent without the user's VM: run the API with `SANDBOX_BACKEND=agent USE_FAKE_DB=1` on a spare port and drive `sandbox_agent.cli` with `runner.VBox` replaced by a fake (see `tests/test_sandbox_agent*.py`). Never run `test`/`run` against the real VM without asking; `check` is read-only (`recon.py`: isolation settings from `showvminfo`, Hyper-V warning) and does not start the VM.
- `backend/analysis_jobs.py`: `POST /analyze/jobs` + `GET /analyze/jobs/{id}` (in-memory jobs, 9 stages: parse, headers, static_attachments, sandbox, indicators, reputation, history, ai, verdict). `POST /analyze` kept for the Gmail extension.
- `backend/verdicts.py`: single source of truth for labels/thresholds (0/20/40/65/85) and bands; mirrored in `frontend/src/utils/verdict.js` (test enforces parity).
- `backend/evidence.py`: evidence ledger + `evidence_report` (ids `hdr.*`, `att.*`, `qr.*`, `link.*`, `rep.*`, `corr.*`, `ai.*`).
- `backend/workflow_c.py`: retention, review workflow, share pack, baselines. `trusted_sender_check`: a trusted domain lowers risk by 25 **only** if SPF+DKIM+DMARC pass and no spoofing/attachment/reputation findings.
- `backend/rag/chat.py`: SOC assistant; offline answer is a readable summary when no Gemini key.

## Frontend (React 18 + Vite 8, light cream/navy/red theme)
- Styles: `styles/workspace.css` (base) + `styles/v2.css` (all revamp components; loaded last).
- Pages: `OverviewPage` (dashboard numbers from `GET /investigations`), `UploadPage` (live timeline; stages paced by `MIN_STAGE_MS` in the default Full animation, **Settings → Analysis animation → Fast** or `VITE_TIMELINE_PACING=off` removes the delay, see `utils/animationSpeed.js`; the sandbox row appears only for deeper runs; Re-analyze), `DashboardPage` (report: sticky tabs, `VerdictHero`, `RiskBreakdown`, `Remediation`, map, `EvidenceBreakdown` radar + MITRE, collapsible details, analyst tools last), `HistoryPage` (Reports: per-stage cards from `stageSummaries`), `SettingsPage` (trusted domains + retention).
- `components/common/TimelineCat.jsx`: animated SVG cat mascot on the Analyze timeline (one scene per stage: book, magnifier, PDF scratch, PDF tear, chain, laptop+globe, detective board, iron-cat suit, notebook). Positioned by `PipelineTimeline` next to the active row; drops with a bounce on each stage change; CSS keyframes `kc-*` in `v2.css`; hidden under 760 px and with reduced motion. Refinement deferred by the user.
- `utils/reportSummary.js`: risk categories, key stats, per-stage summaries — the single place that turns a report into UI numbers.
- `context/InvestigationContext.jsx`: `startAnalysis` (job polling), `resetToken` (remounts Analyze page on New analysis), `sourceFiles` (uploaded File per email_id, memory only) + `requestReanalysis` / `rerunRequest` for Re-analyze.

## Run and test
- Backend: `cd backend && python -m uvicorn app:app --port 5000` (needs `.env`; this folder has none — tests use env vars). Frontend: `cd frontend && npm run dev` (proxy to 127.0.0.1:5000).
- Tests: `cd backend && python -m pytest tests -q --ignore=tests/test_threat_intel_live.py` (198 pass); `cd frontend && npm test && npx vite build`; `node --test --test-isolation=none extension/tests/*.test.mjs`.
- Browser checks: the user may already have a backend and Vite running on 5000/5173. Don't kill those; run test servers on other ports (e.g. API 5010 with `ALLOWED_ORIGINS` set, UI via `vite build` with `VITE_API_BASE_URL` + `vite preview --port 5183`, output dir outside the repo).

## Known gaps worth remembering
- `dnspython` and `sentence-transformers` not in requirements; caches/limiters are in-process (one worker).
- Keep `CONTEXT.md` (last updated 2026-10-24) and `README.md` in step with any feature change.
- Sandbox: a live agent run on a real VM was verified on 2026-10-24, on the author's machine only. A fresh-machine setup by a teammate following the README, and VirtualBox on a Hyper-V host, are still untested. The Defender checkpoint (the first PowerShell call after the VM resumes) takes about 18 s, so it gets 60 s and a retry, and a failure shows as "Defender not checked". Next steps:
  - Sigma/YARA rules;
  - a Windows Sandbox provider;
  - UI automation for documents.
- Open API: no auth. The old bearer-key auth layer (`security.py`, `db/scoped.py`, `provision_key.py`, `migrate_workflow_c.py`, the extension options page and the `/me` dev proxy) was deleted on 2026-10-24; `test_auth_layer_is_gone` keeps it gone. Restoring sign-in is future work.
