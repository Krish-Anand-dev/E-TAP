# E-TAP — Project Status

E-TAP (Email-TAP) bridges the gap between email-forensics evidence and understandable, actionable guidance for everyday users while preserving technical detail for analysts.

## Current demo deployment

- Frontend: <https://e-tap-lac.vercel.app/>
- Backend liveness: <https://etap-backend-od1c.onrender.com/health>
- Backend readiness: <https://etap-backend-od1c.onrender.com/ready>
- API docs: <https://etap-backend-od1c.onrender.com/docs>

## Current implementation

- React/Vite dashboard on Vercel; FastAPI backend on Render; MongoDB Atlas database `etap`.
- Static email and attachment forensics, evidence-led explanation, privacy/data-flow reporting, campaign correlation, RAG/SOC Assistant, and an experimental click-to-analyze Gmail extension.
- B11 provider-status contract, analysis-duration reporting, bounded lookup budgets/timeouts, `/health` liveness and `/ready` database readiness are implemented in the current source tree.
- The Gmail extension targets the hosted Render/Vercel URLs in committed source. For local development, change both URL constants and reload the unpacked extension.

## Current blockers and next actions

1. **Workflow C source gate:** owner-scoped API authentication and regression tests are implemented; deploy only after the migration/key setup in WORKFLOW-C-README.md. Hosted behavior is not verified.
2. **Validation gate:** see WORKFLOW-C-README.md for the current backend/frontend counts and commands; live provider and post-deploy checks remain.
3. **Evaluation gate:** the offline fallback now flags almost nothing (1/15 benign, 0/9 spam flagged on the 24-message fixture). Rerun on an authorized, broader labelled corpus with real phishing before making any accuracy claim.
4. **RAG quality:** hosted Render uses a deterministic hash-based fallback embedder rather than a trained semantic embedding model. Test retrieval grounding and quality before depending on historical answers.
5. **Privacy:** external enrichment and Gemini may receive indicators or email-derived content. Review data flows, retention and deletion before using sensitive inbox data.

## Workflow B documentation

All B0–B11 implementation details, tests, known limitations and the pre-Workflow-C checklist are in **[WORKFLOW-B-README.md](WORKFLOW-B-README.md)**. Individual per-stage change-log files have been consolidated there; future Workflow B changes should update that one document.

## Team

- Bhavit Anand
- Krish Anand
- Yashmit Kamal

## Later direction

Workstream A covers dynamic sandbox feasibility and runtime behavior analysis. Workflow C now implements owner-scoped trust and response features; strategic capabilities are explicitly partial or scaffold-only. A Tauri desktop shell can be evaluated later; E-TAP is not currently a full Gmail replacement.

## Workflow C setup changes

See [WORKFLOW-C-README.md](WORKFLOW-C-README.md) for the authoritative feature status, API routes, security model and limitations. Data routes require personal Bearer keys; set ETAP_API_KEYS digest entries, migrate ownerless records, and schedule retention purge before deployment. Configure the extension key in its options page. Browser history now lasts for the signed-in tab session; server deletion is a separate control. Node >=22.12 is required for the patched build tools. Quotas currently require a single backend worker. Live hosted behavior is not verified.
