# Workflow C - implementation and verification

## Plan and current-state findings

The initial API exposed analysis, investigation retrieval and chat without identity. Correlation, message-ID deduplication and historical RAG searched shared records. The graph adjacency cache fingerprint was incomplete. Workflow B already provided evidence, privacy flow, provider status and click-to-analyze quick checks.

Implement evidence v2 / deletion / redacted sharing, recovery / triage / campaign comparisons, and feasible strategic features. Do not change verdict thresholds or Workstream A. C7 original-message integration and C12 local processing remain scaffolds/designs. Human actions required: review provider consent and run hosted smoke tests.

## Access model (open - authentication deferred)

The API and UI are intentionally **open**: there are no API keys, no sign-in screen, no roles and no per-user data scoping. Anyone who can reach the backend URL can analyze, list, share and delete investigations, and spend provider quota. This keeps the demo, the web app and the Gmail extension zero-configuration.

What still applies: 25 MiB maximum upload (`MAX_UPLOAD_SIZE`), per-IP rate limits on the expensive routes (`/analyze` 10/min, `/chat` 30/min, `GET /investigations/{id}` 60/min via slowapi), explicit CORS origins (`ALLOWED_ORIGINS`), and the per-analysis provider caps (`THREAT_INTEL_MAX_LOOKUPS_PER_PROVIDER`, `GEMINI_REQUEST_TIMEOUT_MS`).

Limitations: a public deployment is single-tenant and shared. Do not put sensitive real-world mail in the hosted instance. `DELETE /investigations` wipes everything for everyone. Behind a proxy (Render) per-IP limits see the proxy address unless forwarded-for handling is configured.

## Future scope: authentication and multi-user isolation

Removed before the demo to keep setup frictionless; deliberately deferred, not abandoned. A previous implementation existed (hashed personal Bearer keys with reporter/analyst/admin roles, an owner-scoped Mongo adapter covering correlation/RAG/campaigns, per-identity request and provider budgets, an ownerless-data migration, key provisioning script, browser sign-in gate and extension options page). When this returns, prefer a standard identity provider (OAuth/OIDC) over hand-managed keys, scope data by an `owner_id` filter applied in one place, put the Atlas vector index filter on `owner_id`, and enforce quotas in a shared store. Recover the earlier design from git history (tag `pre-auth-removal`).


## Validation

Phase 0 in progress. Python compileall and extension syntax checks passed. Initial pytest unavailable; isolated pytest/httpx installed under ignored tmp/test-deps. Existing frontend node_modules is an external junction; clean npm ci uses an isolated workspace copy. Test results will be recorded at each gate.

## Not verified

Live MongoDB migration/Atlas index, live providers, deployed URLs, real Gmail/Outlook, browser extension interaction and multi-user load are not verified.

Phase 0 gate: 113 tests passed (17.44s), frontend clean install/build passed in isolated copy, compileall and extension checks passed. Offline TestClient smoke covered benign, phishing and quick checks. Restricted sandbox pytest stalled; the same suite ran outside it with dotenv/providers disabled. Existing dependency advisories are under review.

## C1 / C6 / C4 trust features

C1: schema v2 adds raw_observation (structured stored data or the bounded observation text), normalized_explanation, confidence (explicitly not calibrated), provenance_type, source_type, supports and contradicts. AI citations become supports; no contradiction links are invented. Existing records are reconstructed if they lack v2. UI and PDF expose the fields. The existing schema-version assertion in test_evidence.py was updated from 1 to 2 because this is an intentional version change; all behavioral assertions remain.

Limitations: bounded observation text is not the original artifact. Source types reserve sandbox for future use; none is emitted. Per-finding numeric confidence is not calibrated. Links only exist when supported by stored evidence.

C6: retention preference (1-365 days; default 30) applies to future analyses. Expiry is stored even if later stages fail. Expired records are removed after each analysis; schedule `python purge_retention.py` for idle periods. Delete routes remove analysis and embedded RAG vectors, legacy email index entries, campaign references, and invalidate dependent stored graph/RAG snapshots. UI offers delete-one/delete-all and clears browser session history. Existing privacy/data-flow panel remains visible.

Limitations: no recall of provider submissions, downloaded reports or operator backups; deletion is not a cross-collection transaction. Run periodic purge and retry after database failures. Browser snapshots in other tabs may remain until closed. Retention is not a guarantee of immediate timed physical erasure without the purge job.

C4: JSON share pack includes canonical verdict, fixed reasoning, enumerated authentication results, hashes and evidence references. Strict field allowlist omits all free-form email/model text, filenames, addresses and original artifacts.

Limitations: URLs/domains and free-form explanations are deliberately omitted, including potentially secret-bearing hostnames. This is a reduced share pack, not a full sanitized forensic export; review hashes/report IDs before sharing.

Phase 1 gate: 118 tests passed (9.33s); clean frontend install/build, compileall, extension checks and git diff --check passed.

## C2 / C3 / Campaign Lens

C2: seven deterministic, versioned recovery checklists. No model-generated advice or infection/safety inference. UI is optional and post-analysis; the selected interaction is not stored.
Limitations: general triage guidance, not an incident-response service; no device inspection or payment recovery action.

C3: server review queue plus submitted/analyzed initialization, needs_review, confirmed_malicious, benign_or_spam and unresolved review states. Any user may record outcomes. Server enforces expected-state concurrency control and bounded note/history sizes. Reporter-facing explanation and timestamped history are displayed. Analysis verdicts remain unchanged by review outcomes.
Limitations: no notifications, assignees or per-user attribution (single shared workspace). Re-analysis preserves review history. Notes are plain text, untrusted, and never executed.

Campaign Lens: compares up to 200 recent submissions by existing indicator overlap or inferred subject-token similarity. Shows first/last seen and changed sender/subject/indicators. This does not alter detection thresholds or campaign matching logic.
Limitations: subject similarity is a candidate link, not proof of a campaign; no automatic merge, body-semantic deduplication or mailbox prevalence claim.


Phase 2 gate: 121 tests passed (8.91s); clean frontend install/build, compileall and extension checks passed.

## Status at delivery

| Item | Status | Implementation / limitation |
|---|---|---|
| C1 Evidence Ledger v2 | Done, bounded observations | API/UI/PDF provenance and observation fields; no calibrated numeric finding confidence |
| C2 Recovery | Done | Seven versioned deterministic checklists; no device diagnosis |
| C3 Report / triage / feedback | Done | Review transitions and history with concurrency control; no notifications or per-user attribution |
| C4 Safe Share Pack | Partial | Strict redacted JSON allowlist; URLs/domains/free-text omitted instead of heuristic redaction |
| C5 Authentication / isolation | Deferred (future scope) | Removed for demo simplicity; API is open. See Future scope above |
| C6 Privacy / retention | Done with scheduled purge requirement | Data-flow panel, preferences, deletion and purge; external copies/backups excluded |
| C7 Original-message integration | Scaffold-only, not live | Provider protocol and account-scoped mock byte retrieval |
| C8 Case management | Partial | Case label, campaign link, review notes/history; no assignees or multi-user workspace |
| C9 API / webhooks | API done; webhook scaffold-only | Open routes; local HMAC/replay/target/retry contract tests; no network delivery, durable retries or audit outbox |
| C10 Baselines | Partial | User-declared domain context on future reports; no organization baseline or score override |
| C11 Analytics | Partial | Actual report/outcome/provider counts, latency, triage duration and feedback; no accuracy, savings, sandbox or duplicate-rate claims |
| C12 Local/private mode | Design-only | Feasibility and data-flow notes below; not local-first |
| C13 Language / accessibility | Partial | Fixed English/Spanish/Hindi summary, labelled controls and keyboard focus; no full translation or WCAG audit |
| C14 Deployment / cost | Done as documentation | Self-host, quota/cache controls and migration notes; no measured cost promise |

## C7 original-message integration design (not live)

`integrations.OriginalMessageProvider.retrieve_selected(account_id, message_id)` returns original bytes without reconstruction. Mock retrieval keys by account and message; missing access fails and artifact size is bounded. A future live adapter must bind the provider account to the authenticated E-TAP owner, request the minimum message-read OAuth scope, use authorization code + PKCE and verified state/redirect URIs, and retrieve only an explicitly selected message. No mailbox sweep is planned.

Token storage design: provider refresh tokens belong in an encrypted server-side credential store keyed by owner/provider/account; use envelope encryption with a separately managed KMS key, strict DB privileges, revocation/deletion and short-lived access tokens. Never send provider tokens to analysis prompts, browser localStorage or logs. Consent screens, provider scope/policy review, OAuth credentials and live provider authorization are not implemented or verified.
Limitations: no OAuth routes or real Gmail/Outlook retrieval; the extension remains a visible-content quick check.

## C8 / C9 integration boundaries

Case marking records a label, timestamp and campaign provenance in the analysis record, alongside review notes and history. The UI offers a single 'Mark as case for review' action.
Limitations: no organization membership model, user directory or per-user assignment.

Webhook scaffolds in `integrations.py` allow `analysis.completed` and `review.changed`. `sandbox.completed` is reserved and rejected, never emitted. Bodies contain identifiers only, no raw evidence. HMAC-SHA256 signs `timestamp.body`; receiver harness checks a five-minute window, constant-time signature comparison and event-ID replay rejection. Retry policy is five bounded exponential delays. Target validation requires HTTPS:443, no credentials/fragments, and all resolved addresses public.
Limitations: no outbound sender is wired, no URLs/secrets accepted through the API, and no events are emitted. Before delivery is enabled, implement a durable outbox with unique idempotency keys, quotas, content-free audit records, expiry, jitter, dead-letter handling and atomic replay storage. Pin validated DNS addresses for every connection, retain TLS hostname validation, reject redirects, validate each retry and enforce network egress restrictions. Validation alone is not DNS-rebinding protection. The in-memory replay test harness is not production replay storage.

## C10 / C11 / C13

User baseline domains are validated bare ASCII names, stored globally, and intersected with observed domains after scoring. Baseline context has no path back into verdict or risk-score calculation.
Limitations: no organizational vendor history or internationalized-domain normalization; newly changed preferences apply to future analyses.

Analytics is bounded to 5,000 recent records. It reports sample counts with mean pipeline latency and submission-to-first-outcome duration, actual provider status counts, outcomes, campaigns, top domains and helpful/incorrect feedback. Unmeasured values are null. Deleted data no longer contributes.
Limitations: no mailbox denominator, duplicate-rate estimator, cost attribution, detection accuracy or sandbox measurements. IDs and domain values may be sensitive; the API is open.

The plain-language layer uses fixed English, Spanish and Hindi summaries selected by the canonical band. Verdicts, technical evidence and evidence IDs are unchanged. Form controls have labels, native keyboard interaction and visible focus; risk remains text-labelled.
Limitations: translations are not professionally reviewed; existing application contrast, screen-reader behavior and full WCAG compliance are not verified. PDF uses its existing font coverage and does not translate technical evidence.

## C12 local/private processing feasibility (design-only)

Current flow: browser/extension -> hosted Python parser/static analysis -> MongoDB findings/embeddings -> optional Gemini and indicator providers. A local interface does not change those destinations. For a truly local deployment, run Python and MongoDB on the user's device, disable Gemini and all threat-intelligence/WHOIS/geolocation calls, use local embeddings, prohibit remote images/resources in rendered email, audit logs/caches/backups, and firewall outbound requests. Local inference needs separately measured hardware/model performance; offline heuristics are not equivalent to live enrichment. A managed desktop sidecar, update/signing process, encrypted local storage and offline distribution remain work to design and test.
Limitations: no local/private product mode or no-egress test has been implemented. Self-hosting does not itself prove privacy.

## API / schema reference

All routes are open (no Authorization header). 404 means the report does not exist, 409 signals stale/bounded review state, 413 size limit, 422 invalid input, 429 per-IP rate limit. OpenAPI is available at `/docs`.

| Method / path | Purpose |
|---|---|
| POST /analyze | Multipart artifact and optional quick_content_check source |
| POST /chat | question plus optional email_id; client email_context rejected |
| GET /investigations?offset=0&limit=50 | Listing; limit 1-100, bounded inventory |
| GET /investigations/{id} | Canonical report |
| DELETE /investigations/{id}, DELETE /investigations | Delete one / all investigations |
| GET /investigations/{id}/share | Reduced redacted JSON share pack |
| GET /investigations/{id}/workflow | State, notes and history |
| PATCH /investigations/{id}/workflow | state, expected_state, note, explanation |
| GET /investigations/{id}/related | Candidate related submissions and differences |
| PUT /investigations/{id}/case | Case label and assignee text |
| PUT /investigations/{id}/feedback | value: helpful or incorrect |
| GET /campaigns | Campaign inventory |
| GET/PUT /preferences | retention_days 1-365 |
| GET/PUT /baselines | Bare domains array, at most 100 |
| GET /analytics | Measured aggregates |
| GET /recovery | Versioned fixed guidance |

Stored records add expires_at, retention_days, workflow, case/case_history, feedback and baseline_context. RAG vectors remain embedded, so deleting the record deletes those vectors. Legacy `owner_id` fields on older records are ignored; the compound `(owner_id, message_id)` / `(owner_id, campaign_id)` unique indexes are kept so existing Atlas deployments need no index migration.

## Dependencies and validation environment

No new runtime backend dependency. Test dependencies are recorded in backend/requirements-dev.txt. PDF/build dependencies updated to jsPDF 4.2.1, AutoTable 5.0.9, Vite 8.3.4 and React plugin 6.1.2 because the original lockfile audit reported 6 advisories (including a critical PDF-library advisory). Node >=22.12 is required by this project; validated on 22.23.2. The patched clean install reported zero advisories, which is not a proof of application security. Large frontend bundle warnings remain.

Local validation uses the existing Python 3.12 environment plus isolated pytest/httpx under tmp/test-deps, PYTHON_DOTENV_DISABLED=1, USE_FAKE_DB=1, THREAT_INTEL_LIVE=0 and fallback embeddings. No live keys are required. Existing frontend node_modules is an external junction, so clean installs/builds run against an exact source/lockfile copy under tmp/frontend-check. All tmp/output/dependency artifacts are ignored and excluded from the deliverable ZIP.

Commands (normal fresh checkout):
```text
python -m pip install -r backend/requirements-dev.txt
cd backend
python -m pytest tests -q --ignore=tests/test_threat_intel_live.py
cd ..
python -m compileall -q backend
cd frontend
npm ci
npm test
npm run build
cd ..
node --check extension/background.js
node --check extension/content.js
```

Phase 3 initial gate: 130 backend tests passed (12.52s), 2 frontend tests passed, clean patched npm ci/build passed with zero advisories, compileall and extension syntax checks passed. Final post-review validation is recorded below.

## Pre-deploy checklist / self-hosting and cost controls

1. Configure MONGODB_URI, MONGO_DB_NAME, USE_FAKE_DB=0, AUTO_FALLBACK_DB=0, ALLOWED_ORIGINS (include the deployed frontend origin) and HTTPS. Keep provider keys server-side. Set THREAT_INTEL_LIVE deliberately; use THREAT_INTEL_MAX_LOOKUPS_PER_PROVIDER and GEMINI_REQUEST_TIMEOUT_MS to bound use. To disable Gemini leave GEMINI_API_KEY unset; disable external intel separately. Caches are process-local and can reuse indicator results; they are not a billing meter.
2. Schedule `python purge_retention.py` periodically (for example hourly). Backups need a separate retention policy.
3. Build the frontend with VITE_API_BASE_URL (Node >=22.12). Load the unpacked `extension/` folder in Chrome/Brave; no configuration is needed. Preserve click-to-analyze and the quick-check scope label.
4. Hosted smoke: GET /health and /ready; upload benign and phishing synthetic fixtures and a quick check; inspect provider gaps. Delete a report, confirm retrieval and RAG no longer find it, then exercise expiration in a disposable test database.

Costs are not measured. No free-tier, affordability, privacy or accuracy guarantee is made. Use your providers' current billing records to measure cost per analysis and establish operational budgets before opening access.

## Remaining verification and risks

Not verified: hosted deployment, live Mongo migration/index behavior, real Atlas vector search, live Gemini/intelligence, real Gmail extension interaction, OAuth, webhook delivery, multi-worker limits, inactive-account purge scheduling, full browser accessibility or professional translation. Database failure during multi-collection deletion may require retry; backups and provider copies remain external to deletion. Existing model serialization/deprecation warnings remain. Detection thresholds and Workstream A were untouched. The previous 24-message offline evaluation remains a limited historical debugging fixture; it was not rerun and is not a detection-rate claim.

Files most relevant: backend/app.py, workflow_c.py, evidence.py, pipeline.py, integrations.py, purge_retention.py; frontend TrustControls, ResponseWorkflow, WorkspaceTools, pdfGenerator; extension background/content; tests/test_workflow_c_*.py and frontend/tests/report.test.mjs.

Exit criteria: offline HTTP isolation and regression gates green; shipped behavior tested and documented; deferred integrations explicitly not live; source-only ZIP and clean Git state. Live deployment acceptance remains the operator checklist above.


## Validation status

Authentication, roles and owner scoping were removed after the earlier validation runs; the workflow C tests were rewritten for the open API (`tests/test_workflow_c_api.py` plus the response, strategic and trust suites). Re-run the commands under "Commands" before relying on any earlier pass counts. Hop-origin analysis has its own tests in `tests/test_received_chain_origin.py`. No live-provider or hosted-deployment smoke has been claimed.
