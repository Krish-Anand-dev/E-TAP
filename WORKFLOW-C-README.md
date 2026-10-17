# Workflow C - implementation and verification

## Plan and current-state findings

The initial API exposed analysis, investigation retrieval and chat without identity. Correlation, message-ID deduplication and historical RAG searched shared records. The graph adjacency cache fingerprint was incomplete. Workflow B already provided evidence, privacy flow, provider status and click-to-analyze quick checks.

Implement the security gate first, then evidence v2 / deletion / redacted sharing, recovery / triage / campaign comparisons, and feasible strategic features. Do not change verdict thresholds or Workstream A. C7 original-message integration and C12 local processing remain scaffolds/designs. Human actions required: provision private API keys, back up and migrate the live database, review provider consent and run hosted smoke tests.

## Security model

All data API routes require a Bearer API key. `ETAP_API_KEYS` is a JSON array of `owner_id`, `role` (reporter/analyst/admin), and SHA-256 `sha256` entries. Use independently generated high-entropy keys, never passwords. Only digests are configured on the server. Remove an entry to revoke its key and restart the service. No self-registration, password recovery or organization sharing is provided. Even admins only access their own records.

The HTTP middleware establishes identity before parsing request bodies. Context propagates through worker threads to an allowlisted owner-scoped Mongo adapter. Reads, writes, deduplication, correlation and RAG are scoped. Atlas vector queries include an owner filter (the Atlas index must index owner_id). Unsupported adapter operations fail closed. Legacy ownerless records are inaccessible; migration marks them `__quarantine__`.

Limits: 25 MiB artifacts, 26 MiB multipart bodies, 64 KiB other bodies; default 120 requests/minute and 100 expensive analysis/chat operations/day per identity. Failed requests also consume quota. Existing provider per-analysis caps remain in effect.

Limitations: quotas are process-local; run a single worker and enforce upstream body/connection/time limits. API keys are bearer credentials and require HTTPS. Browser keys are in sessionStorage; extension keys in trusted-context chrome.storage.session. XSS or a compromised browser can steal keys. No MFA, external identity provider, distributed quota enforcement, encryption-at-rest management or formal penetration test. Database/CLI access is trusted administrator access outside HTTP isolation. Historical reads cap at 5,000 records.

## Migration

Stop writers and back up MongoDB, then run `cd backend; python migrate_workflow_c.py`. This idempotently quarantines ownerless records and replaces global unique message/campaign indexes with owner-compound indexes. Verify duplicate message IDs in different owners. Rollback requires restoring the backup before the old code/indexes; never expose quarantined records with the old unauthenticated API.

## Validation

Phase 0 in progress. Python compileall and extension syntax checks passed. Initial pytest unavailable; isolated pytest/httpx installed under ignored tmp/test-deps. Existing frontend node_modules is an external junction; clean npm ci uses an isolated workspace copy. Test results will be recorded at each gate.

## Not verified

Live MongoDB migration/Atlas index, live providers, deployed URLs, real Gmail/Outlook, browser extension interaction and multi-user load are not verified.

Phase 0 gate: 113 tests passed (17.44s), frontend clean install/build passed in isolated copy, compileall and extension checks passed. Offline TestClient smoke covered benign, phishing and quick checks. Restricted sandbox pytest stalled; the same suite ran outside it with dotenv/providers disabled. Existing dependency advisories are under review.

## C1 / C6 / C4 trust features

C1: schema v2 adds raw_observation (structured stored data or the bounded observation text), normalized_explanation, confidence (explicitly not calibrated), provenance_type, source_type, supports and contradicts. AI citations become supports; no contradiction links are invented. Existing records are reconstructed if they lack v2. UI and PDF expose the fields. The existing schema-version assertion in test_evidence.py was updated from 1 to 2 because this is an intentional version change; all behavioral assertions remain.

Limitations: bounded observation text is not the original artifact. Source types reserve sandbox for future use; none is emitted. Per-finding numeric confidence is not calibrated. Links only exist when supported by stored evidence.

C6: per-owner retention preference (1-365 days; default 30) applies to future analyses. Expiry is stored even if later stages fail. Expired records are removed on the owner's next authenticated request; schedule `python purge_retention.py` for inactive accounts. Delete routes remove analysis and embedded RAG vectors, legacy email index entries, campaign references, and invalidate dependent stored graph/RAG snapshots. UI offers delete-one/delete-all and clears browser session history. Existing privacy/data-flow panel remains visible.

Limitations: no recall of provider submissions, downloaded reports or operator backups; deletion is not a cross-collection transaction. Run periodic purge and retry after database failures. Browser snapshots in other tabs may remain until closed. Retention is not a guarantee of immediate timed physical erasure without the purge job.

C4: authenticated JSON share pack includes canonical verdict, fixed reasoning, enumerated authentication results, hashes and evidence references. Strict field allowlist omits all free-form email/model text, filenames, addresses and original artifacts.

Limitations: URLs/domains and free-form explanations are deliberately omitted, including potentially secret-bearing hostnames. This is a reduced share pack, not a full sanitized forensic export; review hashes/report IDs before sharing.

Phase 1 gate: 118 tests passed (9.33s); clean frontend install/build, compileall, extension checks and git diff --check passed.

## C2 / C3 / Campaign Lens

C2: seven deterministic, versioned recovery checklists. No model-generated advice or infection/safety inference. UI is optional and post-analysis; the selected interaction is not stored.
Limitations: general triage guidance, not an incident-response service; no device inspection or payment recovery action.

C3: owner-scoped server review queue plus submitted/analyzed initialization, needs_review, confirmed_malicious, benign_or_spam and unresolved review states. Reporter may request review; analyst/admin may record outcomes. Server enforces roles, owner checks, expected-state concurrency control and bounded note/history sizes. Reporter-facing explanation and timestamped role/actor history are displayed. Analysis verdicts remain unchanged by review outcomes.
Limitations: no notifications or cross-owner analyst access; roles operate within the same explicitly provisioned owner boundary. Re-analysis preserves review history. Notes are plain text, untrusted, and never executed.

Campaign Lens: compares up to 200 recent owner submissions by existing indicator overlap or inferred subject-token similarity. Shows first/last seen and changed sender/subject/indicators. This does not alter detection thresholds or campaign matching logic.
Limitations: subject similarity is a candidate link, not proof of a campaign; no automatic merge, body-semantic deduplication or mailbox prevalence claim.


Phase 2 gate: 121 tests passed (8.91s); clean frontend install/build, compileall and extension checks passed.

## Status at delivery

| Item | Status | Implementation / limitation |
|---|---|---|
| C1 Evidence Ledger v2 | Done, bounded observations | API/UI/PDF provenance and observation fields; no calibrated numeric finding confidence |
| C2 Recovery | Done | Seven versioned deterministic checklists; no device diagnosis |
| C3 Report / triage / feedback | Done within owner boundary | Role-enforced transitions and history; no notifications or cross-owner analyst queue |
| C4 Safe Share Pack | Partial | Strict redacted JSON allowlist; URLs/domains/free-text omitted instead of heuristic redaction |
| C5 Authentication / isolation | Done for HTTP routes | Hashed keys, roles, scoped RAG/correlation, request budgets; single-worker quotas |
| C6 Privacy / retention | Done with scheduled purge requirement | Data-flow panel, preferences, deletion and purge; external copies/backups excluded |
| C7 Original-message integration | Scaffold-only, not live | Provider protocol and account-scoped mock byte retrieval |
| C8 Case management | Partial | Owner-local assignment, campaign link, review notes/history; shared multi-owner workspace deferred |
| C9 API / webhooks | API done; webhook scaffold-only | Authenticated routes; local HMAC/replay/target/retry contract tests; no network delivery, durable retries or audit outbox |
| C10 Baselines | Partial | User-declared domain context on future reports; no organization baseline or score override |
| C11 Analytics | Partial | Actual owner report/outcome/provider counts, latency, triage duration and feedback; no accuracy, savings, sandbox or duplicate-rate claims |
| C12 Local/private mode | Design-only | Feasibility and data-flow notes below; not local-first |
| C13 Language / accessibility | Partial | Fixed English/Spanish/Hindi summary, labelled controls and keyboard focus; no full translation or WCAG audit |
| C14 Deployment / cost | Done as documentation | Self-host, quota/cache controls and migration notes; no measured cost promise |

## C7 original-message integration design (not live)

`integrations.OriginalMessageProvider.retrieve_selected(account_id, message_id)` returns original bytes without reconstruction. Mock retrieval keys by account and message; missing access fails and artifact size is bounded. A future live adapter must bind the provider account to the authenticated E-TAP owner, request the minimum message-read OAuth scope, use authorization code + PKCE and verified state/redirect URIs, and retrieve only an explicitly selected message. No mailbox sweep is planned.

Token storage design: provider refresh tokens belong in an encrypted server-side credential store keyed by owner/provider/account; use envelope encryption with a separately managed KMS key, strict DB privileges, revocation/deletion and short-lived access tokens. Never send provider tokens to analysis prompts, browser localStorage or logs. Consent screens, provider scope/policy review, OAuth credentials and live provider authorization are not implemented or verified.
Limitations: no OAuth routes or real Gmail/Outlook retrieval; the extension remains a visible-content quick check.

## C8 / C9 integration boundaries

Case assignment is analyst/admin-only and limited to the current owner. Assignment history, review notes, timestamps and campaign provenance persist in the analysis record. The UI offers assignment to the current owner workspace. Cross-owner assignment is rejected, not silently granted.
Limitations: no organization membership model, user directory or shared analyst workspace. Sharing an owner identifier intentionally shares the boundary and must be an operator decision, never client-controlled.

Webhook scaffolds in `integrations.py` allow `analysis.completed` and `review.changed`. `sandbox.completed` is reserved and rejected, never emitted. Bodies contain identifiers only, no raw evidence. HMAC-SHA256 signs `timestamp.body`; receiver harness checks a five-minute window, constant-time signature comparison and event-ID replay rejection. Retry policy is five bounded exponential delays. Target validation requires HTTPS:443, no credentials/fragments, and all resolved addresses public.
Limitations: no outbound sender is wired, no URLs/secrets accepted through the API, and no events are emitted. Before delivery is enabled, implement a durable owner-scoped outbox with unique idempotency keys, quotas, content-free audit records, expiry, jitter, dead-letter handling and atomic replay storage. Pin validated DNS addresses for every connection, retain TLS hostname validation, reject redirects, validate each retry and enforce network egress restrictions. Validation alone is not DNS-rebinding protection. The in-memory replay test harness is not production replay storage.

## C10 / C11 / C13

User baseline domains are validated bare ASCII names, stored per owner, and intersected with observed domains after scoring. Baseline context has no path back into verdict or risk-score calculation.
Limitations: no organizational vendor history or internationalized-domain normalization; newly changed preferences apply to future analyses.

Analytics is bounded to 5,000 recent owner records. It reports sample counts with mean pipeline latency and submission-to-first-outcome duration, actual provider status counts, outcomes, campaigns, top domains and helpful/incorrect feedback. Unmeasured values are null. Deleted data no longer contributes.
Limitations: no mailbox denominator, duplicate-rate estimator, cost attribution, detection accuracy or sandbox measurements. IDs and domain values are owner-only sensitive data.

The plain-language layer uses fixed English, Spanish and Hindi summaries selected by the canonical band. Verdicts, technical evidence and evidence IDs are unchanged. Form controls have labels, native keyboard interaction and visible focus; risk remains text-labelled.
Limitations: translations are not professionally reviewed; existing application contrast, screen-reader behavior and full WCAG compliance are not verified. PDF uses its existing font coverage and does not translate technical evidence.

## C12 local/private processing feasibility (design-only)

Current flow: browser/extension -> hosted Python parser/static analysis -> MongoDB findings/embeddings -> optional Gemini and indicator providers. A local interface does not change those destinations. For a truly local deployment, run Python and MongoDB on the user's device, disable Gemini and all threat-intelligence/WHOIS/geolocation calls, use local embeddings, prohibit remote images/resources in rendered email, audit logs/caches/backups, and firewall outbound requests. Local inference needs separately measured hardware/model performance; offline heuristics are not equivalent to live enrichment. A managed desktop sidecar, update/signing process, encrypted local storage and offline distribution remain work to design and test.
Limitations: no local/private product mode or no-egress test has been implemented. Self-hosting does not itself prove privacy.

## API / schema reference

Public routes: `/`, `/health`, `/ready`, `/docs`, `/openapi.json` (and OPTIONS preflight). Every data route requires `Authorization: Bearer <personal-key>`; 401 means invalid/missing key, 404 hides non-owned reports, 403 denies role changes, 409 signals stale/bounded review state, 413 size limit, 429 quota. OpenAPI is available but use the Authorization header explicitly in API clients.

| Method / path | Purpose |
|---|---|
| GET /me | Owner and server-assigned role |
| POST /analyze | Multipart artifact and optional quick_content_check source |
| POST /chat | question plus optional owned email_id; client email_context rejected |
| GET /investigations?offset=0&limit=50 | Owner listing; limit 1-100, bounded inventory |
| GET /investigations/{id} | Owned canonical report |
| DELETE /investigations/{id}, DELETE /investigations | Delete one / all owned investigations |
| GET /investigations/{id}/share | Reduced redacted JSON share pack |
| GET /investigations/{id}/workflow | State, notes and history |
| PATCH /investigations/{id}/workflow | state, expected_state, note, explanation |
| GET /investigations/{id}/related | Candidate related submissions and differences |
| PUT /investigations/{id}/case | Analyst/admin owner-local label and assignee |
| PUT /investigations/{id}/feedback | value: helpful or incorrect |
| GET /campaigns | Owner campaign inventory |
| GET/PUT /preferences | retention_days 1-365 |
| GET/PUT /baselines | Bare domains array, at most 100 |
| GET /analytics | Measured owner aggregates |
| GET /recovery | Versioned fixed guidance |

Stored records add owner_id, expires_at, retention_days, workflow, case/case_history, feedback and baseline_context. RAG vectors remain embedded, so deleting the record deletes those vectors. New compound owner/message and owner/campaign indexes replace global uniqueness. Preferences are owner-scoped. Legacy data is quarantined, never assigned automatically.

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
node --check extension/options.js
```

Phase 3 initial gate: 130 backend tests passed (12.52s), 2 frontend tests passed, clean patched npm ci/build passed with zero advisories, compileall and extension syntax checks passed. Final post-review validation is recorded below.

## Pre-deploy checklist / self-hosting and cost controls

1. Back up MongoDB and stop writers. Provision a separate random personal key per user with `python backend/provision_key.py --owner <opaque-owner-id> --role reporter` (or analyst/admin); deliver the key privately, configure only its digest entry in ETAP_API_KEYS. Do not commit console output. Empty ETAP_API_KEYS denies all data routes.
2. Configure MONGODB_URI, MONGO_DB_NAME, USE_FAKE_DB=0, AUTO_FALLBACK_DB=0, ALLOWED_ORIGINS and HTTPS. Keep provider keys server-side. Set THREAT_INTEL_LIVE deliberately; use THREAT_INTEL_MAX_LOOKUPS_PER_PROVIDER, GEMINI_REQUEST_TIMEOUT_MS and identity quotas to bound use. To disable Gemini leave GEMINI_API_KEY unset; disable external intel separately. Caches are process-local and can reuse indicator results; they are not a billing meter.
3. Run `python migrate_workflow_c.py` from backend. Verify quarantined legacy records and owner-compound indexes. Atlas vector search needs owner_id as a filter field; without that it falls back to scoped cosine retrieval. The migration and live Atlas index are not verified here.
4. Run one backend worker until quotas use a shared store. Enforce upstream request-body, connection, time and concurrency limits. Schedule `python purge_retention.py` periodically (for example hourly) under a protected operator account. Backups need a separate retention policy.
5. Build the frontend with VITE_API_BASE_URL. Require Node >=22.12. Log in with a personal key. Configure the extension key through its options page after each browser restart; preserve click-to-analyze and the quick-check scope label.
6. Hosted smoke: GET /health and /ready; anonymous analyze/chat/report must return 401; two independently provisioned owners must receive 404 for each other's reports/share/review paths and see separate histories/campaigns. Upload benign and phishing synthetic fixtures and a quick check; inspect provider gaps. Delete a report, confirm retrieval and RAG no longer find it, then exercise expiration in a disposable test account. Confirm frontend and extension use the intended hosted URLs.

Costs are not measured. No free-tier, affordability, privacy or accuracy guarantee is made. Use your providers' current billing records to measure cost per analysis and establish operational budgets before opening access.

## Remaining verification and risks

Not verified: hosted deployment, live Mongo migration/index behavior, real Atlas vector search, live Gemini/intelligence, real Gmail extension interaction, OAuth, webhook delivery, multi-worker limits, inactive-account purge scheduling, full browser accessibility or professional translation. Database failure during multi-collection deletion may require retry; backups and provider copies remain external to deletion. Existing model serialization/deprecation warnings remain. Detection thresholds and Workstream A were untouched. The previous 24-message offline evaluation remains a limited historical debugging fixture; it was not rerun and is not a detection-rate claim.

Files most relevant: backend/security.py, db/scoped.py, app.py, workflow_c.py, evidence.py, pipeline.py, integrations.py, migrate_workflow_c.py, purge_retention.py; frontend AuthGate, TrustControls, ResponseWorkflow, WorkspaceTools, pdfGenerator; extension options/background; tests/test_workflow_c_*.py and frontend/tests/report.test.mjs.

Exit criteria: offline HTTP isolation and regression gates green; shipped behavior tested and documented; deferred integrations explicitly not live; source-only ZIP and clean Git state. Live deployment acceptance remains the operator checklist above.


## Final validation (18 October 2026)

- Backend: **135 passed**, 23 existing dependency/deprecation/model warnings, 18.85s. Full `python -m pytest tests -q --ignore=tests/test_threat_intel_live.py` with isolated test packages and offline environment; added `--disable-warnings` only for output formatting. Includes negative HTTP access, owner/RAG/campaign isolation, Atlas prefilter, native-thread indexing and deletion race, anonymous/forged headers, chunked oversize input, migration idempotence, retention, share redaction, roles/concurrency, recovery wording, measured analytics, original-message mock, webhook integrity/replay and SSRF target rejection.
- Frontend: clean `npm ci`, **2 tests passed**, production `npm run build` passed on patched dependencies; **0 npm audit advisories** at install. Recharts deprecation and bundle-size warnings remain.
- `python -m compileall -q backend`, all three extension JavaScript syntax checks, and `git diff --check`: passed.
- TestClient smoke: benign, synthetic phishing and quick-content-check inputs, authenticated report retrieval and cross-user denial. No live-provider or hosted-deployment smoke was claimed.
- Synthetic PDF: generated with jsPDF 4.2.1, 3 pages rendered and visually inspected; ledger observations/provenance readable, no clipping seen. PDF metadata reports no JavaScript; an automated test rejects JavaScript/Launch actions in the fixture. Poppler emitted missing optional-font warnings; standard-font rendered pages were readable. This is not a universal PDF safety certification.
- Final review corrected missing-data PDF defaults, captured the scoped DB in native RAG threads, and made stored-history opens revalidate against the API. The history view now includes the owner's 100 most recent server reports and their review states.

Recommended next steps: provision keys and run migration against a disposable real MongoDB first; verify Atlas filters and purge scheduling; complete two-owner hosted smoke checks; then design organization membership and a durable webhook outbox before enabling shared workspaces or delivery. Keep C7/C12 and webhook delivery visibly non-live until their consent, storage, network and operational tests exist.

Individual report lookups use indexed IDs within the owner filter; the inventory cap applies to history/search views, not to direct report access.
