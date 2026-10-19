# E-TAP — Full Project Context

This is the single technical reference for E-TAP. It is written so that a person or an LLM with no prior knowledge can understand the whole system: what it does, how every stage works, which file does what, which libraries are used and why, how data is shaped, how it is configured and deployed, and what is known to be incomplete.

The short, user-facing overview lives in [README.md](README.md). When this document and the code disagree, the code wins — update this file.

---

## Table of contents

1. [What E-TAP is](#1-what-e-tap-is)
2. [System architecture](#2-system-architecture)
3. [Repository map](#3-repository-map)
4. [The analysis pipeline, stage by stage](#4-the-analysis-pipeline-stage-by-stage)
5. [Verdicts, scoring and the evidence report](#5-verdicts-scoring-and-the-evidence-report)
6. [Privacy model](#6-privacy-model)
7. [Persistence (MongoDB)](#7-persistence-mongodb)
8. [HTTP API](#8-http-api)
9. [RAG / SOC Assistant](#9-rag--soc-assistant)
10. [Workflow C: review, retention, sharing](#10-workflow-c-review-retention-sharing)
11. [Frontend (React dashboard)](#11-frontend-react-dashboard)
12. [Gmail extension](#12-gmail-extension)
13. [Libraries and dependencies](#13-libraries-and-dependencies)
14. [Configuration (environment variables)](#14-configuration-environment-variables)
15. [Running, testing, evaluating](#15-running-testing-evaluating)
16. [Deployment](#16-deployment)
17. [Known gaps, quirks and future work](#17-known-gaps-quirks-and-future-work)
18. [Project history and naming](#18-project-history-and-naming)
19. [Glossary](#19-glossary)

---

## 1. What E-TAP is

E-TAP (Email-TAP, "Email Threat Analysis Platform") is a defensive email-forensics application. A user supplies one email — an `.eml` (RFC 822/MIME) or `.msg` (Outlook) file, or a message opened in Gmail via the extension — and E-TAP returns a structured investigation report containing:

- a canonical verdict (`LIKELY LEGITIMATE` … `HIGH-RISK PHISHING`), a 0–100 risk score and a safe/caution/danger band;
- every piece of evidence, each tagged as **observed** (E-TAP measured it), **reputation** (an external provider said it) or **ai_inferred** (a model said it), and each tagged present / absent / **unavailable**;
- header, attachment, link, QR, IOC, threat-intel, geolocation, campaign-correlation, graph-diffusion and MITRE ATT&CK details;
- plain-language "what to do" guidance, a privacy data-flow report and per-provider coverage status.

**Core design principles (enforced throughout the code):**

1. *Unknown is never safe.* A failed, skipped, disabled or rate-limited check produces `malicious: None` / status `unavailable`, never `malicious: False`.
2. *Deterministic evidence first, AI second.* Observed and reputation facts are built without any model. AI statements must cite evidence IDs or are marked ungrounded.
3. *Degrade, don't crash.* Every optional stage (DNS, OCR, QR, WHOIS, XGBoost, graph diffusion, Gemini, embeddings) fails open and reports why.
4. *Privacy by default.* Secret-bearing URLs are trimmed or withheld from VirusTotal; Gemini gets a sanitized copy; PII is masked at parse time; logs never contain message content.
5. *One source of truth for the verdict* (`backend/verdicts.py`), mirrored in the frontend and checked by a test.

Team: Bhavit Anand, Krish Anand, Yashmit Kamal. Built as a hackathon/academic project; comments in the code refer to stage owners (Stage A/B by Krish, B2 by "the team").

---

## 2. System architecture

```text
 ┌────────────────────┐   ┌────────────────────┐   ┌──────────────────────────┐
 │ React/Vite web app │   │ Gmail MV3 extension│   │ CLI: backend/run_pipeline│
 │ (Vercel)           │   │ (unpacked)         │   │      backend/eval/...    │
 └─────────┬──────────┘   └─────────┬──────────┘   └────────────┬─────────────┘
           │ multipart POST /analyze │                           │ direct import
           ▼                         ▼                           ▼
 ┌───────────────────────────────────────────────────────────────────────────┐
 │ FastAPI backend (backend/app.py, Docker on Render)                        │
 │   pipeline.py  → A → B/B2/B5/B6 → D → E → F → F′ → C′ → G → H             │
 │   workflow_c.py (review/retention/share/analytics routes)                 │
 │   rag/ (SOC Assistant)                                                    │
 └───────┬─────────────────────────────┬─────────────────────────────────────┘
         │                             │ outbound (optional, bounded)
         ▼                             ▼
 ┌──────────────────┐   ┌───────────────────────────────────────────────────┐
 │ MongoDB / Atlas  │   │ Gemini · VirusTotal · AbuseIPDB · WHOIS · ip-api   │
 │ db "etap"        │   │ DNS (SPF/DKIM/DMARC fallback)                      │
 └──────────────────┘   └───────────────────────────────────────────────────┘
```

The orchestrator is `backend/pipeline.py::_run_parsed_pipeline`. Both the HTTP API (`analyze_email_upload`) and the CLI (`analyze_email_file`) call it, so they emit exactly the same JSON shape. The HTTP route runs it in a worker thread (`asyncio.to_thread`) and then `workflow_c.finish_analysis` adds retention and baseline context.

**Exact execution order inside `_run_parsed_pipeline`:**

1. `analyze_headers` (B) — skipped auth/routing when `source=quick_content_check`
2. `analyze_attachments` (B2)
3. `extract_iocs` (D) — consumes B and B2 output
4. `analyze_links` (B5) on the HTML body; `build_qr_trace` (B6) on image attachments
5. `enrich_iocs` (E) then `attach_hop_geo` (E, per-hop geolocation)
6. `correlate_and_store` (F) — **inserts the DB record here**
7. `extract_graph_from_correlation` + `compute_graph_diffusion` (F′)
8. OCR text appended to `email_summary.body_text`
9. `build_evidence_ledger` → compact ledger goes into the AI context
10. `extract_features` + `predict_triage` (C′)
11. heuristic overrides decide whether Gemini is forced
12. either the triage bypass verdict, or `analyze_with_stage_g(sanitize_for_external_ai(context))` (G)
13. `finalize_verdict`, provenance, `build_provider_status`, `build_evidence_report`, `build_privacy_report` (H)
14. `repository.update_analysis_fields` — persists all H fields
15. background thread: `build_summary` + `embed_text` → `rag_summary`, `rag_embedding`

Stage letters are historical (C was originally the content classifier; it moved into G, and C′ is the XGBoost pre-filter that now runs right before G).

---

## 3. Repository map

```text
E-TAP/
├── README.md                 short overview
├── CONTEXT.md                this file
├── .env.example              commit-safe env template
├── requirements.txt          "-r backend/requirements.txt" (root convenience)
├── backend/
│   ├── app.py                FastAPI app, CORS, rate limits, /analyze /chat /investigations
│   ├── pipeline.py           Stage H orchestrator (A→…→H)
│   ├── run_pipeline.py       CLI: python run_pipeline.py file.eml
│   ├── verdicts.py           canonical labels, thresholds, bands, finalize_verdict()
│   ├── evidence.py           evidence ledger + evidence_report (schema v2)
│   ├── privacy.py            URL lookup policy, Gemini sanitizer, privacy report
│   ├── provider_status.py    per-provider coverage object
│   ├── workflow_c.py         APIRouter: review, retention, share, analytics, baselines…
│   ├── recovery.py           fixed "I clicked / I entered my password…" checklists
│   ├── integrations.py       NOT LIVE: original-message provider + webhook contracts
│   ├── security.py           NOT WIRED: bearer-key auth middleware (legacy)
│   ├── provision_key.py      NOT USED: generates keys for security.py
│   ├── migrate_workflow_c.py legacy owner_id migration
│   ├── purge_retention.py    cron job: delete expired analyses
│   ├── verify_all_models.py  utility: probe which Gemini model names work for a key
│   ├── generate_*_eml.py     write synthetic test emails (geo, OCR, PII, safe)
│   ├── Dockerfile            python:3.11-slim + tesseract + libzbar
│   ├── requirements*.txt
│   ├── email_parser/         Stage A
│   │   ├── models.py         ParsedEmail / Attachment dataclasses (the contract)
│   │   ├── unified_parser.py detect_file_type (magic bytes), parse_email, parse_any
│   │   ├── eml_parser.py     stdlib email parser with charset fallback
│   │   ├── msg_parser.py     extract-msg parser
│   │   ├── csv_parser.py     dataset rows → RFC822 → eml parser
│   │   └── pii_masker.py     regex PII redaction
│   ├── forensics/            Stages B, B2, B5, B6, D
│   │   ├── header_forensics.py  analyze_headers() entry
│   │   ├── auth_results.py      SPF/DKIM/DMARC (header tier + DNS tier)
│   │   ├── received_chain.py    hop parsing, provider detection, origin resolution
│   │   ├── domain_similarity.py punycode, homograph, typosquat, display-name checks
│   │   ├── brand_domains.py     impersonated-brand list (India-weighted)
│   │   ├── attachment_forensics.py analyze_attachments() entry
│   │   ├── file_signatures.py   magic-byte type detection, mismatch rules
│   │   ├── macro_scan.py        oletools VBA static analysis
│   │   ├── image_forensics.py   QR (pyzbar/OpenCV) + OCR (Tesseract)
│   │   ├── link_analysis.py     B5 href vs visible text
│   │   ├── qr_trace.py          B6 QR destination trace
│   │   └── ioc_extraction.py    Stage D
│   ├── threat_intel/         Stage E
│   │   ├── threat_intel.py   enrich_iocs(): budgets, offline placeholders
│   │   ├── ip_lookup.py      AbuseIPDB + ip-api.com batch geolocation, SSRF guard
│   │   ├── domain_lookup.py  python-whois
│   │   ├── vt_lookup.py      VirusTotal v3 + sliding-window limiter
│   │   ├── hop_geo.py        geolocate Received hops, re-judge origin
│   │   └── cache.py          in-process TTLCache
│   ├── correlation/          Stage F
│   │   ├── engine.py         correlate_and_store(): match, campaign assign/merge, insert
│   │   ├── historical_stats.py week/month/all-time repetition, NEW vs RECURRING
│   │   └── queries.py        read-only inventory queries
│   ├── ai_engine/            Stages C′, F′, G
│   │   ├── triage_model.py   6 features + XGBoost inference
│   │   ├── train_triage_model.py / convert_dataset.py   training utilities
│   │   ├── models/xgboost_phish_model.pkl               bundled model
│   │   ├── graph_diffusion.py Personalized PageRank over the threat graph
│   │   ├── stage_g.py        Gemini combined call, model fallback chain, offline fallback
│   │   ├── main.py           Gemini client factory, legacy content classifier
│   │   ├── prompts.py        30-category content-analysis system prompt
│   │   └── schemas.py        Pydantic response schemas
│   ├── rag/                  SOC Assistant
│   │   ├── embeddings.py     MiniLM or hash-fallback 384-d embeddings, summaries
│   │   ├── chat.py           active-file or historical retrieval + Gemini answer
│   │   └── backfill_embeddings.py
│   ├── db/
│   │   ├── connection.py     get_db(): real Mongo, fake DB, or auto-fallback
│   │   ├── fake_mongo.py     in-memory subset of pymongo
│   │   ├── repository.py     every read/write
│   │   ├── schema.py         collection names + indexes
│   │   └── scoped.py         NOT USED: owner-scoped adapter (legacy auth)
│   ├── eval/                 labelled-corpus evaluation harness (+ results/)
│   └── tests/                ~30 pytest files, ~145 tests
├── frontend/                 React 18 + Vite (see §11)
├── extension/                Gmail Manifest V3 extension (see §12)
├── docs/
│   ├── workflow/             etap-workflow.mmd/.png (pipeline diagram)
│   ├── extracted/            24 SpamAssassin-style JSON messages (eval fixture)
│   ├── mock_dataset/, parser_fixtures/   small JSON fixtures for tests
│   └── slides/               research-and-references deck
└── samples/email_dataset/    set_01..05 manifests (raw emails are git-ignored)
```

---

## 4. The analysis pipeline, stage by stage

### Input modes

`pipeline.VALID_SOURCES`:

- `full_message` (default) — the original message; every stage runs.
- `quick_content_check` — the message was rebuilt from text visible in a mail client (extension fallback). Header auth/routing are marked `not_available` (no live DNS guessing), XGBoost bypass is disabled, and the evidence report lists the limitation.

### Stage A — Parsing (`backend/email_parser/`)

**Contract** (`models.py`): `ParsedEmail` with `subject, from_raw, from_display_name, from_email, to, reply_to, date, message_id, all_headers: Dict[str, List[str]]` (lists, because `Received` repeats), `body_text, body_html, attachments: List[Attachment], source_format ("eml"|"msg"|"csv"), parse_warnings`. `Attachment` = `filename, content_type (declared), size_bytes, content_bytes_b64`.

**File-type detection** (`unified_parser.detect_file_type`): reads the first bytes. Rejects `MZ` (PE), `\x7fELF`, `PK\x03\x04` (ZIP/OOXML), `%PDF`, Mach-O, RAR, 7z regardless of extension. OLE signature `D0 CF 11 E0 A1 B1 1A E1` → `msg`; a `.msg` without it is rejected. Otherwise, if the first 2 KB contain a common header name (`from:`, `received:`, `mime-version:`…) or the extension is `.eml/.rfc822/.txt` → `eml`. Raises `UnsupportedFileTypeError` (HTTP 400).

**`.eml`** (`eml_parser.parse_eml_bytes`): `email.message_from_bytes(policy=policy.default)`, `parseaddr` for display name/address, every header kept. Walks the MIME tree: parts with `Content-Disposition: attachment` or any filename become attachments (decoded bytes → base64); `text/plain` and `text/html` leaves are concatenated. `_get_text_content` survives invalid charsets (e.g. `charset=DEFAULT`) by falling back to UTF-8 with replacement and recording a parse warning — an empty body must never look clean.

**`.msg`** (`msg_parser.parse_msg`): `extract_msg.Message`. If construction itself fails (malformed attachment streams), returns a mostly empty `ParsedEmail` with a warning instead of crashing. Uploaded `.msg` bytes are written to a temp file because extract-msg needs a path.

**`.csv`** (`csv_parser.parse_csv_dataset`): column aliases (`sender/from`, `body/text/content`, `label/class`…); each row becomes an RFC 822 message (`X-Dataset-Label`, `X-Extracted-URLs` headers) and goes through the same `.eml` parser. `parse_any()` returns a list for CSV and a single object otherwise.

**PII masking** (`pii_masker.redact_sensitive_data`): applied to subject and bodies at parse time. Replaces SSN, 13–16 digit card numbers, Indian mobile (`+91`, 10 digits starting 6–9), US phone, Aadhaar (12 digits), PAN (`AAAAA9999A`) and email addresses with `[REDACTED_*]` tokens. Note: because body email addresses are masked before IOC extraction, those addresses' domains are not extracted from the body (header addresses are unaffected).

### Stage B — Header forensics (`forensics/header_forensics.py` and helpers)

`analyze_headers(parsed, headers_available=True)` returns a `HeaderAnalysis` dict: `sender_email, display_name, reply_to, spf, dkim, dmarc, originating_ip, received_chain, hops, origin_analysis, auth_details, domain_analysis, reply_to_mismatch, available, unavailable_reason, red_flags, risk_indicator_count`.

**Authentication** (`auth_results.evaluate_authentication`), per mechanism:

- *Tier 1 (preferred):* regex `spf=…`, `dkim=…`, `dmarc=…` out of `Authentication-Results`; legacy `Received-SPF`. Source = `header_reported`.
- *Tier 2 (fallback, needs `dnspython`):* source = `live_dns_check`, 4 s DNS timeout.
  - SPF: fetch `v=spf1` TXT; evaluate `ip4/ip6` CIDR, `a`, one level of `include:`, and the trailing `all` qualifier (`+`/`-`/`~`/`?` → pass/fail/softfail/neutral) against the originating IP.
  - DKIM: parse `d=` and `s=` from `DKIM-Signature`, look up `<s>._domainkey.<d>`; verdicts `no_signature`, `key_not_found`, `misaligned` (signing domain ≠ From domain) or `key_found_unverified`. **Signatures are never cryptographically verified** (raw bytes aren't retained) and the output says so.
  - DMARC: fetch `_dmarc.<domain>`, parse `p=`; verdict `record_found` / `no_record`.

Red flags: `spf_fail|softfail`, `dkim_fail|key_not_found|misaligned`, `dmarc_fail`, `no_received_headers`, `reply_to_domain_mismatch`, plus domain flags below.

**Received chain** (`received_chain.py`):

- `parse_hops` returns hops oldest-first. For each hop: the connecting IP is taken **only from the `from` clause** (bracketed `[1.2.3.4]` preferred, then parenthesised, then bare; compressed IPv6 supported), rDNS/HELO host, `by` host, `with` protocol, UTC timestamp, `delay_s` from the previous hop, `out_of_order` (delay < −300 s).
- `kind`: `private` (non-public IP), `anonymizer` (set later from geo proxy flag), `provider_relay` (host suffix in Google/Microsoft/Amazon SES/Yahoo/SendGrid/Mailgun/Mailchimp/Proton/Zoho/Apple list), else `relay`.
- `find_originating_ip` — first public IP in the chain; deliberately unchanged because SPF is evaluated against it.
- `resolve_origin` — the *display* origin with `origin_kind`:
  - `sender_client` — from a client-IP header (`X-Originating-IP`, `X-Sender-IP`, `X-Client-IP`, `X-Real-IP`) not equal to a provider relay (confidence medium), or the first public hop is not a provider and nothing public precedes it (high);
  - `provider_relay_only` — first public hop is Gmail/Outlook/etc.: *the provider strips the sender IP; the true origin cannot be determined* (no origin IP shown);
  - `anonymizer_exit` — Tor/VPN/proxy exit; real IP unrecoverable;
  - `unknown_relay` — public, unknown provider, low confidence;
  - `none` — no public IP at all.

**Sender-domain checks** (`domain_similarity.analyze_domain`) — pure string/Unicode, no network:

- punycode (`xn--`) decode → `punycode_domain`; mixed Latin + Cyrillic/Greek → `homograph_attack_suspected`;
- `find_lookalike_brand`: brand root (`get_brand_root`, handles `co.in`, `gov.in`, `co.uk`…) compared with each brand in `brand_domains.COMMONLY_IMPERSONATED_DOMAINS` (global tech, global banks, Indian banks, Indian government portals, UPI/fintech). `brand_plus_lure` when the exact brand token appears with a lure word (`secure`, `verify`, `login`, `support`…); `typosquat` when `difflib` similarity ≥ 0.80 (plus Levenshtein distance reported). Flag `lookalike_of_<brand>`.
- display-name impersonation: brand mentioned in the display name (words and adjacent-word pairs, not raw substrings) **and** a trigger word (`support`, `security`, `billing`, `team`…) while the domain root differs → `display_name_claims_<brand>_but_domain_is_<domain>`.

### Stage B2 — Attachment forensics (`forensics/attachment_forensics.py`)

`analyze_attachment` per file, result fields: `filename, declared_type, sha256, size_bytes, actual_type, type_mismatch, has_macro, macro_behavior, suspicious, flags, ocr_text, qr_urls, qr_payloads, qr_status, is_image`.

- **Type detection** (`file_signatures.detect_actual_type`): `MZ` is always `application/x-msdownload`; then libmagic (`python-magic`, if installed and not `octet-stream`); then a hand-rolled table (PDF, ZIP, OLE, JPEG, PNG, GIF, PostScript, ELF, gzip, RAR, 7z, RTF). ZIPs are refined to docx/xlsx/pptx by looking for `word/`, `xl/`, `ppt/` in the first 4 KB.
- **Mismatch** (`types_conflict`): lenient — `octet-stream` declarations and the whole Office family (legacy, OOXML, OLE, zip) are treated as equivalent.
- **Double extension**: ends in `.exe/.scr/.bat/.cmd/.js/.vbs/.msi/.ps1` and contains `.pdf./.doc./.jpg./.png./.txt.`.
- **Disguised executable**: actual type PE/ELF but the name doesn't end in `.exe/.dll/.scr/.msi`.
- **Macros** (`macro_scan.analyze_macro_behavior`, oletools `VBA_Parser`): only for Office names/types. Never executes. Categories from `analyze_macros()`: `AutoExec` → `autoexec_triggers`, `Suspicious` → `suspicious_actions`, `IOC` → `referenced_iocs`. Parse failure (password-protected/corrupt) → suspicious.
- **Images** (`image_forensics.scan_image_attachment`): decode with OpenCV and PIL; QR via pyzbar, then OpenCV `QRCodeDetector` (multi then single); `qr_status` ∈ `decoded | no_qr_found | decoder_unavailable | image_unreadable | scan_failed`; QR payloads kept (URL or other), URLs extracted. OCR via pytesseract on the grayscale image (hard-coded Windows path `C:\Program Files\Tesseract-OCR\tesseract.exe` is used if it exists).
- `suspicious = mismatch or has_macro or double_ext or disguised_exe or qr_urls`.

### Stage B5 — Link analysis (`forensics/link_analysis.py`)

`analyze_links(body_html)` parses anchors with `html.parser` (an `<img alt>` inside a link counts as visible text), deduplicates, caps at 200. `analyze_url(href, display_text)` flags: `non_web_scheme` (`javascript:`, `data:`, `vbscript:`), `plain_http`, `userinfo_in_url`, `ip_address_host`, `non_standard_port`, `url_shortener` (bit.ly, tinyurl, t.co, …), `punycode_host`, `homograph_suspected`, `lookalike_domain`, `redirect_parameter_to_other_site` (query keys like `url`, `redirect`, `next`, `goto` pointing at a different registrable domain — reported as `inferred_target_host`), `text_shows_different_site`, `text_names_brand_link_goes_elsewhere`. `resolution.status` is always `not_resolved`: nothing is fetched.

### Stage B6 — QR trace (`forensics/qr_trace.py`)

For each image attachment: source filename, decoder status, whether it was actually checked, and each decoded payload — URLs run through `analyze_url` plus `privacy.personalised_url`. A QR code is not evidence by itself; only what its destination shows is.

### Stage D — IOC extraction (`forensics/ioc_extraction.py`)

`extract_iocs(all_headers, body_text, body_html, attachment_analysis, header_analysis)` → `{ips, domains, urls, hashes, ioc_metadata}` (sorted, deduplicated). Sources: every header value, plain body, HTML (after stripping `<style>`/`<script>`), HTML URL attributes (`href, src, action, poster, data, formaction`), Stage B (originating IP, sender/reply-to domains, canonical From domain, DKIM signing domain), Stage B2 SHA-256s, QR URLs (with `ioc_metadata` provenance `QR in <file>`), and every URL's host.

Noise rules (each documented in the module): final label must be in a frozen IANA TLD snapshot; a dotted token followed by `@` is a local part, not a domain; only globally routable IPs; URLs masked before hash scanning; hashes with ≤ 3 distinct characters dropped; repeated percent-decoding (`_fully_unquote`, max 5 passes) before domain scanning; emails masked after unquoting; boilerplate hosts (`w3.org`, `schemas.microsoft.com`, `schemas.openxmlformats.org`, `purl.org`) dropped. Defanged forms (`hxxp`, `[.]`, `(.)`, `[dot]`) are normalised.

### Stage E — Threat intelligence (`threat_intel/`)

Controlled by `THREAT_INTEL_LIVE`. When off, `enrich_iocs` returns `lookup_mode: offline_placeholder` with `status: not_checked, malicious: None` for every indicator.

When live (`threat_intel.enrich_iocs`), budget = `THREAT_INTEL_MAX_LOOKUPS_PER_PROVIDER` (default 2, clamped 1–20) per provider per email; VirusTotal URL + hash share one budget. Over-budget indicators get `skipped_limit`.

| Module | Provider / endpoint | Details |
|---|---|---|
| `ip_lookup.check_ip_reputation` | AbuseIPDB `GET /api/v2/check` (`maxAgeInDays=90`) | `malicious = abuseConfidenceScore ≥ 50`; returns score, reports, country, ISP, domain, `is_tor`. SSRF guard: non-public IPs → `skipped_non_public`. Cache 1 h. |
| `ip_lookup.get_ip_geolocation` | ip-api.com `POST /batch` (no key, ≤ 100 IPs/call, HTTP) | lat, lon, countryCode, isp, org, `hosting`, `proxy`. Only successes cached. |
| `domain_lookup.get_domain_info` | python-whois | `age_days`, registrar, creation date, country; 3 s socket timeout; library stdout/stderr suppressed; 24 h cache; failures `age_days: -1`. |
| `vt_lookup.check_url_reputation` / `check_hash_reputation` | VirusTotal v3 `GET /urls/{base64url-id}`, `GET /files/{hash}` | `malicious = malicious + suspicious engines > 0`; 404 → `not_found` (cached, "never seen", not clean); 429 → `rate_limited`; internal sliding-window limiter at 4 req/min → `rate_limited_internal`. Only definitive answers cached. URLs pass through `privacy.plan_url_lookup` first. |

All provider errors are scrubbed (exception type only, never URLs/keys). Statuses used across the system: `available, not_found, not_checked, not_configured, timeout, network_error, invalid_response, provider_error, rate_limited, rate_limited_internal, skipped_limit, skipped_privacy, skipped_non_public, disabled`.

**Sender IP locator** (`hop_geo.attach_hop_geo`): takes up to 12 public hop IPs, reuses geo results already fetched, batch-geolocates the rest (when live), attaches `hop["geo"]`, infers the provider from the ASN org/ISP (`provider_from_org`), marks hops with `proxy=true` as `anonymizer`, reclassifies, then **re-runs `resolve_origin`** so the final `header_analysis.origin_analysis` reflects network ownership. The frontend `GeoMap` draws these hops; provider relays are amber, not red, because they are infrastructure, not the sender.

### Stage F — Correlation (`correlation/engine.py`, `historical_stats.py`)

`correlate_and_store(ioc_analysis, db=…, message_id, subject, from_email, …)`:

1. If the `message_id` was analysed before, that record is excluded from matching and its campaign is remembered (idempotent re-analysis).
2. Exact matches for `ips, urls, hashes, domains` via indexed `$in` queries.
3. Fuzzy domain matches: every distinct stored domain whose brand root equals, or whose roots (≥ 4 chars) are ≥ 0.82 similar to, a current domain.
4. Campaign: no match → new `campaign_NNN` (atomic counter); one campaign → join; several → merge into the lowest ID (absorbed campaigns keep `merged_into` for audit).
5. Insert/upsert the analysis doc (upsert by `message_id`), update campaign membership and shared infrastructure.
6. `compute_historical_stats`: per indicator, counts this week (7 d), this month (30 d), all-time, first/last seen, associated campaigns, up to 10 prior incidents; overall `category_status` = `NEW_THREAT_CLUSTER` or `RECURRING_ADVERSARY_ACTIVITY`, a badge like `RECURRING THREAT (3x THIS WEEK)` and an executive summary.
7. Invalidate the graph-diffusion adjacency cache.

Returns `email_id, campaign_id, is_new_campaign, category_status, historical_stats, merged_campaigns, related_emails, shared_infrastructure`.

### Stage F′ — Graph diffusion (`ai_engine/graph_diffusion.py`)

- Graph (`extract_graph_from_correlation`): nodes for the email, its campaign, related emails, each IP/domain/URL/hash IOC and each shared-infrastructure value; undirected edges (`part_of_campaign`, `correlates_with`, `communicates_with_ip`, `resolves_domain`, `contains_url`, `payload_digest`, `shares_infrastructure`, `campaign_infrastructure`).
- Seeds: IOC nodes with `malicious is True`, VT engine count ≥ `SEED_VT_THRESHOLD` (3) or AbuseIPDB score ≥ `SEED_ABUSEIPDB_THRESHOLD` (50).
- Math: `Â = D̃^{-1/2}(A + I)D̃^{-1/2}` (scipy.sparse), then `y_{t+1} = α·Â·y_t + (1−α)·y_0` for `DIFFUSION_HOPS` (3) iterations, `α = DIFFUSION_ALPHA` (0.85), normalised to [0, 1]. BFS gives the nearest-seed path for the explanation.
- Fails open: fewer than `DIFFUSION_MIN_NODES` (5) nodes, or no seeds, → `available: false`. Normalised adjacency is cached by a SHA-256 fingerprint of nodes+edges.
- Output: `diffusion_score, hops_used, nearest_seed_distance, contributing_seeds, node_scores, explanation`. It is reported and visualised (ThreatGraph overlay) but is **not** an input to the verdict score.

### Stage C′ — XGBoost metadata triage (`ai_engine/triage_model.py`)

Features, in this exact order (`FEATURE_NAMES`): `has_attachment, num_urls_in_body, sender_domain_age_days (−1 unknown), auth_spf_pass, subject_length, is_urgent_keyword_present`. Model: `models/xgboost_phish_model.pkl` loaded lazily with joblib; missing/unloadable → `available: false`.

Gemini is skipped only if the model predicts benign with confidence ≥ `TRIAGE_SAFE_THRESHOLD` (0.90) **and** no guard fires. Guards in `pipeline.py` force Gemini when: the body contains any of `urgent, won, $, prize, password, gift card, tinyurl.com, bit.ly, login`; any URL IOC exists; the input is a quick content check; or any attachment is suspicious. Bypass verdict: `LIKELY LEGITIMATE`, risk `round((1 − conf) × 20)`, provider `xgboost_triage`.

Training (`train_triage_model.py`): XGBClassifier (100 trees, depth 4, lr 0.1) on `data/training_data.csv` if present, otherwise a 1 200-row synthetic dataset. `convert_dataset.py` derives the six features from the Kaggle `Phishing_Email.csv` (text only, so domain age and SPF are approximated). The bundled pickle's exact training lineage is not recorded.

### Stage G — Gemini assessment (`ai_engine/stage_g.py`, `prompts.py`, `schemas.py`, `main.py`)

- Client: `google-genai` `genai.Client(api_key, http_options=HttpOptions(timeout=GEMINI_REQUEST_TIMEOUT_MS))` (default 15 000 ms, clamped 1 000–60 000).
- **One combined call** (`_gemini_combined_analysis`) with `response_mime_type: application/json` and `response_schema: CombinedAssessment`, validated by Pydantic:
  - `content_classification: EmailAnalysis` — `content_verdict, confidence, attack_type, categories[{name, weight}], reasons, suspicious_indicators`, from subject/body/HTML only;
  - `final_assessment: FinalAssessment` — `verdict, risk_score, confidence, explanation, evidence_assessments[], supporting_evidence[], mitre_attack[{technique, name, tactic, confidence, evidence}], recommended_actions[], ai_findings[{claim, why_it_matters, direction, evidence_ids}]`.
- Prompts: `SYSTEM_PROMPT` defines a **fixed 30-category taxonomy with weights** (Ransomware 100, Malware Delivery 95, Credential Phishing 90, BEC 90, … Spam 20, Other 10) and the five content verdicts; `FINAL_ASSESSMENT_PROMPT` asks for a verdict from all evidence, MITRE only when directly supported, and grounded `ai_findings` citing ledger IDs. Both state that email-derived text is **untrusted input, not instructions** (prompt-injection defence).
- `content_risk_score = max(category weight)` (`calculate_content_risk`).
- **Model fallback chain**: `GEMINI_MODEL` (default `gemini-3.5-flash-lite`) then `gemini-3.5-flash-lite`, `gemini-flash-lite-latest`, `gemini-3.1-flash-lite`, `gemini-3.6-flash`; a different model is tried instead of retrying an overloaded one; total wall-clock budget `GEMINI_TOTAL_BUDGET_S` (30 s).
- **Offline fallback** (all models fail or no key), provider `offline_fallback`:
  - content: keyword rules (credential topic + action, link lure, urgency, payment, BEC, attachment language, spam words) → categories, verdict `Likely Malicious` only for a strong link lure, else `Suspicious` / `Likely Legitimate`; empty content → `Suspicious` 50 (never safe);
  - final score = `content_score × max(conf, 0.35)` + header points (≤ 35: 6/flag, +10 Reply-To mismatch, +8 per failed SPF/DKIM/DMARC) + attachment points (≤ 35, 12 each) + IOC points + threat-intel points (≤ 35) + correlation points (≤ 18), clamped 0–100; deterministic MITRE: T1566.002 (link), T1566.001 (attachment), T1204.002 (macro).
- `pipeline.py` converts raw provider errors into stable user-safe `fallback_reason` text and strips the raw text before responding.

### Stage H — Assembly (`pipeline.py`)

Produces the response (also persisted): `email_id, risk_score, verdict, verdict_band, analysis_provenance, evidence_report, link_analysis, qr_trace, privacy_report, provider_status, email, headers, attachments, iocs, threat_intel, correlation, historical_correlation, category_status, graph_diffusion, ai_analysis{content_classification, final_assessment}, mitre_attack, triage, stage_status`, then `finish_analysis` adds `retention` and `baseline_context`.

`analysis_provenance`: `input_mode, headers_available, threat_intel_mode, threat_intel_lookups, threat_intel_unavailable, assessment_provider, assessment_model, fallback_used, fallback_reason, gemini_skipped_by_triage, verdict_reconciled, verdict_original, provider_status_summary, provider_coverage_status, analysis_duration_ms`.

`stage_status`: `A, B (complete|headers_unavailable), B2, D, E (live|offline_placeholder), F, F_prime (complete|insufficient_data), C_prime (bypassed_gemini|evaluated|offline), G (skipped_by_triage|gemini|offline_fallback), H`.

---

## 5. Verdicts, scoring and the evidence report

**`backend/verdicts.py`** (mirrored by `frontend/src/utils/verdict.js`; `tests/test_verdicts.py` fails if they drift):

| Label | Min score | Band |
|---|---|---|
| LIKELY LEGITIMATE | 0 | safe |
| LOW RISK | 20 | safe |
| SUSPICIOUS | 40 | caution |
| LIKELY PHISHING | 65 | danger |
| HIGH-RISK PHISHING | 85 | danger |

`finalize_verdict(raw_label, score)` normalises any spelling (`"Likely Malicious"`, `"clean"`, `"Highly Suspicious / Malicious"`…) and takes the **more severe** of label and score; `reconciled` and `original_label` keep the disagreement visible.

**Evidence ledger** (`backend/evidence.py`, `SCHEMA_VERSION = 2`). Each item: `id, kind (observed|reputation|ai_inferred), section, title, detail, status (present|absent|unavailable), direction (raises_risk|lowers_risk|neutral), weight (strong|weak), why, source, grounding, evidence_ids, data`, plus v2 fields (raw observation, normalised explanation, provenance/source type, supports/contradicts). ID families:

- `hdr.auth`, `hdr.sender`, `hdr.flag.<code>`, `hdr.flag.reply_to_domain_mismatch`
- `link.count|scope|none|resolution|text_check|text_ok`, `link.flag.<i>`
- `att.none|scope`, `att.<n>.clean|type_mismatch|macro|flag.<x>|qr.<q>`
- `qr.<n>.none|unchecked|<q>|<q>.text`
- `rep.offline|none`, `rep.<ip|domain|url|hash>.clean|unseen|unavailable|flagged.<i>`, `rep.domain.young.<i>`, `rep.domain.aged`
- `corr.campaign|related|shared`
- `ai.triage`, `ai.content.<n>`, `ai.finding.<n>`

`compact_ledger` (id/kind/title/detail/status/direction/weight) is placed in the Gemini context; AI findings citing unknown IDs become `grounding: ungrounded` and never become headline reasons.

`build_evidence_report` returns: `conclusion{label, band, risk_score, confidence, confidence_level, evidence_state (high_risk_evidence|suspicious_uncertain|no_high_risk_found), state_text, limitations, reconciled}`, `headline`, `top_reasons` (3 ids, strong before weak, observed before reputation before AI), `contradicting`, `evidence`, `sections{observed, reputation, ai_inferred, not_checked}`, `ai_summary`, `what_to_do{steps[{text, basis: evidence|policy, ref}], ai_suggestions}`, `counts`. Confidence is downgraded when limitations exist. There is deliberately no "safe" state. Older stored records are rebuilt by `build_for_stored_record` and marked `reconstructed`.

**Provider status** (`provider_status.build_provider_status`): one entry each for `gemini, virustotal, abuseipdb, whois, ip_geolocation` with counts and a status (`available, fallback_model_used, partial, unavailable, not_configured, timeout, rate_limited, disabled, not_needed, skipped_by_triage, skipped_for_privacy, skipped_by_policy, unknown`), plus `coverage_status` (`complete|partial`) and a summary. This is separate from the threat verdict.

---

## 6. Privacy model

- **At parse time:** PII masking (§4 A).
- **VirusTotal URL policy** (`privacy.plan_url_lookup`): `skip` if the URL has credentials, a private/internal host (`.local`, `.internal`, `.corp`, RFC1918…), an email address, a sensitive parameter name (`token, sid, code, otp, email, user, reset, session, jwt…`, matched as whole camel/snake tokens), a token-like value (hex ≥ 16, UUID, high-entropy base64), or a high-entropy path segment; `trimmed` (scheme://host/path) if it only has a query/fragment; else `full`. Skipped → `skipped_privacy`, shown as "not looked up for privacy", never clean.
- **Gemini context** (`sanitize_for_external_ai`): recursively rewrites every URL in strings and dict keys (`…/[sensitive destination details omitted]` or trimmed), then re-applies PII masking. The original evidence stays server-side. The RAG chat uses the same sanitizer.
- **Privacy report** (`build_privacy_report`): describes, from what the code actually did, where content went (backend processing, DB storage, VirusTotal full/trimmed/skipped/cached counts, AbuseIPDB, WHOIS, geolocation, Gemini used/skipped).
- **Logs:** pipeline debug logs record counts only; provider errors are type-only; `_short_reason` scrubs `AIza…` keys and `key=` parameters.
- **SSRF guard:** private/loopback/link-local/reserved IPs are never sent to providers.
- **Share pack** (`workflow_c.share_pack`): strict allowlist — verdict, score, enumerated SPF/DKIM/DMARC values, hex hashes, evidence id/kind/status. No body, addresses, filenames, URLs, domains or model text.

---

## 7. Persistence (MongoDB)

`db/connection.get_db()`: `USE_FAKE_DB=1` → in-memory `FakeDatabase` (subset of pymongo: find/find_one/insert/update/find_one_and_update/count/distinct/delete, `$in $gte $lte $set $inc $push $addToSet`); otherwise pymongo `MongoClient(MONGODB_URI or MONGO_URI, serverSelectionTimeoutMS=5000)` with a ping and `ensure_indexes`. DB name: `MONGO_DB_NAME`, else the URI path, else `phishing-investigator` (`.env.example` uses `etap`). `AUTO_FALLBACK_DB=1` silently falls back to the fake DB on connection failure (keep it 0 in production).

Collections:

- `analyzed_emails` — one doc per email: `message_id, subject, from_email, to_email, email_date, source_format, analyzed_at, header_analysis, attachment_analysis, threat_intel_analysis, content_analysis, ioc_analysis{ips,domains,urls,hashes}, campaign_id`, then H fields (`final_assessment, mitre_attack, risk_score, verdict, verdict_band, triage, graph_diffusion, evidence_report, link_analysis, qr_trace, privacy_report, provider_status, analysis_provenance, stage_status`), Workflow C fields (`expires_at, retention_days, workflow{state, history, notes, explanation}, case, case_history, feedback, baseline_context`) and RAG fields (`rag_summary, rag_embedding[384]`). Indexes: unique `(owner_id, message_id)` partial (legacy name; `owner_id` is no longer written), `analyzed_at`, `campaign_id`, each `ioc_analysis.*`.
- `campaigns` — `campaign_id, members[], shared_infrastructure[], merged_into, created_at, updated_at`.
- `counters` — `{_id: "campaign_id", seq}` for sequential campaign IDs.
- `preferences` — `{kind: "settings", retention_days}`, `{kind: "baselines", domains[]}`.
- `emails` — legacy RAG index collection, cleaned on delete.

All access goes through `db/repository.py`; every function takes `db` explicitly.

---

## 8. HTTP API

`backend/app.py` + `workflow_c.router`. Rate limiting: slowapi, per remote IP, default 120/min. CORS: exact origins from `ALLOWED_ORIGINS`. Upload streamed in 64 KB chunks, max 25 MB (413). Internal errors never return stack traces or paths.

| Method & path | Purpose |
|---|---|
| `GET /`, `HEAD /` | service index |
| `GET /health` | liveness |
| `GET /ready` | DB ping; 503 when unavailable |
| `POST /analyze` (10/min) | multipart `file` + optional `source` (`full_message`, `quick_content_check`) → full report |
| `POST /chat` (30/min) | `{question, email_id?}`; client `email_context` is rejected (400) |
| `GET /investigations?offset&limit` | listing (limit 1–100) |
| `GET /investigations/{id}` (60/min) | stored report in the same shape as `/analyze` |
| `DELETE /investigations/{id}`, `DELETE /investigations` | delete one / all (also campaigns refs, RAG vectors, graph cache) |
| `GET /investigations/{id}/share` | redacted share pack |
| `GET/PATCH /investigations/{id}/workflow` | review state with optimistic concurrency (`expected_state`, 409 on conflict) |
| `GET /investigations/{id}/related` | Campaign Lens: subject-token Jaccard ≥ 0.8 or shared IOCs among 200 recent |
| `PUT /investigations/{id}/case` | case label + assignee text |
| `PUT /investigations/{id}/feedback` | `helpful` / `incorrect` |
| `GET /campaigns` | campaign inventory |
| `GET/PUT /preferences` | `retention_days` 1–365 |
| `GET/PUT /baselines` | user-declared trusted domains (context only, never changes the score) |
| `GET /analytics` | measured aggregates over ≤ 5 000 records |
| `GET /recovery` | versioned fixed recovery checklists |
| `/docs` | Swagger UI |

The API is **open**: no authentication or per-user scoping (see §17).

---

## 9. RAG / SOC Assistant

- **Indexing** (background thread after each analysis): `rag/embeddings.build_summary` writes one sentence-style summary (incident id, verdict, score, campaign, sender, subject, IPs, domains, URLs, MITRE, assessment ≤ 280 chars); `embed_text` encodes it with sentence-transformers `all-MiniLM-L6-v2` (384-d) **if installed**, otherwise a deterministic hashed bag-of-words 384-d vector. On Render (`RENDER` env) or `USE_FALLBACK_EMBEDDINGS=1` the fallback is always used (memory). `backfill_embeddings.py` indexes older records.
- **Answering** (`rag/chat.answer_query`):
  - *Active-file mode* (`email_id` given): loads that record, builds a telemetry block (`_build_single_file_context`), sanitizes it, asks Gemini to answer **only** about that email; offline fallback prints the structured telemetry.
  - *Historical mode*: retrieves the top 5 records by cosine similarity (brute force in Python by default; `USE_ATLAS_VECTOR_SEARCH=1` uses an Atlas `$vectorSearch` index `ATLAS_VECTOR_INDEX`, default `vector_index`, path `rag_embedding`) and asks Gemini to answer citing incident IDs; offline fallback lists the top 3.
  - Both prompts treat retrieved content as untrusted data.

---

## 10. Workflow C: review, retention, sharing

Implemented in `backend/workflow_c.py`, `recovery.py`, `integrations.py`.

- **Retention:** `finish_analysis` sets `expires_at = now + retention_days` (default 30) and purges expired records on every analysis; `purge_retention.py` is the cron version.
- **Deletion:** `delete_record` removes the analysis, legacy RAG entries, rebuilds campaign membership, clears stored graph/correlation/RAG snapshots on remaining records and invalidates the graph cache. Not a transaction; cannot recall provider copies.
- **Review workflow:** states `submitted → analyzed → needs_review | confirmed_malicious | benign_or_spam | unresolved`; history ≤ 200, notes ≤ 2 000 chars; never changes the verdict.
- **Recovery checklists:** opened email, clicked link/QR, downloaded file, opened attachment, entered password, approved MFA, sent money — deterministic, versioned (`2026-10-18.1`), no device-compromise inference.
- **Baselines, case marking, feedback, analytics, Campaign Lens:** see §8.
- **Scaffolds (not live):** `integrations.OriginalMessageProvider` (future OAuth original-message retrieval, mock only) and webhook contracts (`analysis.completed`, `review.changed`; HMAC-SHA256 over `timestamp.body`, 5-minute window, replay set, HTTPS-443 public-IP target validation, bounded retry delays) — nothing is ever sent.

Status table from the original Workflow C record: C1 evidence v2 ✔, C2 recovery ✔, C3 review ✔, C4 share pack partial, C5 auth deferred, C6 retention ✔ (needs cron), C7 original-message integration scaffold, C8 case management partial, C9 webhooks scaffold, C10 baselines partial, C11 analytics partial, C12 local/private mode design-only, C13 language/accessibility partial (fixed EN/ES/HI summaries), C14 deployment docs ✔.

---

## 11. Frontend (React dashboard)

Location `frontend/`. React 18, Vite 8 (`@vitejs/plugin-react`), Node ≥ 22.12. Dev server bound to `127.0.0.1:5173` (security note in `vite.config.js`) with a proxy for `/analyze /health /ready /chat /investigations /campaigns /preferences /recovery /analytics /baselines /me` → `127.0.0.1:5000`. Production uses `VITE_API_BASE_URL`.

- `src/main.jsx`, `App.jsx` — views: `overview`, `upload`, `dashboard`, `history`, `workspace`; handles the `?dossier=<email_id>` deep link used by the extension.
- `context/InvestigationContext.jsx` — global state (status, data, error, active file, backend health polling via `/ready`, browser-session history under `E-TAP_investigations_history_v1`, a `SAMPLE_REPORT` schema reference).
- `api/client.js` (axios, 120 s timeout, `askSocAssistant`), `api/analyze.js` (`analyzeEmailFile`, `checkBackendHealth`, `fetchInvestigation`).
- `pages/` — `OverviewPage` (Recharts score trend, band counts), `UploadPage` (drag-and-drop plus two embedded sample emails sent to the real API), `DashboardPage` (the report), `HistoryPage` (session history + server `GET /investigations`).
- `components/report/` — `VerdictBanner` + `RiskGauge`, `EvidenceNarrative` (renders `evidence_report`), `EvidenceBreakdown` (bar chart of `evidence_assessments`), `HeaderAnalysis`, `GeoMap` (react-leaflet, ArcGIS dark-gray tiles, hop polyline coloured by kind), `AttachmentTable`, `ContentAnalysis`, `IocTable` (with reputation + history columns), `ThreatGraph` (react-force-graph-2d with diffusion overlay and fullscreen), `MitreCards`, `HistoricalCorrelationCard`, `PrivacyDataPanel`, `ProviderStatusPanel`, `ResponseWorkflow` (review, recovery, related, plain-language summary EN/ES/HI), `TrustControls` (retention/delete/share), `ExportButton` + `PdfPreviewModal`.
- `components/chat/SocChatDrawer.jsx` — SOC Assistant with "active file" vs "all investigations" scope.
- `components/common/` — `Header` (sidebar nav), `Icon`, `WorkspaceTools` (analytics + baselines), `AuthGate` (legacy, unused).
- `utils/` — `verdict.js` (threshold mirror, display labels, provenance chips), `geo.js` (shared coordinate validation for map + PDF), `pdfGenerator.js` (jsPDF + autotable report built from the same JSON; map captured with html2canvas), `plainSummary.js`.
- Tests: `frontend/tests/geo.test.mjs`, `report.test.mjs` (`npm test` → `node --test`).

---

## 12. Gmail extension

Location `extension/`, Manifest V3, version 1.5.1. Permissions: `activeTab`, `scripting`; hosts: `mail.google.com`, local backend, Render backend. Config in `config.js` (`apiBaseUrl`, `appBaseUrl`, `requestTimeoutMs` 90 s).

Flow:

1. `content.js` watches Gmail's DOM (MutationObserver, debounced) and inserts an **Analyze in E-TAP** banner above each opened message body (`.ii.gt`). Nothing is read or sent until the click.
2. On click: snapshot sender/subject/visible body; `gmail-original.js` builds a reference from Gmail's message IDs (`data-legacy-message-id` → `th=`, new `msg-f:` IDs → `permmsgid=`) preserving the account path (`/mail/u/N/`, delegated paths, `authuser`).
3. `background.js` (service worker) validates the sender is a Gmail tab, creates a job in `handoff-store.js` (extension-origin IndexedDB, 1 h expiry) and opens `analysis.html?job=<uuid>`.
4. The content script downloads the original message (`view=om`/attachment view, 30 s timeout, 25 MB cap), validates it looks like RFC 822 (`isOriginal`), and hands the base64 bytes to the job.
5. `analysis.js` waits up to 35 s, then `analysis-core.js` uploads either the original (`gmail_original.eml`, `source=full_message`) or a reconstructed text-only message (`gmail_visible_content.eml`, `source=quick_content_check`) to `/analyze`, and redirects to `<appBaseUrl>?dossier=<email_id>`. The tab also offers retry, "continue with visible text", manual `.eml` upload and **Open E-TAP**.

Tests: `extension/tests/original-message.test.mjs` (Node), `backend/tests/test_extension_original.py`. `options.html/options.js` are leftovers from the removed API-key auth.

---

## 13. Libraries and dependencies

### Backend (`backend/requirements.txt`)

| Library | Used in | Why |
|---|---|---|
| fastapi, uvicorn[standard], python-multipart | `app.py` | HTTP API, ASGI server, multipart uploads |
| slowapi | `app.py` | per-IP rate limits |
| pydantic | `app.py`, `ai_engine/schemas.py`, `workflow_c.py` | request validation, Gemini structured-output schemas |
| python-dotenv | `app.py`, `ai_engine` | load `.env` |
| requests | `threat_intel/*` | AbuseIPDB, ip-api, VirusTotal calls |
| python-whois | `domain_lookup.py` | domain age/registrar |
| pymongo | `db/` | MongoDB / Atlas |
| google-genai | `ai_engine/main.py`, `stage_g.py`, `rag/chat.py` | Gemini |
| extract-msg | `msg_parser.py` | Outlook `.msg` |
| oletools | `macro_scan.py` | VBA macro detection and static analysis |
| opencv-python-headless, numpy | `image_forensics.py` | image decode, QR fallback |
| pyzbar (+ system `libzbar0`) | `image_forensics.py` | primary QR decoder |
| Pillow | `image_forensics.py` | image decode |
| pytesseract (+ system `tesseract-ocr`) | `image_forensics.py` | OCR |
| xgboost, scikit-learn, pandas, joblib | `triage_model.py`, training scripts | Stage C′ |
| scipy | `graph_diffusion.py` | sparse matrices |

Standard library modules doing real work: `email`, `email.utils`, `html.parser`, `urllib.parse`, `ipaddress`, `difflib`, `unicodedata`, `hashlib`, `hmac`, `base64`, `threading`, `asyncio`.

Optional, **not** listed in requirements but used when present: `dnspython` (live SPF/DKIM/DMARC fallback; without it the DNS tier returns "none"/"no record"), `python-magic` + libmagic (better type detection), `sentence-transformers` / `torch` (semantic embeddings), `bson` (ships with pymongo).

Dev: `pytest`, `httpx` (`requirements-dev.txt`).

### Frontend (`frontend/package.json`)

| Package | Why |
|---|---|
| react, react-dom 18 | UI |
| axios | API client |
| leaflet, react-leaflet | sender-route map |
| react-force-graph-2d | threat graph |
| recharts | overview trend, evidence breakdown |
| jspdf 4.2.1, jspdf-autotable 5.0.9 | PDF export (html2canvas arrives transitively via jspdf and is imported directly by `ExportButton`) |
| vite 8.3.4, @vitejs/plugin-react 6.1.2 | build/dev |

### External services

Google Gemini, VirusTotal API v3 (free tier 4 req/min, 500/day), AbuseIPDB API v2, ip-api.com batch (free, no key, HTTP only, 15 req/min), WHOIS servers, DNS, ArcGIS map tiles, MongoDB Atlas, Render, Vercel.

---

## 14. Configuration (environment variables)

Backend (`.env` at repo root locally; host settings in production — never in the frontend):

| Variable | Default | Effect |
|---|---|---|
| `MONGODB_URI` / `MONGO_URI` | `mongodb://localhost:27017` | database |
| `MONGO_DB_NAME` | URI path or `phishing-investigator` | database name (`etap` in practice) |
| `USE_FAKE_DB` | `0` | `1` = in-memory DB (data lost on exit) |
| `AUTO_FALLBACK_DB` | `0` | `1` = fake DB if Mongo fails |
| `THREAT_INTEL_LIVE` | `0` | enable Stage E external lookups |
| `THREAT_INTEL_MAX_LOOKUPS_PER_PROVIDER` | `2` | per-email budget (1–20) |
| `ABUSEIPDB_API_KEY`, `VIRUSTOTAL_API_KEY` | — | provider keys |
| `GEMINI_API_KEY` | — | enables Stage G and chat answers |
| `GEMINI_MODEL` | `gemini-3.5-flash-lite` | primary model |
| `GEMINI_REQUEST_TIMEOUT_MS` | `15000` | per request (1 000–60 000) |
| `GEMINI_TOTAL_BUDGET_S` | `30` | whole fallback chain |
| `TRIAGE_SAFE_THRESHOLD` | `0.90` | XGBoost bypass confidence |
| `SEED_VT_THRESHOLD`, `SEED_ABUSEIPDB_THRESHOLD` | `3`, `50` | diffusion seeds |
| `DIFFUSION_ALPHA`, `DIFFUSION_HOPS`, `DIFFUSION_MIN_NODES` | `0.85`, `3`, `5` | diffusion |
| `RAG_EMBEDDING_MODEL` | `all-MiniLM-L6-v2` | embeddings |
| `USE_FALLBACK_EMBEDDINGS`, `RENDER` | — | force hash embeddings |
| `USE_ATLAS_VECTOR_SEARCH`, `ATLAS_VECTOR_INDEX` | `0`, `vector_index` | Atlas vector search |
| `ALLOWED_ORIGINS` | `http://127.0.0.1:5173,http://localhost:5173` | CORS |
| `PORT` | `5000` | server port (Render injects it) |
| `KMP_DUPLICATE_LIB_OK` | set to `TRUE` by `app.py` | avoids an OpenMP clash with torch |

Frontend: `VITE_API_BASE_URL` (empty in dev to use the proxy; the Render URL on Vercel).
Extension: constants in `extension/config.js` and host permissions in `manifest.json`.

---

## 15. Running, testing, evaluating

```bash
# backend
cp .env.example .env                       # USE_FAKE_DB=1 for zero setup
pip install -r backend/requirements.txt
cd backend && python -m uvicorn app:app --host 127.0.0.1 --port 5000

# frontend
cd frontend && npm ci && npm run dev       # http://127.0.0.1:5173

# CLI
cd backend && python run_pipeline.py path/to/email.eml

# tests (offline; no keys needed)
pip install -r backend/requirements-dev.txt
cd backend && python -m pytest tests -q --ignore=tests/test_threat_intel_live.py
cd frontend && npm test && npm run build
node --test --test-isolation=none extension/tests/*.test.mjs
```

Test suites cover: parsing (`test_parse_any`, `test_single_email`), headers/origin (`test_received_chain_origin`, `test_hop_geo`), attachments/macros/images (`test_attachment_forensics`, `test_macro_behavior`, `test_image_forensics`), links/QR/privacy (`test_links_qr_privacy`), threat intel (`test_threat_intel`, live in `test_threat_intel_live`), triage/classifier, graph diffusion, correlation demo, evidence, verdicts (including frontend parity), provider status, truthfulness, RAG and chat API, the offline pipeline end-to-end, extension original-message parity and Workflow C (API, response, security, strategic, trust). `tests/run_batch_test.py`, `run_full_pipeline_test.py`, `batch_ioc_test.py`, `generate_sample_outputs.py` are manual scripts.

**Evaluation** (`backend/eval/`): `python -m eval.run_eval ../docs/extracted [--use-gemini --live-threat-intel] [--out eval/results]` runs a labelled corpus through the real pipeline with a fresh fake DB per message and reports FPR/FNR with 95% Wilson intervals at three operating points (danger band, caution-or-worse, `high_risk_evidence`). The committed result (`eval/results/report.md`) is a 24-message, offline-only debugging run on 2002-era SpamAssassin mail — **not a benchmark**; it flags 1/15 ham and 0/9 spam at the danger band. No detection-rate claim should be made until a broader, authorised phishing corpus is evaluated with Gemini and live intel enabled.

---

## 16. Deployment

- **Backend → Render** (Docker): root/build context `backend`, `backend/Dockerfile` (python:3.11-slim + `tesseract-ocr`, `tesseract-ocr-eng`, `libtesseract-dev`, `libzbar0`; `uvicorn app:app --host 0.0.0.0 --port ${PORT:-5000}`), health check `/health`. Set `MONGODB_URI, MONGO_DB_NAME=etap, USE_FAKE_DB=0, AUTO_FALLBACK_DB=0, THREAT_INTEL_LIVE=1, GEMINI_API_KEY, GEMINI_MODEL, VIRUSTOTAL_API_KEY, ABUSEIPDB_API_KEY, ALLOWED_ORIGINS` (include the Vercel origin). Don't set `PORT`. Current: `https://etap-backend-od1c.onrender.com`.
- **Frontend → Vercel**: root `frontend`, Vite preset, `npm ci`, `npm run build`, output `dist`, env `VITE_API_BASE_URL=https://etap-backend-od1c.onrender.com` (no trailing slash; redeploy after changes). Current: `https://e-tap-lac.vercel.app`.
- **Database → MongoDB Atlas**: least-privilege user, database `etap`, network access limited to Render egress where possible.
- **Extension**: load unpacked from `extension/` in Chrome/Brave (`chrome://extensions`, Developer mode); for local use, point `config.js` at `127.0.0.1:5000` / `:5173` and check host permissions.
- **Operations**: schedule `python purge_retention.py` (e.g. hourly); run one Uvicorn worker (rate limiter, VT limiter and caches are process-local); free Render instances cold-start and are memory-constrained (hence hash embeddings).

---

## 17. Known gaps, quirks and future work

- **Open API.** No authentication or multi-tenancy; anyone with the URL can analyse, read, share and delete (including `DELETE /investigations`). Per-IP limits see Render's proxy unless forwarded-for handling is added. The earlier bearer-key/role/owner-scoping implementation is still in the tree but **not wired**: `security.py` (`SecurityBoundary` middleware), `provision_key.py`, `db/scoped.py`, `migrate_workflow_c.py`, `frontend/src/components/common/AuthGate.jsx`, `extension/options.*`, the `/me` proxy entry and the `owner_id` index names. The original design is in git history (earlier notes cite a tag `pre-auth-removal`, which is not present in this clone). Future direction: OAuth/OIDC, `owner_id` scoping in one place, Atlas vector filter on `owner_id`, shared quota store.
- **`dnspython` not in requirements**, so the live-DNS auth tier is inactive in the Docker image unless added; header-reported results still work.
- **sentence-transformers not in requirements**; hosted RAG uses lexical hash embeddings, not semantic ones.
- **No dynamic sandbox.** `docs/workflow/etap-workflow.mmd` describes a Windows 11 VM + Sysmon detonation stage (Workstream A); none of it is in this repository. Attachment analysis is static only.
- **XGBoost model** lineage is undocumented; features are coarse (e.g. SPF pass is mostly unknown for text-only training data). Treat as a triage aid.
- **Evaluation** is not yet meaningful (see §15).
- **Gmail extension** relies on Gmail's private web endpoints (no Gmail API/OAuth) and can break when Gmail changes.
- **Caches and limiters are in-process** (lost on restart, wrong with multiple workers).
- **ip-api.com** is called over plain HTTP (free tier).
- **Tesseract path** is hard-coded for Windows when present; elsewhere the binary must be on `PATH`.
- **PII masking regexes** can over-match long digit runs and remove body email addresses before IOC extraction.
- **History page** uses browser session storage plus the server listing; it is not a full multi-user inventory.
- Deletion is not transactional and cannot recall data already sent to providers or backups.
- Planned / design-only: Tauri desktop shell with a local Python sidecar, fully local/private mode (no egress), OAuth original-message retrieval, live webhooks, professional translations and a WCAG audit.

---

## 18. Project history and naming

- **Stages A–H** come from the original team plan: A parse, B headers, B2 attachments, C content classifier (folded into G), C′ XGBoost triage, D IOCs, E threat intel, F correlation, F′ graph diffusion, G Gemini, H assembly/report.
- **Workflow B (B0–B11)** hardened truthfulness and evidence: B0 canonical verdicts and safe failure, B1/B9 evidence ledger and "observed / why / what to do", B2 evaluation harness and offline-fallback/charset fixes, B5 link analysis, B6 QR trace, B10 privacy controls, B11 provider status, timeouts, `/ready`.
- **Workflow C (C1–C14)** added trust and response features (see §10); authentication (C5) was built and then removed before the demo.
- **Workstream A** is the separate dynamic-sandbox effort, not in this repo.
- Older per-workflow notes (`WORKFLOW-B-README.md`, `WORKFLOW-C-README.md`, `SETUP.md`, `DEPLOYMENT.md`, `work.md`, `study.txt`, per-package READMEs) were consolidated into README.md and this file; they remain available in git history.

---

## 19. Glossary

- **IOC** — indicator of compromise: IP, domain, URL or file hash.
- **SPF / DKIM / DMARC** — email authentication: authorised sending IPs / signed messages / domain policy tying them to the From domain.
- **Received chain** — the `Received:` headers each mail server prepends; read bottom-up to trace the route.
- **Provider relay** — an outbound server of a big mail provider; its IP is not the sender's.
- **Homograph** — a domain using look-alike characters from another script (Cyrillic `а` vs Latin `a`).
- **Typosquat / lookalike** — a domain imitating a brand (`paypa1.com`, `hdfcbank-verify.com`).
- **Quick content check** — analysis of reconstructed visible text only; header evidence unavailable.
- **Evidence ledger** — the list of deterministic evidence items with stable IDs that the AI must cite.
- **Grounded / ungrounded** — whether an AI statement cites valid evidence IDs.
- **Campaign** — a group of analysed emails sharing infrastructure.
- **Graph diffusion / Personalized PageRank** — spreading "known malicious" signal from seed nodes through the threat graph.
- **Triage bypass** — skipping Gemini when XGBoost is ≥ 90% sure the email is benign and no guard fires.
- **Offline fallback** — deterministic scoring used when Gemini is unavailable.
- **Verdict band** — safe / caution / danger, derived only from `verdicts.py`.
- **MITRE ATT&CK** — public catalogue of adversary techniques (e.g. T1566.002 Spearphishing Link).
- **SOC Assistant** — the RAG chat over the open report or past investigations.
