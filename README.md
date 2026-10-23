# E-TAP — Email Threat Analysis Platform

**One tap from a suspicious email to an evidence-backed verdict.**

E-TAP takes a raw email (`.eml` / `.msg`, or a message opened in Gmail through the browser extension) and runs it through a multi-stage forensic pipeline: header and authentication forensics, sender-origin tracing with IP geolocation, static attachment forensics (file signatures, macros, QR codes, OCR), IOC extraction, live threat-intelligence lookups, historical campaign correlation, graph-based risk propagation, an XGBoost pre-filter and a Gemini-backed final assessment with MITRE ATT&CK mapping.

The result is one report that says **how risky the email is, why, and what to do**, written so a non-expert can act on it, with the full technical detail kept for security analysts.

> E-TAP is a triage assistant, not an oracle. A missing or failed check is always reported as *unknown*, never as *safe*.

- **Live demo (frontend):** <https://e-tap-lac.vercel.app/>
- **Backend API:** <https://etap-backend-od1c.onrender.com> · [health](https://etap-backend-od1c.onrender.com/health) · [docs](https://etap-backend-od1c.onrender.com/docs)

For the deep technical reference (every module, library, environment variable, data shape and design decision), read **[CONTEXT.md](CONTEXT.md)**.

---

## How an email is analysed

```text
 .eml / .msg upload  ─┐
 Gmail extension     ─┼─►  A  Parse & normalise (MIME, headers, attachments, PII masking)
 CLI (run_pipeline)  ─┘         │
                                ├─► B   Header forensics: SPF / DKIM / DMARC, Received chain,
                                │        true-origin resolution, lookalike & homograph domains
                                ├─► B2  Attachment forensics: SHA-256, magic bytes, macros (oletools),
                                │        QR decoding (pyzbar/OpenCV), OCR (Tesseract)
                                ├─► B5  Link analysis: visible text vs real href destination
                                ├─► B6  QR trace: where each decoded QR code points
                                ▼
                           D  IOC extraction: IPs, domains, URLs, hashes
                                ▼
                           E  Threat intel: VirusTotal, AbuseIPDB, WHOIS, ip-api geolocation
                              + per-hop geolocation of the Received chain
                                ▼
                           F  Correlation: MongoDB history, campaigns, repeat-offender stats
                           F′ Graph diffusion: Personalized-PageRank risk propagation
                                ▼
                           C′ XGBoost metadata triage ──(clearly benign)──┐
                                ▼                                          │
                           G  Gemini assessment + MITRE ATT&CK (offline    │
                              fallback if Gemini is unavailable)           │
                                ▼                                          │
                           H  Verdict reconciliation, evidence report, ◄───┘
                              privacy report, provider status, persistence
                                ▼
                      React dashboard · PDF export · SOC Assistant (RAG chat)
```

### Stage A — Parsing and normalisation
Every input becomes the same `ParsedEmail` object. The file type is decided from **magic bytes, not the extension**: executables, ZIPs, PDFs and archives renamed to `.eml` are rejected, `.msg` must carry the Outlook OLE signature. `.eml` is parsed with Python's `email` package (robust against bogus charsets), `.msg` with `extract-msg`, and bulk `.csv` datasets are converted row by row into RFC 822 messages and fed through the same parser. Before anything is stored, SSNs, card numbers, Indian/US phone numbers, Aadhaar, PAN and body email addresses are masked.

### Stage B — Header forensics
- **SPF / DKIM / DMARC** in two tiers: first the verdict the receiving mail server stamped in `Authentication-Results` / `Received-SPF`; if absent, a live DNS check (SPF record evaluation against the connecting IP with `ip4/ip6/a/include/all`, DKIM public-key presence and alignment, DMARC policy fetch). DKIM signatures are never claimed as cryptographically verified.
- **Received chain** parsed into structured hops (oldest first): connecting IP from the `from` clause only, rDNS/HELO host, protocol, timestamp, inter-hop delay and out-of-order detection. Each hop is classified as private, relay, provider relay (Google, Microsoft, SES, SendGrid, …) or anonymizer.
- **True-origin resolution:** honest about what can be known. Client-IP headers (`X-Originating-IP`, …) are used when present; if the first public hop is a Gmail/Outlook relay, the report says *the provider hides the sender's IP* instead of pinning a Google data centre as the attacker.
- **Sender identity:** Reply-To domain mismatch, punycode and mixed-script (Cyrillic/Greek) homographs, typosquats and brand-plus-lure domains (`paypal-secure-login.com`) against an India-weighted brand list, and display-name impersonation ("PayPal Support" from an unrelated domain).

### Stage B2 — Attachment forensics (static, nothing is executed)
For each attachment: SHA-256, true type from magic bytes (libmagic when installed, built-in signature table otherwise), declared-vs-actual type mismatch, double extensions (`invoice.pdf.exe`), executables disguised under harmless names, and password-protected/corrupt Office files. Office documents get **static VBA analysis with oletools**: auto-run triggers (`AutoOpen`), suspicious APIs (`Shell`, `CreateObject`, PowerShell) and referenced IOCs. Images are decoded for **QR codes** (pyzbar, OpenCV fallback) and **OCR text** (Tesseract); OCR text is appended to the content the AI reviews, so image-only phishing is not invisible.

### Stage S — Deeper attachment analysis (optional, in your own sandbox)
When you choose **Deeper attachment analysis**, eligible attachments (scripts, executables, shortcuts, documents, PDFs, ZIP members; up to 3 per email) are opened inside a VirtualBox Windows VM **you own**. The free **E-TAP Sandbox Agent** runs next to the VM and pairs once with a short code. For each job it:
1. restores the VM's clean snapshot;
2. opens the files;
3. records what happens with Sysmon and Windows Defender;
4. restores the snapshot again;
5. uploads only the recorded events.

E-TAP checks them against behavioural detection rules (MITRE-mapped). A match raises the risk score, and "nothing observed" never lowers it. The agent only makes outbound requests. See [`backend/sandbox_agent/README.md`](backend/sandbox_agent/README.md).

### Stages B5 / B6 — Link and QR analysis
Every `<a href>` is compared with the text a reader sees: "text shows a different site", "text names PayPal but the link goes elsewhere", credentials in URLs (`paypal.com@evil.com`), IP hosts, non-standard ports, shorteners, punycode, lookalikes and redirect parameters (`?url=https://other.site`, reported as *inferred*). QR destinations get the same checks. Links are never fetched or followed.

### Stage D — IOC extraction
Offline, regex-plus-parser extraction of public IPs, domains, URLs (including defanged `hxxp://evil[.]com`) and MD5/SHA-1/SHA-256 hashes from headers, text, HTML attributes, attachment hashes and QR codes. Heavy noise reduction: domains must end in a real IANA TLD, Message-ID local parts and auth-header tags are ignored, private/loopback IPs are dropped, URLs are masked before hash scanning, CSS/script blocks and XML namespace boilerplate are stripped.

### Stage E — Threat intelligence and sender geolocation
With `THREAT_INTEL_LIVE=1`:

| Indicator | Provider | What we get |
|---|---|---|
| Public IPs | **AbuseIPDB** | abuse confidence score, report count, ISP, Tor flag |
| Domains | **WHOIS** (`python-whois`) | registration age, registrar, country |
| URLs, file hashes | **VirusTotal v3** | engines flagging the indicator |
| IPs + every Received hop | **ip-api.com** batch | lat/lon, country, ISP/org, hosting & proxy flags |

Each provider has a per-analysis budget (default 2 lookups), short timeouts, an in-memory TTL cache, and VirusTotal has an internal 4-requests/minute limiter. **Privacy first:** URLs carrying an email address, token, session ID or other secret are trimmed to `scheme://host/path` or not sent at all; private IPs never leave the server. Hop geolocation then re-judges the origin using the network owner (e.g. a proxy exit becomes an *anonymizer*), and the dashboard draws the route on a map.

### Stage F / F′ — Correlation and graph diffusion
The email's IOCs are matched against every stored analysis (exact for IPs/URLs/hashes, exact + fuzzy for domains). Matches join or create a **campaign**; campaigns that turn out to share infrastructure are merged. Historical stats report how often each indicator was seen this week, this month and all-time, and label the email a *new threat cluster* or *recurring adversary activity*. A threat graph (email, campaign, related emails, IOCs, shared infrastructure) is then scored with **Personalized PageRank label propagation**: reputation-confirmed malicious indicators are seeds, and risk diffuses up to 3 hops to the current email.

### Stage C′ — XGBoost metadata triage
Six metadata features (attachment present, URL count, sender-domain age, SPF pass, subject length, urgency keywords) go into a bundled XGBoost model. If it is ≥ 90% confident the email is benign, Gemini is skipped to save latency and quota. Safety guards force the full AI review whenever URLs, risky keywords, suspicious attachments or a visible-text-only (quick check) input are present.

### Stage G — Gemini assessment and MITRE ATT&CK
A **privacy-reduced copy** of all evidence (URLs redacted, PII masked) goes to Gemini in a single structured-JSON call that returns both a content-only classification against a fixed 30-category threat taxonomy and a full-evidence final verdict with MITRE ATT&CK techniques and recommended actions. The model is told that email content is untrusted data, and every AI finding must cite evidence IDs from the deterministic evidence ledger; uncited claims are kept but marked *ungrounded*. A chain of fallback Gemini models is tried within a time budget; if all fail, a deterministic offline scorer produces the result and the report says so.

### Stage H — Verdict, evidence report and persistence
One function reconciles the label and the 0–100 score (the more severe wins) into five canonical verdicts — `LIKELY LEGITIMATE` (0–19), `LOW RISK` (20–39), `SUSPICIOUS` (40–64), `LIKELY PHISHING` (65–84), `HIGH-RISK PHISHING` (85–100) — and three UI bands (safe / caution / danger). The evidence report separates **observed** facts, **reputation** results and **AI-inferred** statements, lists what could not be checked, and produces a headline plus concrete remediation steps. A privacy record of what left the server and a per-provider coverage status are stored with each report for analysts and the API. Everything is saved to MongoDB, and a summary + 384-dim embedding is indexed in the background for the SOC Assistant.

---

## What you get in the dashboard

- **Dashboard** — emails analysed, high risk / suspicious / low risk counts, average risk, risk-over-time chart, verdict breakdown, top threat types and recent investigations, from everything stored
- **Analyze email** — a live timeline that lights up each stage as it runs (reading the email, sender & headers, static attachments, dynamic attachments, links & indicators, reputation, past emails, AI assessment, verdict), then the score, the verdict and **Re-analyze**; before running it asks for a **Standard** or a **Deeper attachment analysis**, and pairs your sandbox right there the first time
- **Investigation report** — a big score ring and verdict, "why it was risky" tags (Header issues, Attachment issues, Suspicious links, Bad reputation, Seen before, Suspicious wording), category cards with the serious findings first, **Remediation**, the sender-route map, multi-vector analysis and MITRE ATT&CK, collapsible technical details, past emails and the threat graph, and analyst tools (review, case, sharing, retention) at the end
- **Reports** — every analysed email broken down stage by stage, searchable and filterable by risk
- **Sandbox behaviour** — for deeper analyses, what each attachment did in your VM (rules matched, Defender blocks, processes), updating live while it runs
- **Trusted domains** — senders you trust lower the risk only when SPF, DKIM and DMARC prove the email is genuine; the same page pairs your sandbox
- **Ask E-TAP** — the SOC Assistant for the open report or all past investigations, plus **PDF/JSON export**

## Gmail extension

A Manifest V3 extension adds **Analyze in E-TAP** above an opened Gmail message. On click it asks for a **Standard analysis** or a **Deeper attachment analysis** (an info icon explains that the deeper option needs a VirtualBox VM; Windows Sandbox on Windows Pro is planned). The first deeper analysis walks you through downloading the agent and entering its pairing code, after which the extension shows *Your sandbox: online*. It then downloads the original RFC 822 message through the signed-in Gmail session (full headers and attachments) and submits it as `full_message`. If Gmail does not provide the original, it submits the visible sender/subject/body as a clearly labelled `quick_content_check`, where header checks are reported as unavailable. The report then opens in the web dashboard.

---

## Tech stack

| Layer | Technologies |
|---|---|
| Backend | Python 3.11, FastAPI, Uvicorn, slowapi, Pydantic |
| Parsing / forensics | `email` stdlib, extract-msg, dnspython (optional, for live SPF/DKIM/DMARC DNS checks), oletools, python-magic (optional), OpenCV, pyzbar, Pillow, pytesseract |
| Threat intel | VirusTotal v3, AbuseIPDB v2, python-whois, ip-api.com |
| ML / AI | XGBoost, scikit-learn, NumPy, SciPy, Google Gemini (`google-genai`), sentence-transformers (optional) |
| Database | MongoDB / MongoDB Atlas (pymongo), in-memory fake DB for tests |
| Frontend | React 18, Vite, axios, Leaflet / react-leaflet, react-force-graph-2d, Recharts, jsPDF |
| Extension | Chrome Manifest V3, IndexedDB handoff store |
| Hosting | Render (Docker backend), Vercel (frontend), MongoDB Atlas |

## Quick start (local)

Prerequisites: Python 3.11, Node.js ≥ 22.12, optionally MongoDB. Tesseract and libzbar are needed only for OCR/QR (the Docker image installs both).

```bash
cp .env.example .env          # set USE_FAKE_DB=1 for a zero-setup run
python -m venv .venv && source .venv/bin/activate      # Windows: .\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
cd backend && python -m uvicorn app:app --host 127.0.0.1 --port 5000
```

In a second terminal:

```bash
cd frontend && npm ci && npm run dev
```

Open <http://127.0.0.1:5173>. Vite proxies API calls to port 5000. Add `GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY`, `ABUSEIPDB_API_KEY` and set `THREAT_INTEL_LIVE=1` in `.env` to enable the live stages; without them E-TAP runs fully offline with deterministic fallbacks.

Analyse a file from the command line:

```bash
cd backend && python run_pipeline.py path/to/email.eml
```

Run the tests:

```bash
pip install -r backend/requirements-dev.txt
cd backend && python -m pytest tests -q --ignore=tests/test_threat_intel_live.py
cd ../frontend && npm test
```

Deployment (Render + Vercel + Atlas), every environment variable and the full API route list are documented in [CONTEXT.md](CONTEXT.md).

## Repository layout

```text
backend/     FastAPI app, pipeline and all analysis stages
frontend/    React/Vite dashboard
extension/   Gmail browser extension (Manifest V3)
docs/        Workflow diagram, parser fixtures, small evaluation corpus
samples/     Dataset manifests (raw emails are not committed)
```

## Limitations

- The API is open (no sign-in or per-user isolation); do not upload sensitive real mail to a public instance.
- Live lookups and Gemini receive indicators and privacy-reduced email content.
- The bundled XGBoost model is an initial triage aid, not a calibrated production detector, and no benchmark accuracy is claimed yet.
- Dynamic analysis needs your own VirtualBox VM and the agent; nothing clicks inside documents yet, so Office files and click-triggered PDFs are often inconclusive, and only 36 of the 164 bundled behaviour rules can be evaluated so far.
- The Gmail extension uses Gmail's web endpoints, not the official Gmail API.

## Team

- Bhavit Anand
- Krish Anand
- Yashmit Kamal
