# Development notes and iterations

How E-TAP got to where it is: the main iterations, the research behind the bigger decisions, and the decisions themselves. Newest entries are at the bottom of the timeline. The current technical reference is [`../CONTEXT.md`](../CONTEXT.md); this folder records *why* things are the way they are.

## Contents

| Date | Entry | Type |
|---|---|---|
| 2026-10-23 | [Hosted dynamic attachment analysis](2026-10-23%20Hosted%20dynamic%20attachment%20analysis/report.md) (with [research notes](2026-10-23%20Hosted%20dynamic%20attachment%20analysis/research%20notes/)) | Research |
| 2026-10-24 | [Sandbox agent direction](2026-10-24%20Sandbox%20agent%20direction.md) | Decision |

## Project timeline

### 1. Static forensic pipeline
The first version parsed `.eml`/`.msg` files and ran a fixed chain of checks: header forensics (SPF/DKIM/DMARC, Received chain, lookalike domains), static attachment forensics (file signatures, macros, QR codes, OCR), IOC extraction, live threat-intelligence lookups (VirusTotal, AbuseIPDB, WHOIS, IP geolocation), campaign correlation in MongoDB, graph diffusion, an XGBoost metadata pre-filter and a Gemini assessment with MITRE ATT&CK mapping. A React dashboard showed the report, and an early Gmail extension sent visible message text for a quick check.

### 2. Workflow B: truthfulness, evidence and privacy (B0–B11)
- One canonical verdict scale and score bands shared by every client (`verdicts.py`).
- An evidence ledger separating what was **observed**, what a **reputation service** said and what the **AI inferred**, with explicit "not checked" states, so a failed lookup is never shown as clean.
- Link text versus real destination (B5), QR-code destinations (B6), a privacy policy for what may be sent to external services (B10), and per-provider status and timeouts (B11).

### 3. Workflow C: trust and response (C1–C14)
Retention and deletion, a review workflow, recovery checklists, a redacted share pack, case marking, trusted-domain context, analytics, and scaffolds for webhooks and original-message retrieval. An API-key authentication layer was built and then removed to keep the demo zero-configuration; restoring proper sign-in is future work.

### 4. Sender origin and the Gmail extension
Received-chain hops are classified (provider relay, anonymiser, private, relay) so a Gmail or Outlook relay is not mistaken for the attacker, and each hop is geolocated for the sender map. The extension now downloads the original Gmail message (headers and attachments) when it can, and labels a text-only fallback honestly.

### 5. Local sandbox edition
A separate local build added dynamic attachment analysis: eligible attachments are opened inside an isolated, snapshot-restored VirtualBox Windows 11 VM, Sysmon records what they do, and behavioural rules (an EQL subset; 36 of 164 definitions evaluable) raise the score. Verified end to end on a script-in-ZIP sample that Windows Defender blocked. PDFs later gained a launcher; click-triggered documents remain out of reach without UI automation.

### 6. Documentation consolidation (2026-10-20)
Fourteen scattered notes were replaced by one `README.md` and one technical `CONTEXT.md` per edition.

### 7. Frontend revamp (2026-10-20)
- Dashboard with real numbers from all stored investigations.
- Analyze page with a live nine-stage timeline, backed by background analysis jobs (`/analyze/jobs`) that report each stage as it finishes, with a minimum on-screen time per stage so fast runs stay readable.
- Report rebuilt around "how risky, why, what to do": score ring, risk-category tags and cards, a Remediation section, the sender map moved up, a multi-vector radar, collapsible technical details, analyst tools last. Internal plumbing (provider status, privacy flows) was removed from the user view.
- Reports page broken down stage by stage; trusted domains turned into a real preference that lowers risk only for verified senders (SPF, DKIM and DMARC all pass, no spoofing signs).
- SOC assistant restyled, with readable answers when the AI is offline; New analysis and Re-analyze fixed and added.

### 8. One product, two folders (2026-10-20 to 2026-10-23)
The local sandbox build was merged with the hosted revamp so both had every feature; the sandbox became the only difference. A timeline mascot (an animated cat with a scene per stage) was added to the hosted edition.

### 9. Pluggable dynamic analysis (2026-10-23 onwards)
Research ([report](2026-10-23%20Hosted%20dynamic%20attachment%20analysis/report.md)) concluded that dynamic analysis should be a pluggable provider feeding one common event format and one Sigma/YARA rule engine, so there is a single codebase. The first provider to build is a user-owned sandbox reached through a paired agent ([decision](2026-10-24%20Sandbox%20agent%20direction.md)).

### 10. Deeper attachment analysis with a paired agent (2026-10-24)
The sandbox moved into the main codebase as stage S, with one VM-run implementation shared by a new **E-TAP Sandbox Agent** and the local worker. The flow:
- The Gmail extension asks for a standard or a deeper analysis.
- A first deeper analysis walks the user through downloading the agent and entering its one-time pairing code.
- After that, the extension shows *Your sandbox: online*.
- Hosted E-TAP queues the attachments, the agent runs them in the user's clean VM snapshot and uploads the Sysmon record, and the report's score and *Sandbox behaviour* section update by themselves.

Verified end to end, first with a simulated VM and then live on a real VirtualBox Windows 11 VM: a harmless script attachment matched rule etap-004 and raised the score from 73 to 85. Sigma/YARA rules are next.
