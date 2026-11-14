# E-TAP: the build journey

**One tap from a suspicious email to an evidence-backed verdict.** E-TAP reads a suspicious email the way a security analyst would, opens its attachments in a safe virtual machine when you ask it to, and then explains the result in plain words to someone who is not an analyst.

Hacktober HackDays 2026 · Tech for Social Good · Open source (MIT) · Built with Cloudinary

## Links

| What | Where |
|---|---|
| Live app | https://e-tap-azure.vercel.app |
| Backend API (health, docs) | https://etap-backend-2std.onrender.com/health and https://etap-backend-2std.onrender.com/docs |
| Source code (MIT licensed) | https://github.com/Krish-Anand-dev/E-TAP |
| Technical reference | CONTEXT.md in the repository |
| Full development notes | the "Development notes and iterations" folder in the repository |

## Team

| Name | Role |
|---|---|
| Krish Anand | Creator and lead engineer. Conceived E-TAP. Backend, forensics and the detection rules, the sandbox and its agent, the redesigned frontend, deployment and the Cloudinary integration. Also the demo video and pitch material. |
| Bhavit Anand | Backend and infrastructure engineer. Wrote the original static forensic stages, set up the API keys and first hosting, maintains the backend, and co-developed and maintains the SOC assistant (RAG). |
| Yashmit Kamal | Product strategy and communications. The business model and cost-effectiveness plan, product ideation, the pitch deck, this Notion documentation, and the applications and submissions. |

### Origins and credits

E-TAP began as a larger team project. Two parts of today's product come from that earlier work, and we want to credit them:
- The **XGBoost metadata triage model** was trained by a former member of the original team on a large corpus of phishing emails. We integrated it into the pipeline, set its safety rules (it can never skip the AI review when links, risky keywords or suspicious attachments are present) and maintain it.
- The **first version of the RAG assistant** was also written by that member. We rebuilt it into the current SOC assistant, with privacy sanitising of what it sees.
- That member also built the **original frontend**. It has since been completely replaced by the redesigned frontend and is no longer in use.

Everything else (the forensic stages, the detection rules, the sandbox and its agent, the deployment, the Cloudinary evidence store and the current frontend) was built by the three of us.

---

## 1. The problem

Phishing is the easiest way into a person's bank account, a small business's invoices or a family's photos, and the people it hurts most are the ones least able to judge an email for themselves: parents, shop owners, first-time email users, people reading in a second language. They get a message that looks like their bank, a delivery company or a government office, with a link, an attachment or a QR code, and a few seconds to decide.

The tools that could help were built for security teams. They answer in headers, hashes and jargon. A normal person needs one answer: is this safe, why, and what do I do now?

Three things make modern phishing hard to spot by eye:
- **The sender is faked.** The name on screen says "PayPal Support"; the real address does not. Authentication results (SPF, DKIM, DMARC) tell the truth, but nobody reads them.
- **The link lies.** The text says one website; the link goes to another.
- **The danger hides in the attachment.** A QR code inside a picture, a screenshot of an "invoice", or a script disguised as a document gets past filters that only read text, and a static scan cannot say what a file will actually do once opened.

## 2. Who it helps

- A family member who forwards "is this real?" messages to the one relative who understands computers.
- A small business that pays invoices by email and has no security team.
- A first-time email user, or someone reading in a language that is not their first.
- A volunteer or school IT helper who needs evidence they can show, not just a feeling.

## 3. How E-TAP works

You give E-TAP an email (upload a file, or click a button above a message in Gmail). It runs a chain of checks, shows each one lighting up on a live timeline, and ends with one report. There are two ways to run it, and both are visible up front:

| | Standard analysis | Deeper attachment analysis |
|---|---|---|
| What it does | Reads the email and its attachments without opening anything | Everything in Standard, plus opens the attachments inside a virtual machine and records what they do |
| What you need | Nothing | A Windows VM in VirtualBox that you own, and the free E-TAP Sandbox Agent |
| Speed | Seconds | A couple of minutes |
| Who it is for | Everyone, and it is the default | People who have a VM and want the strongest check |

### The analysis pipeline

| Stage | What it looks at |
|---|---|
| Read the email | The file type is decided from its real bytes, not its name. Personal data (phone numbers, card numbers, Aadhaar, PAN) is masked before anything is stored. |
| Sender and headers | SPF, DKIM and DMARC results, the route the message took through mail servers, the real origin, lookalike domains, a display name pretending to be a brand. |
| Attachments, static | File hash, real type versus claimed type, double extensions like `invoice.pdf.exe`, macros in Office files, QR codes in images, text in images (OCR). Nothing is opened. |
| Image evidence (Cloudinary) | Image attachments are saved to Cloudinary and shown in the report as blurred previews. See below. |
| Deeper attachment analysis (optional) | The sandbox: attachments are opened in the user's own VM and the behaviour is recorded. See below. |
| Links and QR codes | The text a person sees versus where the link really goes. Links are never followed. |
| Indicators | Every IP, domain, URL and file hash found in the message. |
| Reputation | VirusTotal, AbuseIPDB, WHOIS and IP location, under privacy rules about what may leave the server. |
| Past emails | Whether the same infrastructure appeared before, grouped into campaigns in MongoDB, with risk spreading through a graph (Personalized PageRank). |
| AI assessment | A fast XGBoost pre-filter, then a Gemini review mapped to MITRE ATT&CK, with an offline fallback if the AI is unavailable. |
| Verdict | One function reconciles the label and the score; the more severe wins. |

### Deeper attachment analysis: seeing what a file actually does

A static scan can tell you a file looks wrong. It cannot tell you what the file does. So E-TAP can open the attachment, but never on our server and never on the user's everyday computer.

**How it works**
1. The user picks **Deeper attachment analysis** and, the first time, downloads the **E-TAP Sandbox Agent** and enters a one-time pairing code.
2. The hosted E-TAP server queues the email's attachments for that user's agent. Only attachments are sent, never the whole email, and only for an analysis the user chose.
3. The agent, running on the user's PC, **restores the VM's clean snapshot**, opens the file inside the VM, and records what happens with **Sysmon** and **Windows Defender** events.
4. The agent keeps only the events that belong to the file's own processes (kilobytes, not the whole log), uploads them, and restores the clean snapshot again.
5. The server checks the events against **behaviour detection rules mapped to MITRE ATT&CK**. A match raises the risk score; a quiet run never lowers it, because seeing nothing in a short run is not proof of safety.
6. The open report updates by itself and shows a **Sandbox behaviour** section: how many files were opened, which rules matched, what Windows Defender blocked and which processes ran.

**Why this design**
- Nothing is executed on the hosted service.
- The agent only makes outbound requests, so no port on the user's PC is opened to the internet.
- Each agent has its own pairing token, jobs expire, and attachment bytes are deleted as soon as a job ends.
- The agent tells the truth about its state: "online" means it is really connected, "ready" means the VM and clean snapshot were checked, and a wrong VM password is refused instead of being saved.

**What it found.** A harmless script attachment, run end to end on a real VirtualBox Windows 11 VM, matched rule `etap-004` (MITRE T1059.005 and T1059.007), Windows Defender's block was recorded, 13 process events were observed, and the score rose from 73 to 85. The whole run took about two minutes.

### Image evidence with Cloudinary

Phishing hides in images, and an image needs somewhere to live and a safe way to be shown. Cloudinary does both in E-TAP.

1. **Evidence store.** Each image attachment (a QR code, a screenshot of an invoice, a scanned letter) is uploaded to Cloudinary as soon as it is found. At most 3 images per email, images only: documents, scripts and archives never leave the server. The image bytes do not sit in the database.
2. **Safe viewing.** Cloudinary generates a **blurred preview**, a transformation of the stored image. The report shows it blurred and reveals it only when the reader clicks, because a phishing image can be misleading or unpleasant, and a QR code is never opened automatically.
3. **Image evidence section.** The report has its own "Image evidence" section with the preview, the hidden QR link that was decoded, any text read from the image, and a link to the full image.
4. **A second reading of the text (optional).** The Cloudinary OCR add-on can read the image's text in addition to E-TAP's local OCR, switched on with one setting once the add-on is installed.
5. **Image moderation (optional).** The Rekognition moderation add-on can flag unsafe images, also one setting.
6. **Clean-up.** Deleting a report, or letting it expire, deletes its images from Cloudinary.

**Rules we gave ourselves**
- Standard analysis never waits on Cloudinary: uploads run in parallel with an 8-second limit, and any failure is ignored, so the email is still fully analysed.
- With no Cloudinary credentials the step is simply off and nothing is uploaded.
- Images get a random, unguessable name.
- It runs on the Cloudinary free plan.

**Honest limits.** Images are reachable by their link until the report is deleted; the links cannot be guessed but they are not signed. The two add-ons are optional because their free quotas vary by account. Pictures embedded inside the email body (as opposed to attachments) are not uploaded yet.

**Proof.** A test email with a QR-code image attachment went through the live site: the image appeared in the Cloudinary media library under the `etap` folder, and the report's Image evidence section showed it blurred with the decoded link, while the report's privacy record recorded one image sent.

## 4. What the user gets

- **How risky it is:** a score out of 100 and one of five plain labels, from "Likely legitimate" to "High-risk phishing".
- **Why:** tags such as "Header issues", "Suspicious links" and "Bad reputation", with the serious findings first.
- **What to do:** specific steps for this email, for example "Do not act on the request yet; confirm it through a separate, trusted channel".
- **Image evidence:** blurred previews of image attachments, revealed on click.
- **Sandbox behaviour:** for a deeper analysis, what each attachment did in the VM, updating live while it runs.
- **The evidence:** every statement points at a numbered piece of evidence, split into what was **observed**, what a **reputation service said** and what the **AI inferred**. A check that could not run is shown as "not checked", never as "safe".
- **Everything else for analysts:** sender route on a map, MITRE ATT&CK techniques, past related emails and a threat graph, a review workflow, a redacted share pack, PDF and JSON export, and a SOC assistant you can ask questions about any report.

## 5. The journey

### The static pipeline
The first version parsed `.eml` and `.msg` files and ran a fixed chain of checks: headers, attachments, indicators, live reputation lookups, correlation against past emails, an XGBoost filter and a Gemini assessment. A React dashboard showed the report, and an early Gmail extension sent the visible text of a message for a quick check.

### Truthfulness and evidence
We realised a security tool that sounds confident when it does not know is worse than none. So we added:
- one canonical verdict scale shared by every part of the product;
- the evidence ledger (observed versus reputation versus AI-inferred) with explicit "not checked" states;
- link text versus real destination, and QR destination analysis;
- a privacy policy for what may be sent to outside services (URLs that carry tokens or email addresses are trimmed or never sent);
- per-provider timeouts and status.

### Trust and response
Retention and deletion, a review workflow, recovery checklists, a redacted share pack that contains no body text, addresses or links, trusted-domain context, and analytics. We built an API-key sign-in layer and then removed it to keep the demo zero-configuration; restoring sign-in is on the roadmap.

### Sender origin and the Gmail extension
A message sent through Gmail does not reveal the sender's IP address, and blaming a Google data centre for the attack would be wrong. E-TAP classifies each hop (provider relay, anonymiser, private, relay) and says "the provider hides the sender's address" when that is the truth. The extension downloads the original Gmail message when it can, and clearly labels a text-only fallback.

### A dashboard built for non-experts
- A dashboard with real numbers from all stored reports.
- An Analyze page with a live timeline backed by background analysis jobs, and an animated cat mascot for each stage.
- The report rebuilt around "how risky, why, what to do".
- A Reports page broken down stage by stage, and trusted domains that lower risk only when SPF, DKIM and DMARC all pass.

### Research: should a hosted tool open attachments at all?
Opening attachments is the most valuable check and the most dangerous. We compared public cloud sandboxes (their free tiers make uploads public, which is unacceptable for private mail) and settled on a design with one record format, one rule engine and pluggable providers.

### The user's own sandbox
Deeper analysis became optional and runs on a virtual machine the user owns, through the paired E-TAP Sandbox Agent described above. The first live run raised a harmless script from 73 to 85.

### Standard analysis first
The principle: **nothing we add may get in a normal person's way.** Standard analysis is one click and never touches the sandbox, and the Deeper option is visible up front with what it needs written on the card. We debated hiding it and decided against, because adding Deeper after a Standard run means re-running the whole analysis, including the rate-limited reputation lookups.

### Making the sandbox work for a real person
About a dozen rounds of testing it the way a normal user would turned a sandbox that worked on one machine into one that works through the hosted site. Each round started with something that went wrong:
- the Defender check timed out silently (the first query after the VM resumes takes about 18 seconds);
- the deeper option did not appear on the real site;
- "No module named sandbox_agent": someone double-clicked the launcher inside the zip;
- a wrong VM password was accepted, and the page said "online" when the VM was gone;
- a deeper run did nothing visible because the only attachment was a data file the sandbox deliberately does not run;
- a PDF result never reached the report because the agent tried to upload tens of megabytes of log that overflowed a small server.

Each fix made a status tell the truth, and every path now ends the job with a reason.

### Cloudinary image evidence
Image attachments are where phishing hides and where the report had the weakest way to show evidence. We added the Cloudinary store, the blurred previews, the optional OCR and moderation add-ons and clean-up on delete, then moved the previews into their own visible "Image evidence" section after seeing that a collapsed technical panel hid them.

### Our own deployment
The project runs on MongoDB Atlas, a Render backend and a Vercel frontend. Two database errors taught us to read the clue rather than the symptom: a `ServerSelectionTimeoutError` meant the database was not reachable from the server (its network allow-list held only one home address), and the next error, `OperationFailure`, meant it was reachable but the password in the connection string was wrong. The sandbox agent and the Gmail extension both point at the deployed backend.

## 6. Decisions and why

| Decision | Why |
|---|---|
| Report in plain words first, forensic detail second | The people we want to protect cannot read headers. Analysts can still open everything. |
| "Not checked" is never "safe" | A silent failure that looks clean is how people get hurt. |
| Standard analysis is the default, always | Most people have no virtual machine; nothing may block them. |
| Dynamic analysis runs on the user's own VM | Nothing is executed on our server, and private mail is not sent to public sandboxes. |
| The score can only go up after a sandbox run | "We saw nothing" in a short run is not proof of safety. |
| Images, and only images, go to Cloudinary, with a blurred preview | Image phishing is where text filters fail, and a person should choose to look. |
| Links are never followed | Opening a phishing link to check it is exactly what the attacker wants. |
| Remove the sign-in layer for the demo | Zero setup for users and judges; restoring accounts is on the roadmap. |

## 7. What we learned

- **Every real failure came from using the product the way a normal person does**, not from unit tests. Tests passed throughout because they used a fake database and a fake VM.
- **Status that sounds reassuring has to be earned.** "Online", "set up" and "0 blocked" each claimed more than had been checked.
- **Say what will and will not happen before it happens**, not afterwards.
- **A job must always end**, with a reason, whatever goes wrong.
- **Read the error, not the symptom.** A timeout and a login failure look the same on a dashboard and have different fixes.

## 8. Built with

| Area | Tools (free or open source unless noted) |
|---|---|
| Backend | Python, FastAPI, Uvicorn, Pydantic |
| Frontend | React 18, Vite |
| Database | MongoDB Atlas (free tier) |
| Image storage and previews | Cloudinary (free plan) |
| Email and file analysis | Python `email`, extract-msg, oletools, pytesseract (Tesseract OCR), pyzbar and OpenCV (QR codes), Pillow |
| Machine learning | XGBoost, scikit-learn, Personalized PageRank graph diffusion |
| AI | Google Gemini (with an offline fallback) |
| Threat intelligence | VirusTotal, AbuseIPDB, WHOIS, ip-api |
| Sandbox | VirtualBox, Sysmon, Windows Defender events, behaviour rules mapped to MITRE ATT&CK |
| Hosting | Render (backend), Vercel (frontend) |
| Browser | A Manifest V3 Gmail extension |
| Licence | MIT |

## 9. Privacy and safety

- Personal data in the message is masked before storage; the body is not saved as its own field.
- Links and QR codes are never fetched or followed.
- URLs that carry tokens, session IDs or email addresses are trimmed or never sent to reputation services.
- The AI is told that email content is untrusted data, and the text it sees is sanitised first.
- Only images go to Cloudinary, and they are deleted with the report.
- The sandbox agent never accepts inbound connections, attachments are sent to it only for an analysis the user chose, and the VM returns to a clean snapshot after every run.
- Every report carries a privacy record, shown in the exported PDF and available from the API, listing where its data went.
- Harmless sample files only; nothing in this project is meant for unauthorised testing.

## 10. Honest limits

We would rather say these than have anyone find them.
- There is **no accuracy benchmark yet**. The only evaluation committed is a small offline debugging run on old spam data, and it is not a detection-rate claim.
- The sandbox rule engine can evaluate **36 of 164** rule definitions today; Sigma and YARA support is the next step.
- Documents that need a click to run (some Office files and PDFs) usually come back inconclusive, because nothing clicks inside them yet.
- The sandbox agent has been run end to end on one real machine. A first-time setup by someone else from the README alone is not yet tested.
- The API has no sign-in; anyone with the address could use it.
- The hosted free tier sleeps when idle, so the first request after a pause is slow.
- The Gmail extension depends on Gmail's private web endpoints and can break when Gmail changes.

## 11. What comes next

1. Sigma and YARA detection rules, and a rule-writing guide so others can contribute detections.
2. A real accuracy evaluation on an authorised phishing corpus.
3. A "run deeper analysis on this report" button, so choosing Deeper does not mean starting over.
4. Windows Sandbox as a second kind of user machine.
5. Sign-in and per-user reports.
6. Professional translations and an accessibility review, so the people we are building for can actually read it.
7. Signed Cloudinary delivery links, and uploading images embedded in the message body.

## 12. A three-minute demo

1. Open the live app and drop in a phishing sample. Watch the stages light up.
2. Read the headline verdict and the plain "what to do" steps. Open "Why it was flagged".
3. Scroll to **Image evidence**: the QR image is blurred; click to reveal it and see the hidden link it points to. Show the stored file in the Cloudinary library.
4. Choose **Deeper attachment analysis** on an email with a harmless script: the agent opens it in the virtual machine, the **Sandbox behaviour** section fills in live, and the score rises.
5. Click Export PDF and show the privacy page: Cloudinary is listed as a data flow with the number of images sent.
6. End on: "A missing check is always reported as unknown, never as safe."

## 13. Try it or contribute

- Use the live app above; standard analysis needs no sign-up.
- Run it yourself: copy `.env.example` to `.env`, set `USE_FAKE_DB=1` for a zero-setup start, `pip install -r backend/requirements.txt`, run the backend with Uvicorn, then `npm install` and `npm run dev` in the `frontend` folder. Cloudinary is optional: set `CLOUDINARY_URL` to switch image evidence on.
- Tests: 238 backend tests, 18 frontend tests and 27 extension tests pass.
- Contributions are welcome, especially detection rules and translations.

## 14. Screenshots to add to this page

- The live timeline during an analysis.
- A finished report: verdict, "Why it was flagged" and Remediation.
- The Image evidence section, blurred and revealed.
- The Cloudinary media library showing the `etap` folder.
- The Sandbox behaviour section after a deeper analysis, and the agent window.
- The exported PDF's privacy page listing Cloudinary.
- The Atlas, Render and Vercel dashboards.
