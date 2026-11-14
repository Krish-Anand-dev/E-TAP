# 2026-10-25 — Hacktober HackDays: Cloudinary image evidence and our own deployment

**Type:** Decision and implementation

## Why
Hacktober HackDays (Unstop, SheBuilds Delhi, powered by MLH; theme Tech for Social Good) requires the project to use Cloudinary and to keep its build journey on Notion. The online round closed at 22:00 IST on 2026-10-25, a few hours after the work started. The original deployment belongs to a teammate's accounts, so the project was copied into `Hacktober HackDays\E-TAP`, pushed to the user's own repo and hosted again on the user's own accounts.

## Hosting on our own accounts
- **Atlas:** a free M0 cluster. The first deploy failed twice, in a way worth remembering: `ServerSelectionTimeoutError` meant Atlas's IP list only held the user's own address (fix: add `0.0.0.0/0`, because Render's free tier has no fixed address), and after that `OperationFailure` meant a wrong database password in `MONGODB_URI` (fix: reset the password and use a plain one). The change of error is how to tell a network problem from a login problem.
- **Render:** Docker web service, root directory `backend`, health check `/health`, free instance (512 MB, cold starts). `/ready` reports `database: ok`.
- **Vercel:** root directory `frontend`, Vite preset, `VITE_API_BASE_URL` set to the Render URL, and the Vercel origin added to `ALLOWED_ORIGINS` on Render.
- **Old URLs removed:** the Gmail extension (`config.js`, `manifest.json`, `analysis.html` and its test), `sandbox_agent/config.py`, `start-agent.cmd`, the README and CONTEXT.md.
- **Why "Deeper analysis does not work" after the move:** the agent still talked to the old server (a hard-coded default plus a saved URL and token in `%APPDATA%\E-TAP Sandbox Agent`). `start-agent.cmd` now passes `--server`, and `cmd_start` keeps the VM settings while dropping the old pairing. The agent zip the site serves is built on the fly from the deployed files (`sandbox_api.py`), so agent changes reach users only after a push and a Render redeploy.

## Cloudinary: what it is used for
The idea was to use it where E-TAP already handles images and where a user-facing benefit exists, not as decoration.
- **Evidence store.** Image attachments (a QR code, a screenshot of an invoice) are uploaded to Cloudinary, so the report can show them without keeping image bytes in MongoDB.
- **Safe viewing.** The report shows a blurred preview (a Cloudinary transformation of the stored asset); the reader clicks to reveal it. Phishing images can be unpleasant or misleading, and a QR code in an image is never opened automatically.
- **Second reading of the text.** The `adv_ocr` add-on can read the image's text in addition to local Tesseract. It is off by default.
- **Moderation.** `aws_rek` is also an opt-in flag.
- **Cleanup.** Deleting a report or letting it expire deletes the images; the privacy report lists Cloudinary as a data flow with the image count.

Design choices and why:
- Free plan only. The pricing page confirmed 25 monthly credits (about 1 GB of storage or bandwidth, or 1,000 transformations) and access to free add-ons. The add-on quotas could not be confirmed from the public pages, so add-ons are optional, and an add-on error retries the upload without them.
- Standard analysis must never wait on Cloudinary (the project's first rule). Uploads run in parallel, have an 8 s timeout, cap at 3 images of 8 MB each, and swallow every error.
- Random public ids rather than signed delivery URLs. Signed URLs would be better for sensitive mail, but could not be tested without a live account in the time available. The limit is written in CONTEXT.md.
- Only images are uploaded. Documents, scripts and archives never leave the server.

## What went wrong on the way (and was fixed)
- The first live report showed no Cloudinary anything. The upload had worked (the API record held a `cloudinary` object and the privacy report said `sent`), but the preview lived inside the collapsed *Technical details → Attachments* block at the bottom. It was moved into its own **Image evidence** section directly under Remediation, with its own tab.
- Observed but not changed: the same report scored the Attachments category 0 although the file was flagged suspicious (the hidden QR code was counted under message content by the AI reading). Worth a look in `reportSummary.js`.

## Verification
Backend suite 226 passed (11 new tests for the store with the network mocked: off by default, URL parsing, signature rule, upload, images only, failure handling, add-on retry, the 3-image cap, deletion, privacy flow). Frontend tests 18 passed and the build succeeds. Live: one real upload through the hosted site stored `rickroll qr.png` in Cloudinary and recorded it on the report.

## Addendum, 2026-10-30: shareable result card
A second use of Cloudinary, for the "relative forwards a suspicious message and asks if it is real" case. Every report gets a picture card with the verdict, score, one to three fixed reasons, a next step and the date.
- **How:** `backend/share_card.py` keeps four plain base images in Cloudinary (`etap/templates/card_danger|caution|safe|limited`, uploaded once, never overwritten). A card is a delivery URL that writes text layers onto the matching base image, so nothing is stored per email and there is nothing extra to delete.
- **Privacy:** no subject, sender, link, file name or quoted text. Reasons are fixed sentences chosen by evidence type (`att.`, `link.`, `qr.`, `rep.`, `corr.`, `ai.`, `hdr.`); text is limited to letters, digits, space, dot and hyphen.
- **Honesty rules:** a good result says "No problems found", never "Safe"; if headers, reputation lookups or the AI review could not run, it becomes a grey "Limited check" card. Missing checks never soften a caution or danger card.
- **Where:** `pipeline.py` returns `share_card`; `app.py` rebuilds it on each stored-report read so a sandbox-raised score shows; UI is the **Share card** section (`ShareCard.jsx`) with Download and Copy link.
- **Verification:** 12 new tests (`test_share_card.py`, network mocked); backend 238 passed, frontend 18 passed, build succeeds. Not yet seen against live Cloudinary at the time of writing.

## Addendum, 2026-10-31: pasting a message instead of uploading an email
A second way into the same analysis, for text that never was an email (an SMS, a WhatsApp message) with its attachments added separately.
- **Why:** the people E-TAP is for mostly receive scams as chat messages, and the share card is how the answer goes back to them.
- **How:** the Analyze page has a "paste a message" box. The browser packages the text (plain and link-ified HTML) and the files into an .eml with no sender, date or route lines and sends it with source `forwarded_message`.
- **What changes:** header and sender checks are skipped and marked not applicable, and nothing about them can add to the score (rule-based scoring and the AI prompt both ignore them). XGBoost triage, which reads header features, is not run. The report says so, and a good result becomes the grey "Limited check" share card rather than "No problems found".
- **What stays the same:** link text versus destination, QR decoding, OCR, hashes and VirusTotal, Cloudinary previews, the AI review and the sandbox.
- **Verification:** 8 new backend tests and 5 frontend tests; backend 246, frontend 26, extension 27 pass. A browser-built message for the demo text and `invoice.js` scored "Likely phishing" 75 offline with no header contribution. Checked in a local browser; the sandbox part was not re-run against a real VM today.
