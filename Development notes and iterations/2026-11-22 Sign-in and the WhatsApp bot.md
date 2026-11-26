# 2026-11-15 to 2026-11-22: optional sign-in and the WhatsApp bot

Written on 2026-11-26 from the commit history, the code and `docs/whatsapp-bot.md`.

## Why
People get scams on WhatsApp, not only by email, and someone who forwards one wants the result where they can find it again.

## What was built
- **Optional sign-in** (2026-11-15): an emailed 6-digit code, no passwords. It only tags reports with an owner and enables **My reports**; analysing never needs it.
- **WhatsApp bot** (2026-11-15): first on the Twilio sandbox, then on Meta's WhatsApp Cloud API, because a Twilio trial cannot set the incoming webhook. A forwarded message is packaged like a pasted message and analysed statically; the reply is text with the verdict, reasons and report link.
- **25 MB files**: the .eml is built in small pieces and analyses over 8 MB take turns (`heavy_gate.py`) to fit a 512 MB server. A privacy page was added, which Meta requires.
- **One-way mode**: when replies were blocked, a signed-in person could still link their number by sending a one-time code to the bot, and read results under **My reports**. Numbers are stored only as keyed hashes.
- **Reliability**: one retry on a busy Gemini model, a dead model name removed, offline rules for fee-before-deadline scams, and clearer logs when media downloads fail.
- **Reply diagnostics** (2026-11-22, PR #1 by Yashmit Kamal): Meta errors and failed deliveries are logged by numeric code only.
- The GitHub keep-alive workflow was replaced by an UptimeRobot monitor.

## Where it stands
- 2026-11-15: every reply on the original account failed with 131031 "Business Account locked"; receiving worked.
- 2026-11-15: PDFs and a screenshot sent to the bot produced reports.
- 2026-11-22: a live greeting reply was verified on a replacement Meta test number with a temporary token. Replies from the production sender are not re-confirmed.
- The result card made with Cloudinary is shown on the website; the bot does not send it as an image.
