# Demo plan: WhatsApp bot blocked by Meta

Status (2026-11-15): the bot receives WhatsApp messages and runs the real pipeline, but Meta rejects
every reply with error 131031 "Business Account locked" (the WhatsApp business account is not a
verified business). Do not claim the replies work live. Say exactly what is true:

> "The bot is built and tested: it receives forwarded messages and files up to 25 MB, runs the same
> analysis as the website, and replies with the verdict and a report link. Meta only lets a verified
> business send replies, and we are a student team, so for the demo we show the same flow on the website."

## What to show (about 3 minutes)

1. **The website, paste mode (same pipeline as the bot).** Analyze page, "Or paste a message you were
   sent". Paste `samples/forwarded-message-demo/suspicious-message.txt`, optionally add `invoice.js`
   (harmless), choose Standard analysis. Show the live timeline, the verdict, the reasons, the report.
   Standard is fine; Deeper needs the paired agent and a VM.
2. **The bot receiving a message (proof it is wired).** Send "hi" or the suspicious text from WhatsApp
   to the test number, then show either:
   - Meta dashboard > WhatsApp > API Setup > "Check test webhooks" (the `messages` row with your text), or
   - Render logs: `POST /whatsapp/meta 200 OK`.
3. **The reply side, honestly.** Show the same webhook list: the status row says `failed`, 131031.
   Say it is a Meta verification limit, not a bug in our code.
4. **Tests as evidence.** `cd backend; python -m pytest tests/test_whatsapp_meta.py tests/test_whatsapp_large_files.py -q`
   (45 tests: signature check, media download, 25 MB limits, reply wording, link to the report).
5. **Privacy page and login.** `https://e-tap-clean.vercel.app/privacy.html`, Settings > sign in by emailed code.

## Before the demo (10 minutes)

- Open `https://etap-clean-backend.onrender.com/health` so Render is awake (UptimeRobot keeps it so).
- Pre-run the sample once so a finished report is ready if the live run is slow.
- Keep WhatsApp Web open on the bot chat and the Meta webhook panel open in another tab.
- Rotate the Meta token you shared earlier; the webhook panel does not need it.

## If someone asks

- Why not Twilio? Its trial cannot set the incoming webhook; it needs a paid upgrade.
- What would make replies work? Complete Meta business verification (legal entity documents) and add a
  payment method; nothing in our code changes.
- Is the code ready? Yes. Set a verified number's token in `META_ACCESS_TOKEN` and it replies.
