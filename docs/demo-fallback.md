# Demo plan: the one-way WhatsApp bot

Status (2026-11-15): the WhatsApp bot is live in **one-way** mode. It receives what you forward (text,
links, photos, PDFs and other files up to 25 MB), runs the same analysis as the website, and saves the
report under your account. It cannot send replies, because Meta only lets a **verified business** send
messages and we are a student team: the account is locked for replies (error 131031 "Business Account
locked"). Do not claim the bot replies. Say what is true:

> "WhatsApp is the convenient way in: forward anything suspicious to our bot and the full report
> appears in your account on the website. Replies on WhatsApp come after Meta verifies our business."

## Before the demo (10 minutes)

- Open `https://etap-clean-backend.onrender.com/health` so Render is awake (UptimeRobot keeps it so).
- Sign in on the site (Settings, Your account, emailed code) and link your number (Settings, WhatsApp,
  send the `ETAP-xxxxxx` code to the bot). Only numbers added in Meta (API Setup, the "To" list) can
  message the test number, and only the linked number's forwards land in **My reports**.
- Set `WHATSAPP_REPLIES=0` on Render (it is set). Keep WhatsApp Web open on the bot chat.
- Pre-run the sample message on the website so a finished report is ready if anything is slow.
- Send images as **photos**. WhatsApp Web sends a bare PNG as a sticker, which the bot ignores.

## What to show (about 3 minutes)

1. **Forward from WhatsApp.** From the linked phone send the bot a scam message
   (`samples/forwarded-message-demo/suspicious-message.txt`) or a screenshot or PDF. It takes 10 to 30 seconds.
2. **Open My reports on the website.** Show the verdict, the reasons, the links and the attachment checks.
   For a screenshot, show the text read off the image (OCR). For a harmless message, show it is not flagged.
3. **Same pipeline in the browser.** Analyze page, "Or paste a message you were sent", Standard analysis,
   to show the live timeline.
4. **Be upfront about the limit.** The bot is one-way until Meta verification clears (needs legal business
   documents and a payment method; nothing in our code changes).
5. **Privacy page and sign-in.** `https://e-tap-clean.vercel.app/privacy.html`; the phone number is
   stored only as a keyed hash.

## If something goes wrong

- **No report after forwarding:** check the number is linked (Settings, WhatsApp), the message is not a
  sticker/voice note/video (those are ignored), and Render is awake. Render logs show
  `POST /whatsapp/meta 200` for every message that arrived.
- **Files or photos never produce a report but text does:** `META_ACCESS_TOKEN` on Render is invalid. The
  log says "WhatsApp media lookup refused (status ...)". Generate a new system-user token (see
  `docs/whatsapp-bot.md`).
- **A report shows "AI unavailable; offline assessment used":** Gemini was down. Re-send the message.
- **Fall back to the website:** the paste mode runs the identical pipeline.

## If someone asks

- Why not Twilio? Its trial cannot set the incoming webhook; it needs a paid upgrade.
- What makes replies possible? Meta business verification and a payment method; then set
  `WHATSAPP_REPLIES=1`. The reply code and tests already exist.
- Can anyone use it? The Meta test number only talks to the numbers added as recipients (up to 5).
  A public bot needs a verified WhatsApp Business number.
