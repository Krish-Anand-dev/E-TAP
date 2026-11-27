# Demo plan: WhatsApp bot (receive-only fallback)

Use this fallback if the configured sender cannot reply or the demo needs to run without WhatsApp
replies. With replies disabled, the bot can still receive forwarded messages and save reports for
linked accounts. On 2026-11-22, a live greeting reply was verified on the replacement Meta test
number using a temporary token. See [the setup guide](whatsapp-bot.md) for two-way testing.

> "WhatsApp is the convenient way in: forward anything suspicious to our bot and the full report
> appears in your account on the website."

## Before the demo (10 minutes)

- Open `https://etap-v8-backend.onrender.com/health` to check Render is awake (an UptimeRobot monitor on the service root keeps it so).
- Sign in on the site (Settings, Your account, emailed code) and link your number (Settings, WhatsApp,
  send the `ETAP-xxxxxx` code to the bot). Only numbers added in Meta (API Setup, the "To" list) can
  message the test number, and only the linked number's forwards land in **My reports**.
- For a receive-only demo, set `WHATSAPP_REPLIES=0` on Render. Keep WhatsApp Web open on the bot chat.
- Pre-run the sample message on the website so a finished report is ready if anything is slow.
- Send images as **photos**. WhatsApp Web sends a bare PNG as a sticker, which the bot ignores.

## What to show (about 3 minutes)

1. **Forward from WhatsApp.** From the linked phone send the bot a scam message
   (`samples/forwarded-message-demo/suspicious-message.txt`) or a screenshot or PDF. It takes 10 to 30 seconds.
2. **Open My reports on the website.** Show the verdict, the reasons, the links and the attachment checks.
   For a screenshot, show the text read off the image (OCR). For a harmless message, show it is not flagged.
3. **Same pipeline in the browser.** Analyze page, "Or paste a message you were sent", Standard analysis,
   to show the live timeline.
4. **Show where the result appears.** In this mode, the result is under **My reports**.
5. **Privacy page and sign-in.** `https://e-tap-azure.vercel.app/privacy.html`; the phone number is
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
- What makes replies possible? Configure the sender, account subscription and access token, then set
  `WHATSAPP_REPLIES=1`. If Meta reports an account lock, check Business Support Home.
- Can anyone use it? The Meta test number only talks to the numbers added as recipients (up to 5).
  A public bot needs a verified WhatsApp Business number.
