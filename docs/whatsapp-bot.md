# WhatsApp bot (Twilio sandbox)

Forward a suspicious message, link or file to the bot. It replies at once ("checking"), runs the
normal static analysis, then sends the verdict, the main reasons, what to do next and a link to
the full report on the website. No sandbox, files are never opened.

Code: `backend/whatsapp.py`. Tests: `backend/tests/test_whatsapp.py` (Twilio is faked).

## One-time setup (about 10 minutes)

1. Create a free Twilio account. In the console open **Messaging > Try it out > Send a WhatsApp message**.
2. Note the sandbox number (usually `whatsapp:+14155238886`) and your **join code** ("join word-word").
3. On Render, add these environment variables to the backend service, then let it redeploy:

   | Variable | Value |
   |---|---|
   | `TWILIO_ACCOUNT_SID` | from the Twilio console home page |
   | `TWILIO_AUTH_TOKEN` | from the Twilio console home page |
   | `TWILIO_WHATSAPP_FROM` | `whatsapp:+14155238886` (the sandbox number) |
   | `PUBLIC_API_URL` | `https://etap-clean-backend.onrender.com` (exactly the public address, no trailing slash) |
   | `PUBLIC_FRONTEND_URL` | `https://e-tap-clean.vercel.app` (used in report links) |

4. In Twilio, **Sandbox settings > When a message comes in**: set the URL to
   `https://etap-clean-backend.onrender.com/whatsapp/twilio`, method **POST**, and save.
5. From your phone, send the join code to the sandbox number. Then send "hi" to check the bot answers.

`PUBLIC_API_URL` matters: every request is checked against Twilio's signature, which is computed over
the exact public URL. If it is wrong, every message is refused with 403.

## Before a demo

- Make sure the backend is awake. Twilio gives up on a webhook after about 15 seconds and a sleeping
  free Render service can take longer to start. Open `https://etap-clean-backend.onrender.com/health`
  and confirm it answers instantly, and keep an external pinger running (see below).
- Everyone who will message the bot must have sent the join code. In the Twilio sandbox that join
  expires after a few days (check the console), so ask people to rejoin the day before.
- Try a text, a link and a file once from the demo phone.

## Keeping Render awake

An UptimeRobot monitor (free, 5-minute interval) pings
`https://etap-clean-backend.onrender.com/health`, which keeps the free Render service from sleeping.
There is no GitHub workflow for this: GitHub delays or skips scheduled runs, so it was removed.
If the backend URL ever changes, update the monitor.

## Limits and behaviour

- Up to 3 files per message, 10 MB each, 15 MB total. Anything larger, or not hosted by Twilio, is
  skipped and the reply says so.
- One number can send 10 messages an hour (`WHATSAPP_MAX_PER_HOUR`).
- A clean result is worded "No problems found", never "safe", and becomes "Limited check" when a
  check could not run. Sender checks do not apply to forwarded messages.
- The report is saved on the website like any other analysis, and can be deleted there.
- The Twilio sandbox is for demos: only people who have joined can use it. Open public use needs a
  verified WhatsApp Business sender.
