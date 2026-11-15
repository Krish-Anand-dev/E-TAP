# WhatsApp bot

Forward a suspicious message, link, image or document to the bot. It replies at once ("checking"),
runs the normal static analysis, then sends the verdict, the main reasons, what to do next and a
link to the full report on the website. No sandbox, and files are never opened.

Code: `backend/whatsapp.py`. Tests: `backend/tests/test_whatsapp.py` (Twilio) and
`backend/tests/test_whatsapp_meta.py` (Meta). Both providers use the same analysis and wording.

| Provider | Route | Free? | Notes |
|---|---|---|---|
| **Meta WhatsApp Cloud API** (recommended) | `/whatsapp/meta` | Yes, test number | Webhook can be set without paying. |
| Twilio WhatsApp sandbox | `/whatsapp/twilio` | Sending only | A trial account cannot set the incoming webhook; it needs a paid upgrade. |

Each route is off until its secret is set, so having both in the code is harmless.

## One-way mode: link your number to your account

Meta only lets a verified business send replies, so until verification the bot works one way: it
receives what you forward and runs the full analysis, and you read the result on the website.

1. On the website sign in (Settings > Your account), then open Settings > WhatsApp and press
   **Link my WhatsApp**. It shows a one-time code like `ETAP-123456` (valid 15 minutes).
2. From the phone you want to link, send exactly that code to the bot's WhatsApp number.
3. Back on the site press **Check now**. From then on, anything that number forwards (text, links,
   images, documents) is analysed and saved under **My reports** for your account.

Numbers that are not linked are still analysed (the report is saved without an owner). A linked
number is stored only as a keyed hash. One number per account; linking a number to a second account
moves it. Set `WHATSAPP_REPLIES=0` on Render so the bot never tries to reply (Meta would refuse with
131031), and `WHATSAPP_BOT_NUMBER` to the number shown in the instructions. Code: `backend/whatsapp_link.py`,
tests: `backend/tests/test_whatsapp_link.py`.

## Meta Cloud API setup (about 20 minutes)

Menu names change now and then, so follow the idea if a label differs slightly.

1. Go to **developers.facebook.com**, sign in, and **Create app**. Choose the use case
   **Connect with customers through WhatsApp** (an app of type *Business*). Accept the prompts to
   create or pick a Meta business portfolio.
2. In the app, open **WhatsApp > API Setup**. It shows:
   - a free **test phone number** and its **Phone number ID** (a long number),
   - a **temporary access token** (lasts about a day),
   - a **To** box: add your own phone number there and confirm it with the code WhatsApp sends.
     The test number can only message people added here (up to 5), so add everyone who will try the
     bot at the demo.
3. Open **App settings > Basic** and copy the **App secret** (click Show).
4. On Render, add these variables to the backend service, then let it redeploy:

   | Variable | Value |
   |---|---|
   | `META_PHONE_NUMBER_ID` | the Phone number ID from step 2 |
   | `META_ACCESS_TOKEN` | the access token (see "Token that does not expire" below) |
   | `META_APP_SECRET` | the App secret from step 3 |
   | `META_VERIFY_TOKEN` | any secret string you make up, e.g. a long random phrase |
   | `PUBLIC_FRONTEND_URL` | `https://e-tap-clean.vercel.app` (used in report links) |

5. Back in the dashboard open **WhatsApp > Configuration**. Under **Webhook**, click **Edit** and enter:
   - **Callback URL:** `https://etap-clean-backend.onrender.com/whatsapp/meta`
   - **Verify token:** exactly the `META_VERIFY_TOKEN` you set on Render.

   Click **Verify and save**. Meta calls the URL once to check it; this only works after Render has
   redeployed with the variables from step 4 and the service is awake.
6. Still under Configuration, **Webhook fields**: click **Manage** and **subscribe to `messages`**.
7. From a phone you added in step 2, send "hi" to the test number. You should get the intro text.
   Then forward a text message, a link, a screenshot and a PDF.

### Token that does not expire

The temporary token from API Setup expires after about 24 hours, which would break a demo the next
day. For a token that lasts: **Meta Business Settings > Users > System users**, add a system user,
assign it your app with full control, then **Generate token** with the
`whatsapp_business_messaging` and `whatsapp_business_management` permissions. Put that token in
`META_ACCESS_TOKEN`.

### If something fails

- **Saving the webhook fails:** the verify token does not match Render, Render has not redeployed, or
  the service was asleep. Open `https://etap-clean-backend.onrender.com/health` and try again.
- **403 in the Render logs on every message:** `META_APP_SECRET` is wrong.
- **You get no reply and nothing in the logs:** you did not subscribe to `messages` (step 6), or your
  phone is not in the **To** list.
- **Replies stopped the next day:** the temporary token expired; use a system-user token.

## Twilio sandbox (alternative)

Works only on an upgraded Twilio account, because the incoming webhook is on the legacy sandbox
settings page that trial accounts cannot open.

1. Join the sandbox from your phone with the number and `join ...` code Twilio shows you.
2. On Render set `TWILIO_ACCOUNT_SID`, `TWILIO_AUTH_TOKEN`, `TWILIO_WHATSAPP_FROM` (`whatsapp:` plus
   **the number your own sandbox page shows**; it differs between accounts), `PUBLIC_API_URL`
   (`https://etap-clean-backend.onrender.com`) and `PUBLIC_FRONTEND_URL`.
3. In Twilio's sandbox settings set **When a message comes in** to
   `https://etap-clean-backend.onrender.com/whatsapp/twilio`, method POST.

## Before a demo

- Confirm the backend answers instantly at `https://etap-clean-backend.onrender.com/health`. Meta and
  Twilio both give up on a webhook after a few seconds, and a sleeping free Render service can take
  longer to wake. An UptimeRobot monitor (5-minute interval) on that URL keeps it awake.
- Make sure everyone who will message the bot is on the allowed list (Meta: the **To** list;
  Twilio: has sent the join code, which expires after a few days).
- Try a text, a link and a file once from the demo phone.

## Limits and behaviour

- Up to 5 files per message and 25 MB in total, the same ceiling as an upload on the website. A file
  over the limit, or one that cannot be downloaded, is skipped and the reply says so; the rest of the
  message is still checked.
- Big files are heavy: a 25 MB attachment needs roughly 325 MB of memory while it is parsed (measured),
  and a free Render service has 512 MB. Big analyses (over 8 MB) therefore take turns, shared with the
  website, so two cannot overlap. A big file takes a few seconds longer, and a second big message waits
  for the first. If you expect many large files, a Render plan with 2 GB removes the limit.
- One number can send 10 messages an hour (`WHATSAPP_MAX_PER_HOUR`).
- Text, links, images and documents are checked. Audio, video and stickers get a short reply saying
  what the bot can check.
- A clean result is worded "No problems found", never "safe", and becomes "Limited check" when a
  check could not run. Sender checks do not apply to forwarded messages.
- The report is saved on the website like any other analysis and can be deleted there.
- The Meta test number and the Twilio sandbox are for demos. Open public use needs a verified
  WhatsApp Business number.

## Keeping Render awake

An UptimeRobot monitor (free, 5-minute interval) pings
`https://etap-clean-backend.onrender.com/health`, which keeps the free Render service from sleeping.
There is no GitHub workflow for this: GitHub delays or skips scheduled runs. If the backend URL ever
changes, update the monitor.
