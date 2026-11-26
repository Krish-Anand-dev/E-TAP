# WhatsApp bot

Forward a suspicious message, link, image or document to the bot. It replies at once ("checking"),
runs the normal static analysis, then sends the verdict, the main reasons, what to do next and a
link to the full report on the website. The reply is text, worded like the website's share card; the card picture itself is not sent. No sandbox, and files are never opened.

**Two modes.** Two-way (`WHATSAPP_REPLIES=1`, the default): the bot replies on WhatsApp. Receive-only (`WHATSAPP_REPLIES=0`): it still analyses everything and saves it, and a linked number reads the result under **My reports** on the website (see "One-way mode" below). Whether replies are delivered depends on the Meta account, so test with the steps in "Restore outgoing Meta replies".

Code: `backend/whatsapp.py`. Tests: `backend/tests/test_whatsapp.py` (Twilio),
`test_whatsapp_meta.py` (Meta) and `test_whatsapp_large_files.py`. Both providers use the same analysis and wording.

| Provider | Route | Free? | Notes |
|---|---|---|---|
| **Meta WhatsApp Cloud API** (recommended) | `/whatsapp/meta` | Yes, test number | Webhook can be set without paying. |
| Twilio WhatsApp sandbox | `/whatsapp/twilio` | Sending only | A trial account cannot set the incoming webhook; it needs a paid upgrade. |

Each route is off until its secret is set, so having both in the code is harmless.

## One-way mode: link your number to your account

While the configured Meta account is restricted, the bot can work one way: it receives what you
forward and runs the full analysis, and you read the result on the website. Error 131031 means
"Business Account locked"; it does not establish that business verification is the cause.

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

## Restore outgoing Meta replies

1. Open [Meta Business Support Home](https://business.facebook.com/business-support-home/) and
   select the WhatsApp account used by E-TAP. Inspect the restriction and complete the specific
   remediation or review Meta offers. A code change cannot override an account lock. Do not assume
   that buying a plan, adding a card or business verification alone will resolve it.
2. In the app's **WhatsApp > API Setup**, confirm that `META_PHONE_NUMBER_ID` and
   `META_ACCESS_TOKEN` refer to the same sending number and account. Refresh an expired token.
   For a test number, add and verify the intended recipient in the **To** list.
3. Send the dashboard's test template to that recipient. Confirm it arrives on their phone,
   then have them reply; this opens the 24-hour customer-service window for ordinary text replies.
4. On the deployed backend, set `WHATSAPP_REPLIES=1` and redeploy. Keep the existing webhook
   subscribed to `messages` at `/whatsapp/meta` and its signature secret configured.
5. From that phone, send `hi`, then a suspicious message. Confirm the instructions, acknowledgement,
   verdict and report link actually arrive. API acceptance alone is not proof of delivery.
   The backend now logs both immediate API errors and failed delivery status webhooks with numeric
   provider codes, without logging phone numbers, message contents or access tokens.

References: [Meta setup and test-message flow](https://developers.facebook.com/documentation/business-messaging/whatsapp/get-started),
[Meta account error reference](https://developers.facebook.com/docs/graph-api/reference/whats-app-business-account/).

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
   | `WHATSAPP_BOT_NUMBER` | the bot's sending number, as shown to users in Settings |
   | `WHATSAPP_REPLIES` | `1` to enable replies, or `0` for receive-only mode |

5. Back in the dashboard open **WhatsApp > Configuration**. Under **Webhook**, click **Edit** and enter:
   - **Callback URL:** `https://etap-clean-backend.onrender.com/whatsapp/meta`
   - **Verify token:** exactly the `META_VERIFY_TOKEN` you set on Render.

   Click **Verify and save**. Meta calls the URL once to check it; this only works after Render has
   redeployed with the variables from step 4 and the service is awake.
6. Still under Configuration, **Webhook fields**: click **Manage** and **subscribe to `messages`**.
7. Check the account-level subscription separately. In Meta Graph API Explorer, select your E-TAP
   app and use a token with WhatsApp Business Management access to the test account. Run
   `GET /<WHATSAPP_BUSINESS_ACCOUNT_ID>/subscribed_apps`. If your app is missing, use
   `POST /<WHATSAPP_BUSINESS_ACCOUNT_ID>/subscribed_apps`, then repeat the GET to verify it.
   Use the business account ID here, which is different from the sending phone number ID.
   [Meta subscription API](https://www.postman.com/meta/whatsapp-business-platform/request/26gui66/subscribe-to-a-waba).
8. Publish the app after meeting Meta's requirements, including its privacy policy URL, so real
   messages can reach the callback. From a phone you added in step 2, send "hi" to the test number.
   Confirm the intro text arrives on your phone.
   Then forward a text message, a link, a screenshot and a PDF.

### Token that does not expire

The temporary token from API Setup expires. For a deployment that needs to keep replying after the
test, configure a system-user token:

1. Open **business.facebook.com > Settings > Users > System users** (business portfolio settings).
   The first time, Meta asks you to accept its advertising non-discrimination policy.
2. **Add** a system user (for example `etap-whatsapp-bot`) with the **Admin** role.
3. Select it, **Assign assets**: under **Apps** tick your app with **Manage app** (full access), and under
   **WhatsApp accounts** tick your WhatsApp account with **Everything**.
4. **Generate token**: pick the app, set expiry to **Never** (or 60 days), tick
   `whatsapp_business_messaging` and `whatsapp_business_management`, then **Generate token**. Copy it
   at once; Meta shows it only once.
5. Paste it into `META_ACCESS_TOKEN` on Render and let it redeploy. Do not paste it into chats or commits.

To revoke it later: System users > the user > **Revoke tokens**.

**Symptoms of a bad token:** text messages still work, but files and photos never produce a report, and
the Render log says `WhatsApp media lookup refused (status 400/401)`. Text does not need the token
because the bot only reads what Meta posts to the webhook; downloading a file does.

### If something fails

- **Saving the webhook fails:** the verify token does not match Render, Render has not redeployed, or
  the service was asleep. Open `https://etap-clean-backend.onrender.com/health` and try again.
- **Incoming POST returns 403:** verify that `META_APP_SECRET` is from the app that sent the webhook.
- **Incoming POST returns 200, but the outbound call is refused:** check the Graph error code,
  token expiry and permissions, and whether the token and sender ID belong to the same app setup.
- **Meta sees the message, but Render has no POST:** check the callback URL, the `messages` field,
  the account-level app subscription, the app's published status, and the verified recipient list.
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
  longer to wake. An UptimeRobot monitor (5-minute interval) on the service root keeps it awake (see below).
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
`https://etap-clean-backend.onrender.com/`, which keeps the free Render service from sleeping. Use the
root address: the free monitor sends `HEAD`, which `/health` rejects with 405.
There is no GitHub workflow for this: GitHub delays or skips scheduled runs. If the backend URL ever
changes, update the monitor.
