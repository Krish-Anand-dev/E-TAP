# E-TAP: Email Threat Analysis Platform

**Is that message safe?** E-TAP checks a suspicious email or message the way a security analyst would, then says in plain words how risky it is, why, and what to do next.

[![Read the documentation](https://img.shields.io/badge/Read_the-Documentation-0f6cbd?style=for-the-badge&logo=notion&logoColor=white)](https://classy-particle-fa3.notion.site/E-TAP-Documentation-4262ec83607681e5b3e7c3d2e7069d4e)

**Website:** <https://e-tap-azure.vercel.app> · **API:** [health](https://etap-v8-backend.onrender.com/health) · [reference](https://etap-v8-backend.onrender.com/docs)

> E-TAP helps you decide. It is not an oracle: a check that is missing or failed is reported as *unknown*, never as *safe*.

## What it does

| Way in | What you give it |
|---|---|
| Upload | an `.eml` or `.msg` file |
| Gmail extension | one click on an opened email |
| Paste a message | an SMS or chat message, with up to 5 files |
| WhatsApp | a forwarded message, link, image or document |

It checks the sender (SPF, DKIM, DMARC, lookalike domains), attachments (real file type, macros, QR codes, text in images), links, reputation and past emails, then gives a score, a verdict, the reasons and the next step. Links are never opened. Optionally, attachments can be run in a virtual machine **you own** to see what they do.

A linked WhatsApp number sees its results under **My reports** (in preview, for approved test numbers).

## Where data comes from and goes

| Service | Used for | What is sent |
|---|---|---|
| VirusTotal | known bad links and files | URLs (trimmed if they carry secrets) and file hashes |
| AbuseIPDB, ip-api | IP reputation and location | public IP addresses |
| WHOIS | domain age | domain names |
| Google Gemini | reading the content | a privacy-reduced copy of the evidence |
| Cloudinary | image previews and the share card | image attachments only |
| MongoDB Atlas | storing reports | analysis results |
| Brevo | sign-in codes | your email address |
| Meta WhatsApp Cloud API | receiving forwards | messages sent to the bot |

Details: [privacy policy](frontend/public/privacy.html).

## Run it

You need Python 3.11 and Node.js 22.12 or newer.

```bash
cp .env.example .env          # set USE_FAKE_DB=1 to try it with no setup
python -m venv .venv && source .venv/bin/activate      # Windows: .\.venv\Scripts\Activate.ps1
pip install -r backend/requirements.txt
cd backend && python -m uvicorn app:app --host 127.0.0.1 --port 5000
```

In a second terminal:

```bash
cd frontend && npm ci && npm run dev
```

Open <http://127.0.0.1:5173>. For live checks, add your own `GEMINI_API_KEY`, `VIRUSTOTAL_API_KEY` and `ABUSEIPDB_API_KEY` to `.env` and set `THREAT_INTEL_LIVE=1`.

**Deeper analysis (optional):** choose *Deeper* on the website, download the agent, extract the zip, run `start-agent.cmd` and enter its pairing code. See the [agent guide](backend/sandbox_agent/README.md).

**Tests:**

```bash
pip install -r backend/requirements-dev.txt
cd backend && python -m pytest tests -q --ignore=tests/test_threat_intel_live.py
cd ../frontend && npm test && npx vite build
cd .. && node --test --test-isolation=none extension/tests/*.test.mjs
```

## More

[Technical reference](CONTEXT.md) · [WhatsApp setup](docs/whatsapp-bot.md) · [Sandbox internals](backend/sandbox/README.md) · [MCP server](mcp_server/README.md) · [Incident runbook](docs/incident-runbook.md) · [Contributing](CONTRIBUTING.md) · [Security](SECURITY.md) · [MIT licence](LICENSE)
