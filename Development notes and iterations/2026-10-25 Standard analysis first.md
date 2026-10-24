# 2026-10-25 — Standard analysis first

**Type:** Decision and implementation

## The principle
Whatever E-TAP adds must not hinder how a normal user uses it. Standard (static) analysis is the default and has to stay instant and unprompted. Dynamic analysis is an extra for people who happen to own a VM, never a hurdle in front of everyone else. This came out of the team's chat on 2026-10-24: most users will never have VirtualBox or Windows Pro, so the product cannot ask them for it.

## What was already true
- **No Google login is needed.** The extension already downloads the full original `.eml` (headers and attachments) through the user's own signed-in Gmail session and falls back to a clearly labelled text-only check. The Google-authorisation idea from the chat is not required.
- **The static report is never blocked by the sandbox.** `_sandbox_plan` and `_submit_to_sandbox` swallow every error, and the VM run happens out of band (the report polls `GET /sandbox/{id}`).
- **The sandbox agent works but is proven once**: one live run on the author's VM (score 73 to 85, rule etap-004), plus tests against a simulated VM.

## What got in a normal user's way (found by reading the code)
- The extension showed "Standard or Deeper?" only after a first click, and asked the server about the sandbox status every time that choice appeared.
- A deeper request asked the user to pair a sandbox before the extension knew the original email, with attachments, had been retrieved.
- The dashboard held every analysis for about 12 seconds of animation with no way to turn it off.
- On the Analyze page, if the sandbox status call failed, the Deeper card stayed selectable but Analyze was disabled with only a hover tooltip.
- Standard runs still showed a "Dynamic attachment analysis" timeline row and a "Not set up" or "Not requested" card.
- Raw errors ("Failed to fetch") and jargon ("Sysmon", "clean snapshot") reached non-technical users.

## What changed
- **Extension 1.6.1:** the banner shows two cards from the start, **Standard analysis** and **Deeper attachment analysis**, each one click, with what Deeper needs written on its card. Nothing is sent and no sandbox status is requested until a card is clicked. A deeper request pairs only once the original email exists, otherwise it finishes as a standard analysis and says why. The pairing screen has an *I don't have a VirtualBox VM* exit. Errors are in plain words, and the manual `.eml` import appears only when retrieval failed. (This replaced a first version with a one-click Standard button and a small Deeper link; see the revision below.)
- **Dashboard:** Standard is the default. **Settings → Analysis animation** has Full (default, the readable timeline) and Fast (no added delay, so the report opens as soon as the analysis finishes), saved per browser. The sandbox row and the Reports-page sandbox card are shown only when relevant. A failed sandbox status check greys out Deeper with a visible reason and leaves Standard working. The wrong-file `alert()` and the silent disabled Analyze button now show inline messages.
- **Agent:** `check` is a new read-only preflight (VirtualBox, snapshot, VM network, clipboard, drag and drop and shared folders off, Hyper-V warning), also run at the end of `setup`, with a one-line fix per item. It never starts the VM; `test` remains the only command that does. Expired jobs and orphaned attachment bytes are now swept when work is queued and every 10 minutes by a background thread, instead of only when something polled.

## Decisions
- Harden the VirtualBox agent first; **no Windows Sandbox provider this round** (it needs a Windows Pro machine to test on, and the research notes recommend one rule engine across providers anyway).
- Slow animation stays the default because the team wants the demo feel; professionals switch to Fast.

## Revision after team feedback (same day)
Krish objected to two things, and one of them was right.
- **Choice up front: he was right, so the choice stays visible.** If Standard runs first and the user later wants Deeper, there is no way to add a sandbox run to the finished report. `sandbox_api.py` has no such route, and the sandbox job is queued only during the original analysis. So "Deeper later" means re-running the whole pipeline, including the rate-limited VirusTotal lookups. Hiding the choice also risks the user finding out about the VM requirement only after wanting it. The extension therefore shows both cards at once (no extra click for Standard), with the requirement in plain text. The Analyze page got the same text on its Deeper card.
- **The 12-second delay and VirusTotal: the delay is display-only.** `usePacedStages` in `UploadPage.jsx` makes no network calls. The backend job starts on the `POST /analyze/jobs` and runs in a thread pool (`analysis_jobs.py`); the page only polls it every 0.6 s and decides how fast to *show* the stages. VirusTotal protection lives in the backend (`vt_lookup.py`: a 4-requests-a-minute limiter, 429 handling, and a per-analysis lookup budget). Measured: a backend job took 6.8 s directly, Fast mode reached the report in 6.9 s, and Full took 13.6 s, so the extra time is purely on screen. The demo reason for the delay is valid and Full stays the default; Fast is an opt-in toggle.
- **Later improvement worth building:** a "run deeper analysis on this report" action that queues only the attachments for the paired agent, without re-running the pipeline. The agent flow already updates a report after the fact, so the missing piece is re-sending the attachments for an existing `email_id`.

## Observation worth a follow-up
In Fast mode a standard analysis took about 7 seconds on the development machine (with an in-memory database and no API keys), against 13.6 seconds in Full. The backend job itself took about 6.8 seconds, so the earlier assumption that it finishes in about a second was wrong. Which stage dominates has not been measured yet.

## Still open
- A fresh-machine run of the agent by someone other than the author, following the README. This is the real proof that deeper analysis works for another user.
- VirtualBox on a Hyper-V host: the agent only warns.
- The agent zip is unsigned (SmartScreen will likely warn) and attachments pass through the hosted server's database on the way to the user's VM.

## Follow-up (2026-10-25): honest sandbox status and a verified login
Found while testing as a user: a wrong guest password was accepted, and the dashboard kept saying *online* when the VM was not usable.
- **Why:** setup never started the VM, so the login was never checked; a wrong password later looked like a slow boot (four minutes of retries). "Online" only meant that the agent program was polling.
- **Login:** setup now starts the VM once and confirms Windows accepts the login before anything counts as set up. A rejected login fails in about 30 seconds, is refused (three tries) and is not saved as working. A login rejected during a run clears the verified flag.
- **Status:** the agent re-reads its VM health every 20 seconds (VirtualBox answers, VM and clean snapshot exist, login verified) and sends it with each poll. The server exposes `online`, `ready` and `problem`; the dashboard and extension show *online*, *needs attention* (with the reason) or *offline*. The Analyze page refreshes it every 10 seconds, so it cannot go stale.
- **Checked live on a real VM:** a deliberately wrong password was refused in 27 seconds, the right one accepted, a deleted snapshot showed as *needs attention*, and closing the agent turned the dashboard to *offline* within about 40 seconds without a reload.
