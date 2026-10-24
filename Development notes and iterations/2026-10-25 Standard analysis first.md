# 2026-10-25 — Standard analysis first

**Type:** Decision and implementation

## The principle
Whatever E-TAP adds must not hinder how a normal user uses it. Standard (static) analysis is the default and has to stay instant and unprompted. Dynamic analysis is an extra for people who happen to own a VM, never a hurdle in front of everyone else. This came out of the team's chat on 2026-10-24: most users will never have VirtualBox or Windows Pro, so the product cannot ask them for it.

## What was already true
- **No Google login is needed.** The extension already downloads the full original `.eml` (headers and attachments) through the user's own signed-in Gmail session and falls back to a clearly labelled text-only check. The Google-authorisation idea from the chat is not required.
- **The static report is never blocked by the sandbox.** `_sandbox_plan` and `_submit_to_sandbox` swallow every error, and the VM run happens out of band (the report polls `GET /sandbox/{id}`).
- **The sandbox agent works but is proven once**: one live run on the author's VM (score 73 to 85, rule etap-004), plus tests against a simulated VM.

## What got in a normal user's way (found by reading the code)
- The extension asked "Standard or Deeper?" on every click and asked the server about the sandbox each time.
- A deeper request asked the user to pair a sandbox before the extension knew the original email, with attachments, had been retrieved.
- The dashboard held every analysis for about 12 seconds of animation with no way to turn it off.
- On the Analyze page, if the sandbox status call failed, the Deeper card stayed selectable but Analyze was disabled with only a hover tooltip.
- Standard runs still showed a "Dynamic attachment analysis" timeline row and a "Not set up" or "Not requested" card.
- Raw errors ("Failed to fetch") and jargon ("Sysmon", "clean snapshot") reached non-technical users.

## What changed
- **Extension 1.6.1:** one click runs the standard analysis. An optional **Deeper analysis** link sits beside it. Nothing about the sandbox is requested unless it is clicked. A deeper request pairs only once the original email exists, otherwise it finishes as a standard analysis and says why. The pairing screen explains what deeper analysis needs and has an *I don't have a VirtualBox VM* exit. Errors are in plain words, and the manual `.eml` import appears only when retrieval failed.
- **Dashboard:** Standard is the default. **Settings → Analysis animation** has Full (default, the readable timeline) and Fast (no added delay, so the report opens as soon as the analysis finishes), saved per browser. The sandbox row and the Reports-page sandbox card are shown only when relevant. A failed sandbox status check greys out Deeper with a visible reason and leaves Standard working. The wrong-file `alert()` and the silent disabled Analyze button now show inline messages.
- **Agent:** `check` is a new read-only preflight (VirtualBox, snapshot, VM network, clipboard, drag and drop and shared folders off, Hyper-V warning), also run at the end of `setup`, with a one-line fix per item. It never starts the VM; `test` remains the only command that does. Expired jobs and orphaned attachment bytes are now swept when work is queued and every 10 minutes by a background thread, instead of only when something polled.

## Decisions
- Harden the VirtualBox agent first; **no Windows Sandbox provider this round** (it needs a Windows Pro machine to test on, and the research notes recommend one rule engine across providers anyway).
- Slow animation stays the default because the team wants the demo feel; professionals switch to Fast.

## Observation worth a follow-up
In Fast mode a standard analysis took about 7 seconds on the development machine (with an in-memory database and no API keys), against 13.6 seconds in Full. The backend job itself took about 6.8 seconds, so the earlier assumption that it finishes in about a second was wrong. Which stage dominates has not been measured yet.

## Still open
- A fresh-machine run of the agent by someone other than the author, following the README. This is the real proof that deeper analysis works for another user.
- VirtualBox on a Hyper-V host: the agent only warns.
- The agent zip is unsigned (SmartScreen will likely warn) and attachments pass through the hosted server's database on the way to the user's VM.
