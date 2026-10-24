# 2026-10-25 — Getting the sandbox working: the iterations

**Type:** Implementation log (what we tried, what broke, what we changed)

Dynamic attachment analysis did not work the first time it met a real user flow. It took about a dozen rounds, each started by something that went wrong while using it the way a normal user would. This entry keeps the sequence in one place, because the individual fixes are spread over the other notes and the code. The architecture itself is in [Sandbox agent direction](2026-10-24%20Sandbox%20agent%20direction.md) and `CONTEXT.md` (Stage S).

## Starting point
A VirtualBox sandbox already worked on one developer machine: attachments were opened in a clean-snapshot Windows 11 VM, Sysmon recorded the activity, an EQL-subset engine matched behaviour rules (36 of 164 definitions evaluable) and the score only ever went up. One sample (a script inside a ZIP, blocked by Windows Defender) had been verified end to end, and PDFs had a launcher. That version only worked when the backend and the VM were on the same computer, so it could not serve a hosted site.

## The rounds

### 1. Research, then a design that fits a hosted product (2026-10-23)
Public cloud sandboxes were compared and set aside for now (free tiers make uploads public). The conclusion was a provider design: one record format, one rule engine, and a user-owned sandbox reached through a small agent. See the [research report](2026-10-23%20Hosted%20dynamic%20attachment%20analysis/report.md).

### 2. First agent build (2026-10-24)
- The VM run was moved into one shared module used by the agent and by the server's local mode. Rule evaluation and scoring stayed on the server, so rules can change without reinstalling anything.
- Added pairing (a one-time code), a MongoDB job queue so jobs survive a restart, and agent endpoints that only make outbound requests.
- Added the Standard / Deeper choice in the extension and a live *Sandbox behaviour* section in the report.
- Verified with a simulated VM, then live: a harmless script raised the score from 73 to 85.

### 3. The Defender check failed silently
The live run reported the Defender log as "unavailable". A follow-up self-test showed the first query after the VM resumes takes about 18 seconds, longer than its 15-second limit. It now gets 60 seconds and a retry, the real reason is logged, and a failed check shows as "Defender not checked" instead of "0 blocked".

### 4. The sandbox did not appear on the real site
Testing as a user showed no deeper option on the dashboard because the server defaulted to "off". The default became the paired-agent mode, every backend runs only when a deeper analysis is requested, the Analyze page always shows both choices, and pairing happens inline.

### 5. "No module named sandbox_agent"
A user double-clicked the launcher inside the downloaded zip, which copies only that one file out. The download was fine; the launcher now checks that its folder is present and says what to do (Extract All), gives a clear Python message, uses Windows line endings (a rule is kept in `.gitattributes`), and every setup instruction says "Extract All".

### 6. Standard first (team feedback, merged)
Nothing may get in a normal user's way: Standard analysis is one click and never touches the sandbox, both choices are visible up front with what Deeper needs written out, the animation has a Full / Fast setting, and the agent gained a read-only `check`. Details in [Standard analysis first](2026-10-25%20Standard%20analysis%20first.md).

### 7. A wrong password was accepted, and "online" lied
Found while using it: the agent accepted a password it had never tested, and the dashboard kept saying *online* when the VM was gone.
- Setup now starts the VM once and confirms Windows accepts the login; a rejected login fails in about 30 seconds (it used to look like a four-minute slow boot) and is never saved as working.
- The agent reports its VM health every 20 seconds (VirtualBox answers, VM and clean snapshot exist, login verified). The page shows *online*, *needs attention* with the reason, or *offline*, and refreshes itself.
- Checked on a real VM: wrong password refused in 27 seconds, right one accepted, a deleted snapshot showed *needs attention*, closing the agent turned the page *offline* within about 40 seconds.

### 8. "Run deeper analysis" did nothing visible
On the hosted site the run went straight to the timeline and ended with nothing opened. The test email's only attachment was a JSON data file, which the sandbox deliberately does not run, and nothing said so. Now choosing Deeper lists each attachment as "will be opened" or "will not be opened: <reason>", and clicking Run first checks the sandbox and the attachments and explains any problem before anything starts. When the sandbox is offline the card carries the agent download, the three setup steps and a way to pair a different sandbox.

### 9. The result never reached the report
A PDF job stayed on "Restoring clean VM…" although the VM had been restored. The agent uploaded the VM's whole Sysmon log; with a "log everything" configuration a browser opening a PDF produces tens of thousands of events. A synthetic 74 MB log needed about 570 MB of memory to parse on the server, more than a small hosted instance has, so the upload failed and the report waited until the job timed out. The agent now streams the log and uploads only the events of the sample's own process trees (kilobytes instead of megabytes; the full export is deleted from the PC), the server's limit is stricter and returns a clear message, and a failed upload is followed by a short note so the report closes as incomplete instead of hanging.

### 10. It works
A full run from the dashboard on a script attachment: the report showed *Threat seen*, one file opened, rule etap-004 matched (prevention-grade, MITRE T1059.005 and T1059.007), Windows Defender's block recorded, the processes observed (13 events) and the score raised. The run took about two minutes from start to finish.

## What the rounds had in common
- **Every failure came from using it as a normal user would**, not from the unit tests. Those passed throughout because they used an in-memory database, a simulated VM and tiny logs, none of which show a 15-second timeout, a 74 MB upload or a person double-clicking inside a zip.
- **Status that sounds reassuring must be earned.** "Online", "set up" and "0 blocked" each claimed more than had been checked, and each was replaced by a state that says what was actually verified.
- **Say what will and will not happen before the run**, not afterwards.
- **A job must always end.** Every path (refused, failed, timed out, agent closed) now finishes the report with a reason.

## Test and verification state
Backend 215, frontend 18 and extension 27 tests pass. Live checks on a real VirtualBox VM covered login verification, health and status changes, and the script-attachment run above.

## Still open
- The agent still needs trying by a person other than its authors, from the README only.
- The queue has been exercised against an in-memory database and the deployed backend, but not stress-tested with several agents at once (the per-IP rate limit sees the hosting proxy as one address).
- Click-triggered documents (Office files, PDFs that wait for a click) come back inconclusive; nothing clicks inside them yet.
- Only 36 of the 164 behaviour rules can be evaluated; Sigma and YARA support is the next step, and a Windows Sandbox provider would add a second kind of user machine.
- The agent zip is unsigned, so Windows SmartScreen may warn.

## Housekeeping
The repository gained an MIT `LICENSE` on 2026-10-25, with a License section in the README.
