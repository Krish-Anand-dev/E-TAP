# Decision: dynamic analysis through a user-paired sandbox agent

**Date:** 2026-10-24 · **Status:** phases 1–3 built on 2026-10-24 (see "Built" below); phase 4 open · **Builds on:** [Hosted dynamic attachment analysis](2026-10-23%20Hosted%20dynamic%20attachment%20analysis/report.md)

## Decision
E-TAP becomes one codebase. Dynamic attachment analysis is optional and runs on a sandbox the **user** owns, reached through a small paired **E-TAP Sandbox Agent**. Public cloud sandboxes are deferred: their free tiers make uploads public. The separate local build is kept only as the reference implementation of the VM worker.

## User workflow
1. The user opens an email in Gmail and clicks the E-TAP button.
2. Before the check starts, they choose **Standard analysis** or **Deeper attachment analysis**. An info icon explains that the deeper option needs a VirtualBox VM (Windows Sandbox on Windows Pro is planned).
3. **Standard** runs today's hosted analysis.
4. **Deeper**, first time only:
   - The user downloads the agent.
   - The agent checks the machine for a supported VM and asks permission for each setup step.
   - It shows a pairing code; once the code is entered in the extension, the extension shows **Your sandbox: online**.
5. **Deeper**, every time:
   - Hosted E-TAP queues the email's eligible attachments for that user's agent (`SANDBOX_BACKEND=agent`).
   - The agent polls for work, collects the job, runs it in its clean VM and uploads the recorded events.
   - Hosted E-TAP converts the events to the common format, runs the shared rules and updates the score and the report. The report shows a status pill until the result arrives.

## Why
- Nothing is executed on the hosted service; files only run inside a VM the user controls.
- No inbound ports on the user's machine: the agent only makes outbound requests.
- The pairing is set up once, so later analyses need no extra steps.
- The same provider interface also serves `replay` (recorded runs for demos and rule tests) and a future managed VM pool.

## Design rules
- Only attachments are transferred to the agent, never the whole email, and only for a job the user started.
- Each agent has its own pairing token. Jobs are scoped to the paired user and expire.
- Events are normalised to Sysmon-style fields. Rules the provider cannot evaluate are shown as **not checked**, never as clean.
- Rules move from Elastic EQL to Sigma (plus YARA for file content). Findings feed the evidence ledger under `dyn.*` ids.
- The existing VM worker (snapshot restore, Sysmon collection, rule evaluation, never-lower scoring) is reused inside the agent rather than rewritten.

## Planned phases
1. **Core:** provider interface, common event format, rule engine, replay provider; the VM worker code moves into the main codebase behind `SANDBOX_BACKEND` (off by default).
2. **Agent:** pairing, an agent job queue and endpoints on the hosted API, and the agent app wrapping the existing VirtualBox worker.
3. **Extension and report:** the Standard/Deeper choice with the info icon, agent status in the extension, and the report's deeper-analysis button and status pill.
4. **Rules:** port the 36 working rules to Sigma, add a curated SigmaHQ set plus YARA, and add tests on replay fixtures.

## Built (2026-10-24)
- **Packaging:** a Python agent (standard library only) that reuses the existing VirtualBox worker. It is served as a zip by the API at `/sandbox/agent/download` and started with `start-agent.cmd`. A signed single-file build comes later.
- **One VM run, two callers:** the run itself (`sandbox_agent/runner.py`) is shared by the agent and the server's local worker. Rule evaluation and scoring (`sandbox/analysis.py`) always run on the server, so a provider only records what happened.
- **Pairing:** the agent registers and shows a single-use code. The extension, or the dashboard's Settings page, exchanges it for a sandbox token. Only token hashes are stored. The agent seals its own token and the guest password with Windows DPAPI.
- **Jobs in MongoDB:** jobs and samples live in MongoDB, so they survive a restart. A job expires after 30 minutes if no agent picks it up, or after 15 minutes if an agent stops reporting during a run. Samples are deleted as soon as a job ends.
- **Extension 1.6.0:** a Standard / Deeper chooser with the info icon, a *Your sandbox* line, and the pairing steps in the analysis tab.
- **Report:** a live *Sandbox behaviour* section and a "Sandbox running" pill. The score and verdict follow when the run finishes.
- **Verification:**
  - Backend tests cover pairing, queueing, ownership, expiry, DTD refusal and a full round trip that raises the score.
  - An end-to-end browser check paired the real agent CLI with the dashboard and ran a script attachment through a simulated VM; the report showed rule etap-004 and a score of 85.
  - A live run on a real VirtualBox Windows 11 VM, through the real agent, succeeded the same day:
    - setup read the VM settings from an existing `.env`;
    - the self-test confirmed the guest login and Sysmon;
    - a paired client sent one deeper analysis of a harmless script attachment;
    - the agent restored the snapshot, opened the file and returned 4 Sysmon events;
    - rule etap-004 matched and the score rose from 73 to 85;
    - the VM went back to its clean snapshot.
  - The Defender event checkpoint was unavailable in that run. A follow-up self-test showed that the first Defender log query after the VM resumes takes about 18 s, longer than its 15 s limit. The limit is now 60 s with one retry, the failure reason is logged, and a failed checkpoint shows in the report as "Defender not checked" instead of zero blocks.

## Open questions
- Windows Sandbox support needs its own launcher and telemetry path.
- Sigma/YARA engine choice (pySigma backend or a small evaluator) for phase 4.
- Whether agent jobs should also be tied to a signed-in user once the API has accounts.
