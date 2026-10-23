# E-TAP Sandbox — Attachment Behavioral Analysis

## What This Module Does

The sandbox answers one question:

> **What actually happens when a normal user opens an email attachment in a Windows environment?**

Since 2026-10-24 the VM run itself lives in `../sandbox_agent/runner.py` (shared by the paired agent and the local worker) and rule evaluation in `analysis.py`; see CONTEXT.md, Stage S, for the architecture. The status notes below come from the local development of this module.

It copies the attachment into a disposable VirtualBox Windows 11 VM, opens it with the appropriate application, watches what happens via Sysmon for 30 seconds, checks the activity against 36 detection rules, and reports the results. If a rule matches, the risk score goes up. If no rule matches, the result is "inconclusive" — never "safe."

---

## Current Status (as of 2026-10-18)

### ✅ Working

| Component | Status | Notes |
|---|---|---|
| VM setup | ✅ Works | VirtualBox 7.x, Win11, Guest Additions, sandbox user (admin, UAC off) |
| Sysmon | ✅ Works | v15.22, schema 4.91, log-everything config, 256 MB log |
| VM isolation | ✅ Works | NIC disabled, clipboard off, drag-and-drop off |
| Snapshot restore | ✅ Works | ~20 seconds (fresh snapshot taken 2026-10-18) |
| Guest control | ✅ Works | run, copyto, copyfrom all verified |
| Rule engine | ✅ Works | 36 evaluable Windows rules, 128 unsupported queries reported |
| ECS converter | ✅ Works | Parses Sysmon XML, filters to sample process tree |
| Scoring | ✅ Works | Never-lowers-risk logic verified |
| Pipeline integration | ✅ Works | sandbox.submit() called after correlation, result in API response |
| API endpoints | ✅ Works | GET /sandbox/{email_id}, sandbox field in GET /investigations/{id} |
| Frontend panel | ✅ Works | SandboxPanel.jsx with status, rules, MITRE, coverage |
| Frontend polling | ✅ Works | Polls every 4s while sandbox is running |
| Detonation policy | ✅ Works | Correctly filters eligible attachments (scripts, executables, docs) |
| Host paths | ✅ Works | Absolute file transfers; configured relative paths resolve from the repository root |
| ZIP children | ✅ Works | Bounded in-memory unpacking; generated sample names; execution only inside the guest |
| Process evidence | ✅ Works | ProcessGuid descendant filtering and observed commands in the report |
| Windows security evidence | ✅ Works | New Defender events collected per job; confirmed blocks distinguished from launch failures |
| Job recovery | ✅ Works | VM lock held through cleanup; terminal status stored after restore with completion timestamp |

### ⚠️ Partially Working / Known Issues

| Issue | Description | Impact |
|---|---|---|
| **Snapshot restore sometimes fails** | After multiple restore cycles, the guest session can get stuck in "terminated" state. The `wait_ready()` function retries but may time out after 240s. Fix: take a fresh snapshot from a clean boot, not from a restored snapshot. | Jobs may fail intermittently |
| **Defender blocks the invoice demo's certutil command** | The supplied `T3_zip_invoice_js.eml` contains `invoice.zip / invoice.js`. Defender detects the command before certutil starts; cscript reports Permission denied. The report includes Defender event 1116 and `blocked_by_security_control`. | No certutil process event is expected when creation is blocked; etap-004 still observes the script interpreter |
| **GUI apps via headless mode** | `wscript.exe`, `notepad.exe`, browsers launched via `cmd.exe /c` may not display on the interactive desktop in headless mode. The process runs but the window may not be visible. | Can't take meaningful screenshots |
| **No screenshots yet** | `take_screenshot()` is implemented but not called in the worker flow. | Dashboard shows no visual evidence |
| **Office/HTML handlers missing; PDFs open without interaction** | PDFs now open with the guest's default PDF app (or `SANDBOX_PDF_VIEWER`). Nothing clicks inside them, and Windows 11's default viewer (Edge) ignores PDF Launch actions, so click-triggered PDFs come back inconclusive. Office/HTML files still have no launcher and return "incomplete" (shown as *Not tested*). | Interactive documents need a suitable viewer plus UI automation |
| **No interactive UI automation** | Profile B (normal-user open and view) is not implemented. Executables launch directly through guestcontrol; scripts use cscript to expose errors without invisible wscript dialogs. | No scroll, no page navigation, no dialog handling |
| **Other archives** | RAR, 7z, disk images, nested ZIPs and encrypted ZIP members are reported as incomplete. | Only unencrypted ZIP children are currently supported |
| **No browser-level observation** | Sysmon can't capture JavaScript execution, page navigations, or form submissions. No headless browser instrumentation. | HTML/SVG attacks invisible |
| **No network simulation** | Profile D (simulated network) is not implemented. VM has no network adapter. DNS/network rules fire on attempted connections but they all fail. | Can't observe C2 communication |
| **Worker error handling** | If the VM fails to restore or the sample crashes, the worker catches the exception but the error message may not be clear in the UI. | User sees "error" without details |
| **No replay traces** | The `replays/` directory is empty. No recorded Sysmon traces for demo mode. | `SANDBOX_BACKEND=replay` returns "unavailable" |

### ❌ Not Implemented

| Feature | Description |
|---|---|
| **Profile C (embedded object interaction)** | Opening embedded files in documents, extracting and detonating child objects |
| **Profile D (simulated network)** | Internal DNS/HTTP sinkhole for observing C2 attempts |
| **Browser instrumentation** | Puppeteer/Selenium in the VM for HTML/SVG behavioral observation |
| **Application detection** | Checking if Word, Excel, Chrome, etc. are installed in the VM |
| **OneNote handler** | Opening .one/.onepkg files |
| **ISO/IMG mounting** | Mounting disk images and inspecting contents |
| **LNK/URL resolution** | Resolving shortcut targets statically |
| **EML/MSG nested parsing** | Parsing nested emails and enqueuing child attachments |
| **ICS/VCF parsing** | Calendar and contact file analysis |
| **Encrypted documents** | ZIP encryption is detected; Office/document encryption handling is not implemented |
| **Image OCR in sandbox** | Running OCR on screenshots taken during detonation |
| **Detection rule tests** | Positive/negative test cases for each rule |
| **Coverage reporting** | Detailed breakdown of which telemetry sources were available |
| **Evidence file storage** | Storing screenshots, raw telemetry, and process trees on host disk |
| **Async banner in extension** | Gmail extension polling for sandbox results |

---

## Architecture

```
Host (your laptop)                         Guest (VirtualBox VM)
┌────────────────────────┐                ┌─────────────────────────┐
│  E-TAP FastAPI Backend  │                │  Windows 11 (headless)  │
│                         │   VBoxManage   │                         │
│  pipeline.py            │  guestcontrol  │  sandbox user (admin)   │
│    └─ sandbox.submit()  │────────────────│  Sysmon v15.22          │
│                         │  copy/run      │  C:\sandbox\in\         │
│  sandbox/worker.py      │────────────────│  C:\sandbox\out\        │
│    ├─ vbox.py           │  export xml    │                         │
│    ├─ policy.py         │────────────────│  Applications:          │
│    ├─ ecs_convert.py    │                │    wscript, cmd, etc.   │
│    ├─ rule_engine.py    │                │                         │
│    └─ scoring.py        │                │  NO network adapter     │
│                         │                │  NO shared folders      │
│  MongoDB                │                │  NO clipboard           │
└────────────────────────┘                └─────────────────────────┘
```

### Job Lifecycle

1. User uploads `.eml` → E-TAP runs static analysis
2. `sandbox.submit()` filters eligible attachments (scripts, executables, archives, documents)
3. Background worker picks up the job (one VM = one job at a time)
4. VM restores to `clean` snapshot → boots → waits for guest control (~20s)
5. Eligible ZIP children unpacked as bytes with bounds (100 entries, 50 MiB total, 10 MiB per sample, at most 3 eligible children per archive); each sample copied to `C:\sandbox\in\` under a unique generated name → launched with separate executable arguments
6. Dwell time (30 seconds) while Sysmon observes
7. Sysmon log exported as XML → copied to host
8. Events filtered to sample's process tree only
9. 36 detection rules evaluated against filtered events
10. New Defender events checked for sample-related detections/blocks
11. VM restored to clean state → results stored in MongoDB → risk score updated (only raised, never lowered)

The configured `clean` snapshot was taken from a running VM. Restoring it leaves VirtualBox in **Saved** state. This is the expected idle baseline; the next job starts/resumes it. Do not boot the guest manually while a job is using it.

`GET /investigations/{id}` and `GET /sandbox/{id}` both expose live job phases, including telemetry collection and snapshot restoration. Raw attachment payloads are excluded from status responses. `error` means execution/collection failed, `partial` means some samples were incomplete, and a confirmed Windows block is a completed observation with an item verdict of `blocked_by_security_control`.

### Verification

From the repository root (offline regressions do not touch VirtualBox):

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s backend/tests -p test_sandbox.py -v
```

Opt-in live test with an isolated in-memory database and offline AI/intelligence. This resets the configured VM before and after execution:

```powershell
.\.venv\Scripts\python.exe backend/tests/run_sandbox_smoke.py --email "C:\path\T3_zip_invoice_js.eml" --allow-vm-reset --expect-blocked-target certutil.exe
```

For a sample expected to spawn a process without being blocked, use `--expect-process <name.exe>`. The smoke report is saved to `.local/sandbox-smoke.json`; raw Sysmon XML stays in the job work directory and host sample files are removed.

---

## Detection Rules

### Sources

**Elastic Defend (30 rules)** — from the `Reorg_det_rules` corpus. Out of 157 unique Windows rules, only 30 work with Sysmon. The other 127 need Elastic-only telemetry (`.Ext.*` fields, call stacks, memory regions, code signatures).

**E-TAP Custom (6 rules)** — written to cover email-phishing attack patterns:

| Rule ID | Name | MITRE |
|---------|------|-------|
| etap-001 | Ingress Transfer via Windows Utility | T1105 |
| etap-002 | Attempt to Disable Windows Defender Services | T1562.001 |
| etap-003 | Suspicious Script Interpreter Spawned by Office Application | T1204.002, T1059 |
| etap-004 | Suspicious Script Host Execution of Script File | T1059.005, T1059.007 |
| etap-005 | File Dropped in Startup or AutoRun Location | T1547.001 |
| etap-006 | DNS Query by Unusual Process | T1071.001 |
| etap-007 | Registry Modification for Persistence | T1547.001 |

### What Rules Can Detect

- Process chains: Office app → script interpreter → LOLBin → network
- LOLBin abuse: certutil, bitsadmin, mshta, regsvr32, rundll32
- Persistence: Startup folder drops, registry Run keys
- Defense evasion: Disabling Defender, AMSI bypass, AppLocker tampering
- Credential theft: Mimikatz, Rubeus, LSA dumps
- Known RATs: Remcos, NetWire registry fingerprints

### What Rules Cannot Detect

- In-memory attacks (no process spawn)
- Browser-only exploits (no Sysmon event)
- Kernel-level rootkits
- Anything needing Elastic-only telemetry
- Zero-days

### Adding More Rules

Drop `.toml` files into `backend/sandbox/rules/`. The engine auto-loads compatible ones, skips the rest with reasons.

---

## Configuration

### .env Variables

```dotenv
SANDBOX_BACKEND=virtualbox          # agent | virtualbox | replay | none
VBOXMANAGE_PATH=C:\Program Files\Oracle\VirtualBox\VBoxManage.exe
SANDBOX_VM_NAME=<your VM name>
SANDBOX_SNAPSHOT=clean
SANDBOX_GUEST_USER=<guest user>
SANDBOX_GUEST_PASSWORD=<password>
SANDBOX_DWELL_SECONDS=30
SANDBOX_WORK_DIR=backend/sandbox/work
SANDBOX_RULES_DIR=backend/sandbox/rules
```

The two directory settings are optional. Defaults are absolute paths derived from this module. Relative overrides resolve from the repository root even when uvicorn starts in `backend/`. A missing/empty rules directory is an explicit job error, never a successful scan with zero rules.

### Backend Modes

| Mode | Behavior |
|------|----------|
| `agent` | The user's own VM through the paired E-TAP Sandbox Agent (`../sandbox_agent/`); jobs queue in MongoDB (`agent_queue.py`) |
| `virtualbox` | Live detonation in a VM on the server's own machine (`worker.py`) |
| `replay` | Evaluates recorded Sysmon XML traces from `replays/` |
| `none` | Sandbox unavailable (default) |

---

## VM Setup

### Prerequisites

- VirtualBox 7.x on Windows host
- Windows 11 VM
- ~20 GB disk, 4 GB RAM

### Setup Steps (one-time)

1. **Install Guest Additions** in the VM
2. **Create sandbox user:**
   ```cmd
   net user sandbox <password> /add
   net localgroup Administrators sandbox /add
   ```
3. **Disable UAC:**
   ```cmd
   reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System /v EnableLUA /t REG_DWORD /d 0 /f
   ```
   Reboot.
4. **Create folders:**
   ```cmd
   mkdir C:\sandbox\in
   mkdir C:\sandbox\out
   ```
5. **Install Sysmon:**
   ```cmd
   C:\Tools\Sysmon\Sysmon64.exe -accepteula -i C:\Tools\Sysmon\sysmon-all.xml
   wevtutil sl Microsoft-Windows-Sysmon/Operational /ms:268435456
   ```
6. **Disable network, clipboard, drag-and-drop** (VM powered off):
   ```powershell
   VBoxManage modifyvm "<your VM>" --nic1 none
   VBoxManage modifyvm "<your VM>" --clipboard-mode disabled --drag-and-drop disabled
   ```
7. **Take clean snapshot** (VM fully booted, at desktop, Sysmon running, log cleared):
   ```powershell
   VBoxManage snapshot "<your VM>" take "clean" --description "Clean baseline"
   ```

---

## API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `POST /analyze` | POST | Upload `.eml`. Response includes `sandbox.status`. |
| `GET /sandbox/{email_id}` | GET | Current sandbox status and results. |
| `GET /investigations/{email_id}` | GET | Full investigation including `sandbox` field. |

---

## Directory Structure

```
backend/sandbox/
├── __init__.py          Entry point: get_backend(), submit()
├── vbox.py              VBoxManage wrapper
├── worker.py            Job queue + lifecycle
├── policy.py            Detonation policy + launcher mapping
├── rule_engine.py       EQL rule parser/evaluator
├── ecs_convert.py       Sysmon XML → ECS events + tree filter
├── scoring.py           Risk scoring (never lowers)
├── replay.py            Recorded-trace fallback
├── README.md            This file
├── rules/               36 detection rules (.toml)
├── replays/             Recorded Sysmon traces (empty)
└── work/                Temp job files (git-ignored)
```

---

## What To Fix Next (Priority Order)

1. **Snapshot restore reliability** — Take snapshots from a clean boot, not from a restored state. Add retry logic with longer waits.
2. **Process tree extraction** — Build a formatted process tree from ECS events for display in the SandboxPanel.
3. **Application detection** — Check if Word/Chrome/etc. are installed before attempting to launch documents.
4. **Other archive formats** — Add bounded RAR/7z and nested archive support.
5. **Screenshots** — Call `take_screenshot()` at key checkpoints during detonation.
6. **Replay traces** — Record Sysmon XML from successful runs for demo mode.
7. **Browser instrumentation** — Add Puppeteer/Selenium in the VM for HTML/SVG observation.
8. **Network simulation** — Internal DNS/HTTP sinkhole for C2 observation.
9. **UI automation** — pywinauto integration for real user interaction simulation.
10. **Extension banner** — Gmail extension polling for sandbox results.
