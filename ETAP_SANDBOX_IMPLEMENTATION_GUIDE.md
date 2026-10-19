# E-TAP Sandbox Implementation Guide

Updated **2026-10-18** against the checked-in/workspace implementation and the recorded live test of `T3_zip_invoice_js.eml`. This replaces the earlier implementation proposal and copied code appendices. Linked Python/JS/TOML files are the source of truth; roadmap items below are explicitly separate from implemented behavior.

## 1. Current result and the meaning of “seven rules”

The local sandbox runs eligible email attachments inside a disposable Windows 11 VirtualBox guest. Sysmon records their behavior. The host converts a subset of those events, evaluates compatible rules, collects Windows Defender evidence, restores the guest baseline, and updates the email investigation.

There are **seven E-TAP custom rule definitions**, `etap-001` through `etap-007`. **Only six currently load.** `etap-002` has an unsupported query expression and is skipped with `bad list`. A different Elastic rule with the same display name, *Attempt to Disable Windows Defender Services*, does load. IDs and filenames distinguish them.

Measured by calling `sandbox.rule_engine.load_rules()` on `backend/sandbox/rules`:

| Inventory | Count |
|---|---:|
| Unique Windows rule definitions considered | 164 |
| Rules successfully loaded and evaluated | 36 |
| Loaded Elastic/vendor rules | 30 |
| Loaded E-TAP custom rules | 6 |
| Skipped definitions | 128 |
| E-TAP custom definitions present on disk | 7 |

“Loaded/evaluated” means the evaluator checks a rule against compatible events. It does not mean the rule matched, or that a positive and negative test exist for it. The invoice email matched **one custom rule, `etap-004`**, not all seven.

## 2. Where the sandbox fits in the email pipeline

```text
Dashboard uploads original .eml/.msg bytes to POST /analyze
  A: parse real headers, body and attachment bytes
  B: header forensics
  B2: static attachment analysis (hashes, signatures, macros, images/OCR/QR)
  D: IOC extraction
  E: configured threat intelligence
  F: historical correlation and database persistence -> email_id
  F': graph diffusion
  C': XGBoost triage
  G: Gemini interpretation or an explicit fallback/triage assessment
  H: assemble report and persist the initial assessment
  S: submit eligible attachments to the sandbox queue
  Return initial report with email_id and sandbox.status=queued
       |
       +--> background VM worker -> evidence -> restore -> update same DB record
       +--> separate background RAG-summary/embedding task
```

`POST /analyze` first completes the normal analysis; it does not wait for VM detonation. Static analysis, configured API calls, model interpretation and MongoDB operations run on the **host**. A local host with internet access can use those services while the **guest** remains disconnected.

The parser supplies attachment `content_bytes_b64`. B2 supplies `filename`, `sha256`, `size_bytes`, `actual_type` and other forensic fields. The worker joins original bytes to B2 candidates by **filename plus SHA-256**, rather than filename alone.

Source: [pipeline.py](backend/pipeline.py), [app.py](backend/app.py), [sandbox entry point](backend/sandbox/__init__.py).

## 3. Host, guest and trust boundaries

| Host laptop | Disposable Windows guest |
|---|---|
| FastAPI/uvicorn, React/Vite, provider configuration and DB connection | Script interpreters, Windows utilities, Guest Additions, Sysmon and Windows security |
| Selects samples, reads bounded ZIP bytes, stages files, evaluates telemetry | Executes selected samples and emits runtime evidence |
| Calls `VBoxManage` through a subprocess argument list | Receives samples using Guest Additions guestcontrol |
| Retains evidence/results after the VM resets | Reset to the configured snapshot after each job |

The inspected VM is `win 11`, using snapshot `clean`. Its network configuration was adapter 1 `null` and the other adapters `none`; clipboard and drag-and-drop were disabled, with no shared folders shown. This is the inspected configuration, **not an isolation check automatically enforced by the worker**. Guest Additions/guestcontrol transfers work without ordinary guest network connectivity.

Attachment contents, email bodies and logs are untrusted data. Sample code executes only inside the guest. The host parses/decodes data and writes generated staging files; it does not run the scripts or executables. Host credentials/provider keys are not copied into the guest.

The current `clean` snapshot was taken while Windows was running. Restoring it returns VirtualBox to **Saved** state. The next job resumes/starts that state headlessly. A saved VM between jobs is therefore expected, and the visible VM window opening/closing does not establish whether a sample actually executed.

## 4. Candidate selection and ZIP handling

[policy.py](backend/sandbox/policy.py) accepts nonempty attachments of at most **10 MiB**, based on eligible extensions or selected detected executable/archive MIME types. It prioritizes script/executable extensions, then smaller files, and selects at most **three top-level attachments per email**.

Eligible extensions include scripts, executables, shortcuts, archives, Office documents, PDF, HTML/SVG/XML and nested mail. Eligibility does not promise a working launcher. A missing application/handler yields `inspection_incomplete`.

[archives.py](backend/sandbox/archives.py) handles unencrypted ZIPs as follows:

1. Read ZIP contents in memory on the host; do not extract the supplied member paths onto the host filesystem.
2. Reject archives with more than **100 entries** or declared expanded size above **50 MiB**.
3. Reject unsafe member paths, including absolute paths, `..` and colon-containing paths.
4. Report encrypted, oversized, nested archive and unsupported members/archives as incomplete where applicable.
5. Read at most **10 MiB + 1 byte** for each eligible member and reject it if oversized.
6. Choose at most **three eligible children per ZIP**. Additional eligible members get explicit limit notes; ordinary ineligible data members are ignored.
7. Hash each chosen child and preserve `archive` / `archive_member` provenance.

The top-level and ZIP-child limits are separate: three selected ZIPs can produce up to nine selected children. There is not currently one global three-child execution budget. ZIP children pass the extension/size eligibility check; they are not rerun through the complete B2 static-analysis stage.

Selected bytes are written under a generated filename such as `sample_job_<job-id>_<random>.js`. The original member filename is retained for display, not used as the staging path. RAR/7z/ISO/IMG and nested archive extraction are not implemented.

## 5. Exact live job lifecycle

[worker.py](backend/sandbox/worker.py) owns an in-process `queue.Queue`, a lazily started daemon thread and an in-process VM lock. One job runs at a time in that process.

1. **Enqueue:** create `job_<random>`, persist a payload-free `queued` status to the existing investigation, then put the job on the queue. Persisting before enqueue prevents an old queued write from overwriting a fast final result.
2. **Prepare:** create the absolute job work directory; set `starting` and `started_at`; load/cache rules. A missing directory or zero evaluable rules is an explicit error.
3. **Acquire VM lock:** retain it through execution and recovery. Stop/discard the current running/paused/saved state as appropriate, then restore the configured snapshot.
4. **Start headless:** resume/boot the guest. Guest readiness is checked by running `cmd.exe /d /c echo ready` using guestcontrol, with a nominal 240-second readiness limit and retries.
5. **Prepare telemetry:** ensure `C:\sandbox\in` and `C:\sandbox\out` exist, clear Sysmon, and checkpoint the latest Defender event record ID. Snapshot-era Defender alerts must not be reused as new detections.
6. **Interact:** expand ZIPs, stage each sample under a unique marker, copy it into `C:\sandbox\in`, and launch it with the configured guest executable and separate arguments.
7. **Observe:** allow the configured dwell interval, default **30 seconds per sample**. Time spent waiting for the launched process counts toward dwell; fast exits leave the remaining dwell time for observation. A started process reaching VBox's observation timeout is recorded as `observation_limit`.
8. **Collect:** export the Sysmon Operational log as XML to `C:\sandbox\out\sysmon.xml`, copy it to the host job directory, and query new Defender detection/action/ASR events.
9. **Evaluate:** select each sample's process tree, convert supported events, evaluate every loaded compatible rule, and attach rule hits, MITRE metadata, process evidence and security events to the item.
10. **Restore:** in `finally`, reset the VM to the clean snapshot while retaining the VM lock. A restore failure becomes an explicit cleanup/job error.
11. **Finish:** set `done`, `partial` or `error`, set `finished_at`, remove host staging files whose names start with `sample_`, and store results/update risk. Raw Sysmon XML remains in the host work directory. Candidate payloads are removed from the in-memory job after processing.

The snapshot resets **once before and once after the whole job**, not between every attachment/ZIP member. Multiple samples in one job share the same running VM state and can affect one another. Unique process markers improve attribution but do not provide per-sample VM isolation.

### Launching and path handling

[vbox.py](backend/sandbox/vbox.py) resolves host copy paths to absolute paths and checks source existence. [config.py](backend/sandbox/config.py) resolves relative work/rules overrides from the repository root, regardless of the shell's working directory. Defaults are derived from the module location.

| Sample | Guest launcher |
|---|---|
| `.js`, `.jse`, `.vbs`, `.vbe`, `.wsf` | `cscript.exe //Nologo <generated-path>` |
| `.wsh` | `wscript.exe <generated-path>` |
| `.hta` | `mshta.exe <generated-path>` |
| `.bat`, `.cmd` | `cmd.exe /c <generated-path>` |
| `.ps1`, `.psh` | Windows PowerShell with `-ExecutionPolicy Bypass -File <generated-path>` |
| `.exe`, `.scr` | Generated executable path directly |
| `.msi` | `msiexec.exe /i <generated-path> /qn` |
| `.lnk`, `.url` | Existing `cmd.exe /c start` mapping; no target resolution/instrumentation |
| Office/PDF/browser/email formats | No application configured in the current map; incomplete inspection |

Console scripting exposes errors on stderr rather than waiting on hidden WScript dialogs. VBox's executable path is not repeated as a positional `argv[0]`, and arguments are not sent as a single shell-escaped command string. Guest PowerShell maintenance commands use UTF-16LE `-EncodedCommand` to preserve quotes/pipes. Base64 here is argument transport, not encryption.

## 6. Telemetry and attribution

[ecs_convert.py](backend/sandbox/ecs_convert.py) parses namespaced Sysmon XML and maps only these event IDs:

| Sysmon ID | ECS-like category | Fields used |
|---|---|---|
| 1 | `process` | Image/name, command line/arguments, ProcessGuid, parent Image/CommandLine/ProcessGuid, user, original filename |
| 3 | `network` | Process identity, destination IP/port |
| 11 | `file` | Process identity, target file path/name/extension |
| 13 | `registry` | Process identity, target registry path, Details |
| 22 | `dns` | Process identity and queried domain |

Roots are process-create events whose command lines contain the sample's unique marker. Descendants are grown using `ProcessGuid` / `ParentProcessGuid`; unrelated processes using the same executable name are not added just because their parent image matches. Behavior executed through an unrelated broker without that GUID lineage can be missed.

`event_count` counts **supported, converted events in that sample tree**. It is not the size of the raw Sysmon log. `process_tree` is a flat list of process-start records with parent metadata, displayed as observed parent/child commands. Other Sysmon event types present in the XML are not evaluated.

### Defender evidence is a separate channel

The worker checkpoints the Defender log and reads up to 50 recent matching events after execution:

| Windows Defender ID | Use in this implementation |
|---|---|
| 1116 | Malware/potentially unwanted software detection evidence |
| 1117 | Security action evidence |
| 1121 | Attack surface reduction block evidence |
| 1122 | Audit evidence collected, but not classified as a block by the helper |

`_security_blocks()` correlates IDs 1121/1116/1117 by a sample marker in the message. For a single launched sample, it can also correlate an observed executable path; a new `CmdLine:_...` alert plus that sample's `Permission denied` / `Access is denied` runtime error handles a child command blocked before a process exists.

**Event 1116 is a detection, not by itself proof of prevention.** The invoice run had additional evidence: the runtime denial and no observed certutil child. The current helper's correlation is heuristic, not PID-perfect. If Defender access/checkpointing fails, block attribution is disabled and the failure is logged; Sysmon analysis can continue. Defender events are not an eighth E-TAP rule and are not evaluated as Sysmon ECS rules.

## 7. The seven E-TAP custom rule definitions

These descriptions reflect the actual query predicates, not just the rule titles. MITRE IDs below are copied from the TOML metadata; they are not independently inferred from a successful attack.

| ID | Rule | Event | Current load status | Metadata MITRE |
|---|---|---|---|---|
| `etap-001` | Ingress Transfer via Windows Utility | Process / Sysmon 1 | Loaded | T1105 |
| `etap-002` | Attempt to Disable Windows Defender Services | Process / Sysmon 1 | **Skipped: `bad list`** | T1562.001 |
| `etap-003` | Suspicious Script Interpreter Spawned by Office Application | Process / Sysmon 1 | Loaded | T1204.002, T1059 |
| `etap-004` | Suspicious Script Host Execution of Script File | Process / Sysmon 1 | Loaded | T1059.005, T1059.007 |
| `etap-005` | File Dropped in Startup or AutoRun Location | File / Sysmon 11 | Loaded | T1547.001 |
| `etap-006` | DNS Query by Unusual Process | DNS / Sysmon 22 | Loaded | T1071.001 |
| `etap-007` | Registry Modification for Persistence | Registry / Sysmon 13 | Loaded | T1547.001 |

All seven files contain an `[[actions]]` entry with `action = "kill_process"`. The evaluator turns that into `prevention_grade: true` for a matching loaded rule. **E-TAP does not execute those rule actions or kill processes when a rule matches.** It evaluates logs after observation; Defender's own prevention and the VM reset are separate mechanisms.

The following query blocks are copied directly from the current TOML files.

### etap-001: Ingress Transfer via Windows Utility

Source: [ingress_transfer.toml](backend/sandbox/rules/ingress_transfer.toml). **Loaded.**

Matches `certutil.exe` with **any one** of `-urlcache`, `-split` or `-f`, or `certreq.exe` with `-Post`. It does not require all three certutil flags, an actual URL, a successful download or a network event. Dedicated synthetic positive assertion exists in `test_real_rules_detect_script_host_and_certutil`. It did **not** match the live invoice run because Defender prevented the certutil child from starting.

```eql
process where
  (process.name : "certutil.exe" and process.command_line : ("-urlcache", "-split", "-f"))
  or (process.name : "certreq.exe" and process.command_line : "-Post")
```

### etap-002: Attempt to Disable Windows Defender Services

Source: [disable_defender.toml](backend/sandbox/rules/disable_defender.toml). **Skipped.**

Intended to match `sc.exe stop/delete` for the listed Defender-related names, `net.exe stop` for the listed services, or PowerShell `Set-MpPreference` with a listed disabling option. The final PowerShell clause embeds `and` inside a parenthesized comparison value list. The current parser rejects the **entire custom rule** as `bad list`; its sc/net branches are therefore not active either. There is no dedicated positive/negative regression for this custom rule. The independently loaded vendor file is `defense_evasion_attempt_to_disable_windows_defender_services.toml`, ID `32ab2977-2932-4172-9117-36e382591818`.

```eql
process where
  (process.name : "sc.exe" and process.command_line : ("stop", "delete") and process.command_line : ("WinDefend", "WdFilter", "WdNisSvc", "WdNisDrv", "Sense"))
  or (process.name : "net.exe" and process.command_line : "stop" and process.command_line : ("WinDefend", "WdFilter", "WdNisSvc"))
  or (process.name : "powershell.exe" and process.command_line : ("Set-MpPreference" and ("DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection")))
```

### etap-003: Suspicious Script Interpreter Spawned by Office Application

Source: [office_spawns_interpreter.toml](backend/sandbox/rules/office_spawns_interpreter.toml). **Loaded.**

Matches a child in the listed interpreter/utility names when its parent is one of Word, Excel, PowerPoint, Outlook, OneNote or Access. This does not prove that a macro ran or that a user clicked anything. The current Office document launchers are unconfigured, and no dedicated positive/negative or live Office test currently exists for this rule.

```eql
process where
  process.parent.name : ("WINWORD.EXE", "EXCEL.EXE", "POWERPNT.EXE", "OUTLOOK.EXE", "ONENOTE.EXE", "msaccess.exe")
  and process.name : ("cmd.exe", "powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "certreq.exe", "bitsadmin.exe")
```

### etap-004: Suspicious Script Host Execution of Script File

Source: [script_host_from_user_dir.toml](backend/sandbox/rules/script_host_from_user_dir.toml). **Loaded.**

Matches `wscript.exe` or `cscript.exe` when its command line contains one of the listed user-writable path fragments, including `\sandbox\`. Despite the description mentioning scripts, the query has no file-extension condition. This is a broad heuristic; benign console scripts can match it. **Confirmed live** for `invoice.zip / invoice.js`; the synthetic certutil test also includes a script-host root, but explicitly asserts `etap-001`.

```eql
process where
  process.name : ("wscript.exe", "cscript.exe")
  and process.command_line : ("\\Users\\", "\\Temp\\", "\\AppData\\", "\\Downloads\\", "\\Desktop\\", "\\sandbox\\")
```

### etap-005: File Dropped in Startup or AutoRun Location

Source: [startup_folder_drop.toml](backend/sandbox/rules/startup_folder_drop.toml). **Loaded.**

Matches file-creation events with target paths under the listed Windows Startup-folder patterns. Despite the title/description mentioning AutoRun or Run keys, this query has no registry branch. Registry behavior belongs to `etap-007`. No dedicated positive/negative or live Startup-file test currently exists.

```eql
file where
  file.path : ("*\\Microsoft\\Windows\\Start Menu\\Programs\\Startup\\*", "*\\Start Menu\\Programs\\Startup\\*")
```

### etap-006: DNS Query by Unusual Process

Source: [dns_by_unusual_process.toml](backend/sandbox/rules/dns_by_unusual_process.toml). **Loaded.**

Matches any DNS event from one of the eight listed interpreters/LOLBins. There is no malicious-domain condition and no requirement that resolution or an outbound connection succeed. An offline guest may produce attempted DNS telemetry, but the invoice test does not guarantee it. No dedicated positive/negative or live DNS test currently exists. The file currently labels the rule T1071.001 (Web Protocols); DNS-specific ATT&CK metadata should be reviewed separately rather than silently claimed as validated.

```eql
dns where
  process.name : ("powershell.exe", "pwsh.exe", "wscript.exe", "cscript.exe", "mshta.exe", "certutil.exe", "regsvr32.exe", "rundll32.exe")
```

### etap-007: Registry Modification for Persistence

Source: [registry_persistence.toml](backend/sandbox/rules/registry_persistence.toml). **Loaded.**

Matches registry modifications under the exact listed CurrentVersion Run, RunOnce, RunServices and Explorer Shell Folders patterns, excluding the four listed process names. It does not cover all Services keys or all persistence techniques; the query is narrower than its description. No dedicated positive/negative or live registry-persistence test currently exists.

```eql
registry where
  registry.path : ("*\\CurrentVersion\\Run\\*", "*\\CurrentVersion\\RunOnce\\*", "*\\CurrentVersion\\RunServices\\*", "*\\CurrentVersion\\Explorer\\Shell Folders\\*")
  and not process.name : ("explorer.exe", "svchost.exe", "dismhost.exe", "msiexec.exe")
```

### Fix needed before saying “all seven custom rules are active”

`etap-002` needs its PowerShell branch expressed as separate predicates, for example the following replacement branch, followed by positive and negative synthetic event tests:

```eql
(process.name : "powershell.exe"
 and process.command_line : "Set-MpPreference"
 and process.command_line : ("DisableRealtimeMonitoring", "DisableBehaviorMonitoring", "DisableIOAVProtection"))
```

This is a **proposed correction, not applied by this documentation update**. Do not test a Defender-disabling rule by turning security off on the host. Synthetic process dictionaries/XML are enough to test rule matching. With only that parser fix and otherwise identical rule files, the expected inventory would become 37 loaded / 127 skipped, including all seven custom rules; that future count is not the current measured result.

### How the evaluator handles the larger corpus

[rule_engine.py](backend/sandbox/rule_engine.py) recursively reads TOML, filters `os_list` for `windows`, deduplicates on `rule.id`, and compiles a limited EQL-like subset. It supports event categories, Boolean expressions, comparisons, list membership and wildcard/string predicates. `:` matching is case-insensitive; the current `_wild()` implementation also permits surrounding text. Description-only requirements are not enforced unless represented in the query.

Current skipped reasons are: 116 definitions need Elastic-only fields; 8 use `sequence`; 2 use `regex`; 1 has unsupported bracket/relationship syntax; and 1 (`etap-002`) produces `bad list`. It does not reproduce full Elastic Defend semantics, temporal sequences, memory/call-stack telemetry or active prevention.

`evaluate()` checks each loaded rule against each converted event and returns one hit per matching **rule/event pair**. Several hits can share one rule ID, and vendor/custom rules can have the same title. The UI's `rule(s)` count is currently the number of match records, not a deduplicated count of rule IDs. Per-event evaluation exceptions are caught and suppressed; a zero-hit result is not proof of complete coverage.

## 8. Verified result for the attached invoice email

```text
T3_zip_invoice_js.eml
  invoice.zip
    invoice.js
      cscript.exe //Nologo C:\sandbox\in\sample_<unique>.js
        attempts WScript.Shell.Run -> certutil.exe -urlcache -split -f ...
        Windows Defender detects the command; script receives Permission denied
```

Recorded on 2026-10-18, from the persistent backend on port 5000:

| Evidence | Recorded result |
|---|---|
| Investigation | `6ad417dc4038a3f932f3bf37` |
| Sample SHA-256 (`invoice.js`) | `8c1c39bdc1ac738385bfde1fd1bc20c05ddd3b7c66f13e384a722e65403e3bf8` |
| Job duration | About 93 seconds, including VM work/collection/restore; timing varies |
| Job status | `done` |
| Item verdict | `blocked_by_security_control` |
| Converted sample-tree events | 13 |
| Matching custom rule | `etap-004` |
| Guest security evidence | Defender event 1116, command-line detection named `Trojan:Win32/Ceprolad.A` |
| Runtime evidence | JavaScript line 3: `Permission denied` |
| certutil process-create event | Not observed; do not claim the download executed |
| Final risk score | 95 in that existing assessment; the sandbox's 85 floor did not lower it |
| Cleanup | Host staging samples removed; guest restored to `clean`, state `saved` |

The detector's threat name is evidence from Windows, not an independent assertion that this demo file successfully infected the machine. The sample attempts a downloader-shaped command using an `.invalid` address. We did not disable Defender to force a child process or a download.

Defender's 1116 event is not `etap-001`. `etap-001` requires a converted process event for certutil/certreq; when security blocks creation before that event exists, it cannot match that absent process.

## 9. Status, APIs, scoring and evidence storage

### Job status versus item verdict

```text
queued -> starting -> interacting -> collecting -> evaluating -> restoring
                                                              -> done / partial / error
```

| Job status | Meaning |
|---|---|
| `done` | Job completed and restored successfully, including a confirmed security-block observation |
| `partial` | At least one item has a launch/inspection gap and at least one does not |
| `error` | Job/cleanup failed, or every item has a launch/inspection gap |
| `not_applicable` | No top-level attachment passed the selection policy |

Item verdicts include `behavior_observed`, `no_behavior_observed_inconclusive`, `blocked_by_security_control`, `inspection_incomplete` and `error`. A rule hit can coexist with a runtime failure; matches remain evidence even when the job is incomplete. An interpreter starting does not prove its payload succeeded. A quiet run is inconclusive, never a clean/safe verdict.

Both `GET /sandbox/{email_id}` and `GET /investigations/{email_id}` merge payload-free in-memory job state with stored results. `/investigations` is what the dashboard polls every four seconds during active phases, including restoration. Polling refreshes only sandbox/risk/assessment-related fields so it preserves the original body/HTML. Terminal results are saved to browser history.

The database field is `sandbox_analysis`; the API report exposes it as `sandbox`. It includes job/mode/status/timestamps, coverage counts, items, matches with sanitized event evidence, observed process records, launch/interaction notes and optional Defender events. Attachment payloads are excluded from status responses and Mongo sandbox documents.

[scoring.py](backend/sandbox/scoring.py) uses `max(existing_score, floor)`:

- A match with `prevention_grade` metadata: score floor **85**.
- Other matches: score floor **65**.
- The label is recomputed with `verdicts.finalize_verdict` (the more severe of the existing label and the new score), so with the canonical thresholds a floor of 85 reads `HIGH-RISK PHISHING` and 65 reads `LIKELY PHISHING`. The stored `verdict_band` is updated too.
- No matches: keep risk unchanged; sandbox assessment is inconclusive/incomplete as appropriate.
- Matching rules append evidence, recommended actions and previously unseen MITRE technique IDs. These are report recommendations; no sender blocking or message deletion is performed automatically.

Numeric risk and the verdict label are never lowered. Defender events alone are not separately given a risk floor; scoring currently consumes rule matches.

Raw Sysmon XML is retained under `backend/sandbox/work/<job_id>/sysmon.xml` by default. Host sample files are deleted after processing. There is no implemented retention policy for XML/work directories, no durable queue and no automatic screenshot capture. `take_screenshot()` exists but is not called by the worker. Process/Defender evidence is stored in the result document, not automatically packaged into a separate evidence bundle.

## 10. Running and retesting

### Normal dashboard workflow

Start from the repository root. The project launcher can start both services:

```powershell
.\start-local.cmd
```

Alternatively, if the services are stopped, run these in two terminals:

```powershell
# Terminal 1, initially at the repository root
cd backend
..\.venv\Scripts\python.exe -m uvicorn app:app --host 127.0.0.1 --port 5000
```

```powershell
# Terminal 2, initially at the repository root
cd frontend
npm run dev -- --host 127.0.0.1
```

If these ports are already serving E-TAP, reuse them rather than starting a second backend. Open `http://127.0.0.1:5173/`, return to the upload screen and upload the **original** `T3_zip_invoice_js.eml` again. Expect queued/start/interaction/collection/evaluation/restore phases, then the evidence above. Local health is `http://127.0.0.1:5000/health`; a dossier deep link is `http://127.0.0.1:5173/?dossier=<email_id>`.

Do not boot/reset the guest manually while a job is active. Run only **one backend worker/process** for this VM: the queue and lock are per process, not a machine-wide lock. A separate CLI smoke process must not run while a backend VM job is active. Restarting uvicorn interrupts in-memory jobs; active persisted statuses without a live job are reported as interrupted and require re-upload. Restart the backend after changing cached rules or environment settings.

### Configuration

Root `.env` is loaded by `app.py` independently of cwd, without overriding explicit process environment variables. Keep real credentials in the local environment; do not put them in this guide or in guest sample files.

```dotenv
SANDBOX_BACKEND=virtualbox
VBOXMANAGE_PATH=C:\Program Files\Oracle\VirtualBox\VBoxManage.exe
SANDBOX_VM_NAME=win 11
SANDBOX_SNAPSHOT=clean
SANDBOX_GUEST_USER=<configured guest account>
SANDBOX_GUEST_PASSWORD=<configured guest password>
SANDBOX_DWELL_SECONDS=30
# Optional: relative values resolve from repository root, not backend cwd.
# SANDBOX_WORK_DIR=backend/sandbox/work
# SANDBOX_RULES_DIR=backend/sandbox/rules
```

`SANDBOX_BACKEND=virtualbox` uses the live worker. `replay` evaluates recorded Sysmon traces from `backend/sandbox/replays`, labels results as recorded, and does not prove live VM operation; fixture traces must actually exist. `none` disables live submission; the pipeline marks sandbox Stage S unavailable. Real database persistence requires configured MongoDB; `USE_FAKE_DB=1` uses temporary process-local storage that disappears on shutdown.

The local frontend now uses the presentation from the sibling deployment project (`E-TAP/frontend`), while retaining the sandbox panel, live polling, observed processes, Defender evidence and terminal-history updates. Optional hosted workflows/workspace controls are shown only when the connected API exposes their required routes; this frontend update does not replace the local backend.

The Vite proxy forwards `/analyze`, `/health`, `/chat`, `/investigations`, `/sandbox` and `/openapi.json` to the configured local backend (`ETAP_BACKEND_URL`, default port 5000). The local connection check uses `/health`, and `/openapi.json` is used to identify optional frontend capabilities.

### Offline regressions

From the repository root:

```powershell
.\.venv\Scripts\python.exe -m unittest discover -s backend/tests -p test_sandbox.py -v
```

The existing **18 tests** cover paths/copies/argument encoding, ZIP bounds/provenance, GUID attribution, a synthetic certutil-rule assertion, lifecycle recovery, payload-free status snapshots, missing apps/telemetry, unique sample names and Defender correlation. They mock guest execution; they do not launch samples or reset VirtualBox. They are not seven positive/negative custom-rule test pairs.

### Opt-in live smoke test

Wait until other VM jobs finish. From the repository root:

```powershell
.\.venv\Scripts\python.exe backend\tests\run_sandbox_smoke.py --email "C:\Users\Krish Anand\Downloads\T3_zip_invoice_js.eml" --allow-vm-reset --expect-blocked-target certutil.exe
```

This creates an in-process FastAPI TestClient and isolated fake DB, disables live threat intelligence/Gemini, uses fallback embeddings, and sets a 10-second dwell for the test. The VM itself is real and is restored before/after sample execution. It validates API ingestion, asynchronous progress, nonzero telemetry, loaded rules, expected Defender evidence, terminal state and both report/status endpoints. The JSON report is written to `.local/sandbox-smoke.json`; it is not inserted into the running dashboard's real database.

For a different fixture that should really spawn a child, `--expect-process <name.exe>` asserts its observed process record. Do not use that assertion for a child that Defender blocks before creation. A successful test ends with `PASS`. The earlier end-to-end check against the real server persisted `.local/sandbox-server-report.json`; this is local verification evidence, not a committed fixture.

## 11. Fixed failures, remaining work and extension scope

The invoice investigation exposed and fixed these implementation faults:

- Relative/cwd-dependent host file transfers caused `VERR_PATH_NOT_FOUND`; configured paths are anchored and copy paths are absolute.
- Incorrect executable quoting/duplicated positional executable arguments prevented the interpreter from starting; executables now receive separate arguments.
- ZIPs were selected without unpacking children; bounded ZIP selection now supplies executable child samples.
- Invisible WScript dialogs concealed script errors; console scripting exposes stderr.
- Failed items were published as a completed job, and active state was not consistently reflected by both APIs; lifecycle/status handling now records failures and waits for restore.
- Frontend refresh could overwrite the original email view or retain queued history; targeted updates preserve the body and persist terminal results.
- A guest `Permission denied` needed to be interpreted with Defender evidence, not assumed to be another copy/launch failure.

Remaining limitations/work:

1. Fix and test `etap-002`; add positive and negative synthetic tests for **every** custom rule. No live claims yet for custom rules 003/005/006/007.
2. Add application detection/launchers and actual UI interaction for Office, PDF, HTML, SVG, OneNote and nested mail. The current worker does not install these apps or automate clicks/scrolling/dialogs.
3. Add bounded support for other archives, nested/encrypted content and document embedded objects. Keep unsupported content visibly incomplete.
4. Add stronger security-event correlation, richer telemetry/coverage diagnostics and metadata review. Full Elastic-only rules, temporal EQL sequences, browser DOM/JS behavior and in-memory exploits are not covered by the current converter/evaluator.
5. Add network simulation if required. The current guest has no external connectivity and there is no DNS/HTTP sinkhole or C2 emulator. Do not present a failed network attempt as a successful connection/download.
6. Add machine-wide VM coordination, durable jobs/recovery, evidence retention and per-sample reset if needed. Current serialization is in one Python process only.
7. Raw-message Gmail extension work remains pending: `extension/content.js` supplies scraped sender/subject/body, and `background.js` constructs a synthetic text-only email and posts it to its configured hosted backend. It does not fetch original Gmail MIME headers/attachment bytes or poll local sandbox results. A dashboard upload of the original `.eml` is the verified attachment-ingestion path. A future raw-message integration must be labelled and tested as a separate change.

The former static-lane/Gmail/OAuth roadmap was a proposal, not evidence of implemented features. This document describes the current local sandbox; inspect linked sources before changing behavior and keep future verification claims tied to actual test outputs.
