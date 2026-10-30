# E-TAP behaviour rules

63 detection rules for the sandbox (stage S). Every rule is written by the E-TAP team, is licensed MIT like the rest of the project, and can be evaluated by our engine ([`../rule_engine.py`](../rule_engine.py)). Each file also carries its own tests.

## Where the rules come from

- **Written from public descriptions, not copied.** The rules are authored from [MITRE ATT&CK](https://attack.mitre.org/) technique descriptions and Microsoft's [Sysmon event documentation](https://learn.microsoft.com/sysinternals/downloads/sysmon). We looked at [Atomic Red Team](https://github.com/redcanaryco/atomic-red-team) (MIT licence, Copyright (c) 2018 Red Canary, Inc.) to see what these techniques look like on a real command line, such as the arguments of `vssadmin`, `regsvr32` or `procdump`. No Atomic Red Team file and no text from any other rule collection is included here.
- **History.** Until 2026-10-31 this folder also held 157 rules taken from a third-party collection published under the Elastic License v2, which is not an open-source licence in the OSI sense. They were removed to keep the project cleanly MIT (a choice first made in a sibling copy of the project and adopted here). 128 of the 164 rules then in the folder could never run in our engine anyway, because they needed telemetry E-TAP does not collect.
- `etap-001` to `etap-007` are the original in-house rules. `etap-002` (Defender service tampering) had a malformed query and was silently skipped until 2026-10-25; it loads and is tested now. `etap-008` to `etap-053` came from a sibling copy of the project, and `etap-054` to `etap-063` were added on 2026-10-31.

## How severity works

- **High** (`[[actions]] action = "kill_process"` in the file) means the behaviour is very rarely benign. A High match raises the report's risk score to **at least 85** and the evidence line is marked prevention-grade.
- **Medium** (no action) means suspicious and worth a look. A Medium match raises the score to **at least 65**.
- The sandbox can only raise a score, never lower it, and "no rule matched" is reported as *inconclusive*, never as safe.

Today 27 rules are High and 36 are Medium.

## What the rules can see

Rules run only on events from the sample's own process tree. These Sysmon events are converted by [`../ecs_convert.py`](../ecs_convert.py):

| Sysmon event | Rule category | Main fields |
|---|---|---|
| 1 Process create | `process` | `process.name`, `.command_line`, `.executable`, `.parent.name`, `.pe.original_file_name` |
| 3 Network connect | `network` | `destination.ip`, `destination.port` (number), `destination.domain` |
| 7 Image load | `library` | `dll.path`, `dll.signed` |
| 8 Remote thread | `thread` | `target.process.name` |
| 10 Process access | `process_access` | `target.process.name`, `process_access.granted_access` |
| 11 File create | `file` | `file.path`, `file.extension` |
| 13 Registry value set | `registry` | `registry.path`, `registry.data.strings` |
| 17 / 18 Named pipe | `pipe` | `pipe.name` |
| 22 DNS query | `dns` | `dns.question.name` |
| 25 Process tampering | `tamper` | `tamper.type` |

Events 7, 8, 10, 17/18 and 25 only exist if the VM's Sysmon configuration logs them. If it does not, the rules that use them simply never fire; the rest are unaffected. These new event paths are covered by tests with synthetic Sysmon XML and have **not** yet been confirmed on a real VM.

## Rule file format

```toml
[rule]
id = "etap-0NN"            # next free number
name = "Plain-language name"
description = "One sentence a non-expert can read."
version = "1"
author = "E-TAP team"
license = "MIT"
os_list = ["windows"]
query = '''process where
  process.name in~ ("example.exe")
  and process.command_line : ("--bad-flag")
'''

[[actions]]                # leave out for a Medium rule
action = "kill_process"

[[threat]]
tactic.name = "Execution"
[[threat.technique]]
id = "T1059.001"
name = "Command and Scripting Interpreter: PowerShell"

[[tests]]                  # at least one "match" and one "no_match"
name = "what this event is"
expect = "match"
event = { _category = "process", process = { name = "example.exe", command_line = "example.exe --bad-flag" } }
```

Query notes: `:` is a case-insensitive substring/wildcard match, `in~` is a case-insensitive exact match (use it for program names), `==` and `in` are case-sensitive. Windows paths need doubled backslashes inside the query (`"\\Temp\\"`). Run `python -m pytest backend/tests/test_sandbox_rules.py` after adding a rule: it checks the file loads, has ATT&CK mapping and licence, and passes its own tests.

Do not copy rules from other collections. Check the licence first, and if in doubt write the rule from the ATT&CK technique page instead.

## Catalogue

Coverage by ATT&CK tactic: Defense Evasion (22), Execution (11), Persistence (10), Command and Control (9), Impact (3), Credential Access (3), Discovery (3), Privilege Escalation (1), Collection (1).

| ID | Rule | Event | Severity | ATT&CK |
|---|---|---|---|---|
| etap-001 | Ingress Transfer via Windows Utility | process | High | T1105 |
| etap-002 | Attempt to Disable Windows Defender Services | process | High | T1562.001 |
| etap-003 | Suspicious Script Interpreter Spawned by Office Application | process | High | T1204.002, T1059 |
| etap-004 | Suspicious Script Host Execution of Script File | process | High | T1059.005, T1059.007 |
| etap-005 | File Dropped in Startup or AutoRun Location | file | High | T1547.001 |
| etap-006 | DNS Query by Unusual Process | dns | Medium | T1071.001 |
| etap-007 | Registry Modification for Persistence | registry | Medium | T1547.001 |
| etap-008 | Encoded PowerShell Command | process | Medium | T1059.001, T1027 |
| etap-009 | PowerShell Download Cradle | process | High | T1059.001, T1105 |
| etap-010 | PowerShell Hidden Window With Policy Bypass | process | Medium | T1059.001, T1564.003 |
| etap-011 | Script Host Spawns a Command Shell | process | Medium | T1059.003, T1059.001 |
| etap-012 | MSHTA Running a Remote or Inline Script | process | High | T1218.005 |
| etap-013 | Regsvr32 Running a Scriptlet | process | High | T1218.010 |
| etap-014 | Rundll32 Running Script or a User-Folder Library | process | Medium | T1218.011 |
| etap-015 | WMIC Creating a Process or Running an XSL Script | process | Medium | T1047, T1220 |
| etap-016 | Developer or Installer Tool Used as a Proxy | process | Medium | T1127.001, T1218.004, T1218.003 |
| etap-017 | BITS Job Used to Transfer a File | process | Medium | T1197, T1105 |
| etap-018 | curl or wget Downloading From a Web Address | process | Medium | T1105 |
| etap-019 | Shadow Copy or Backup Deletion | process | High | T1490 |
| etap-020 | Windows Event Log Cleared | process | High | T1070.001 |
| etap-021 | Windows Defender Exclusion Added | process | High | T1562.001 |
| etap-022 | Windows Firewall Disabled | process | High | T1562.004 |
| etap-023 | Windows Tool Renamed to Hide It | process | High | T1036.003 |
| etap-024 | Program Started From a User-Writable Folder | process | Medium | T1204.002, T1036.005 |
| etap-025 | File Hidden With System and Hidden Attributes | process | Medium | T1564.001 |
| etap-026 | UAC Bypass Through a Registry Hijack | registry | High | T1548.002 |
| etap-027 | Windows Defender Disabled in the Registry | registry | High | T1562.001 |
| etap-028 | AMSI Bypass in a PowerShell Command | process | High | T1562.001 |
| etap-029 | Unsigned Library Loaded From a User-Writable Folder | library | Medium | T1574.002, T1129 |
| etap-030 | Downloaded-File Warning (Mark of the Web) Removed | process | Medium | T1553.005 |
| etap-031 | Scheduled Task Created | process | Medium | T1053.005 |
| etap-032 | Windows Service Created or Repointed | process | Medium | T1543.003 |
| etap-033 | WMI Event Subscription Persistence | process | High | T1546.003 |
| etap-034 | Logon or Debugger Registry Hijack | registry | High | T1546.012, T1547.004, T1546.010 |
| etap-035 | COM Object Hijack in the User Registry | registry | Medium | T1546.015 |
| etap-036 | File Dropped in an Office Startup Location | file | Medium | T1137.001, T1137.006 |
| etap-037 | Executable or Script Dropped by a Script Host or Office | file | Medium | T1105, T1204.002 |
| etap-038 | LSASS Memory Read by Another Process | process_access | High | T1003.001 |
| etap-039 | Credential Dumping Command | process | High | T1003.001, T1003.002, T1003.003 |
| etap-040 | Stored Credentials Listed or Browser Passwords Copied | process | Medium | T1555.004, T1555.003 |
| etap-041 | Domain, Trust or Privilege Enumeration | process | Medium | T1087.002, T1482, T1033 |
| etap-042 | Installed Security Software Queried | process | Medium | T1518.001 |
| etap-043 | Process Image Replaced (Hollowing or Herpaderping) | tamper | High | T1055.012, T1055 |
| etap-044 | External IP Address Lookup | dns | Medium | T1016.001 |
| etap-045 | Lookup of a Dynamic DNS or Tunnelling Service | dns | Medium | T1568, T1572 |
| etap-046 | Lookup of a Paste, Chat-Bot or File-Sharing Service | dns | Medium | T1102, T1567.002 |
| etap-047 | Lookup of a Tor or Onion Service | dns | Medium | T1090.003 |
| etap-048 | Connection to a Common Backdoor Port | network | Medium | T1571 |
| etap-049 | Script Engine or Windows Tool Making a Network Connection | network | Medium | T1071.001, T1105 |
| etap-050 | Command-and-Control Style Named Pipe | pipe | High | T1559 |
| etap-051 | Remote Thread Injected Into Another Process | thread | High | T1055 |
| etap-052 | Disk Image (ISO, IMG or VHD) Mounted by a Script or Program | process | Medium | T1553.005 |
| etap-053 | Clipboard Contents Read by a Script | process | Medium | T1115 |
| etap-054 | Certutil Decoding a File | process | Medium | T1140 |
| etap-055 | Msiexec Installing a Package From the Internet | process | Medium | T1218.007 |
| etap-056 | Local User Account Created | process | Medium | T1136.001 |
| etap-057 | User Added to a Privileged Local Group | process | Medium | T1098 |
| etap-058 | PDF Reader Starting a Shell or Script Host | process | High | T1204.002, T1059 |
| etap-059 | Program Run Straight From an Opened Archive | process | Medium | T1204.002 |
| etap-060 | File With a Disguised Double Extension Created | file | Medium | T1036.007 |
| etap-061 | File Renamed With a Ransomware Extension | file | High | T1486 |
| etap-062 | Ransom Note File Created | file | High | T1486 |
| etap-063 | Windows System Process Running From the Wrong Place | process | High | T1036.005 |
