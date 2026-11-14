# 2026-10-31: 63 original detection rules and VMware in the agent

## Why
Two things were on the list after the hackathon build was working.
1. The claim "self-made detection rules" rested on seven rules. We wanted an honest, defensible count of at least fifty.
2. The sandbox agent only drove VirtualBox. Plenty of people have VMware Workstation instead.

## How it went (two passes)
**First pass.** The brief was to take both from an older iteration of the project. The folder first pointed at (a GitLab-hackathon copy) turned out to hold neither: the same 164 rule files as ours (157 Elastic and our seven) and no VMware code at all, in the working tree or in any of its 55 commits. So both were written fresh: 43 new rules and a VMware module, tested with synthetic events and a fake `vmrun`.

**Second pass.** The right folder was then pointed at, a sibling copy of the project (`E-TAP-clean`) that already had 53 original MIT rules each carrying its own tests, a VMware provider, an extended rule engine and a fix to the agent download. It had been through more checking than the first-pass work, so we compared and adopted it, keeping what ours added. The first-pass rules and VMware module were replaced; ten of the first-pass rules covered techniques the sibling lacked and were kept in its format.

## What was adopted
- **Rules.** 53 original rules (`etap-001` to `etap-053`, MIT, each with `[[tests]]` events) plus ten of ours (`etap-054` to `etap-063`: certutil decoding, msiexec from the web, local user created, user added to a privileged group, PDF reader starting a shell, program run from an opened archive, disguised double extension, ransomware file extension, ransom note, system process in the wrong folder). 27 are High (score to at least 85), 36 Medium (at least 65). The tests live in the rule files themselves, so a rule cannot be added without a positive and a negative case.
- **Engine and converter.** `ecs_convert.py` and `rule_engine.py` now handle Sysmon events 1, 3, 7 (image load), 8 (remote thread), 10 (process access), 11, 13, 17/18 (named pipes), 22 and 25 (process tampering), carry `destination.port` as a number, and add working directory and integrity level. Events 7, 8, 10, 17/18 and 25 only exist if the VM's Sysmon configuration logs them; where it does not, those rules simply never fire.
- **The Elastic rules were removed.** The 157 third-party rules are under the Elastic License v2, which is not open source and limits offering the software as a hosted service, and 127 of them could never run in our engine anyway (they need telemetry E-TAP does not collect). The remaining 30 were replaced by original rules. This also makes the rule count honest: every rule is ours.
- **VMware.** The sibling's `vmware.py` replaced the first-pass module: `vmrun` is found through the installer's registry entry (a real bug, found on a PC with a custom install drive), a guest PowerShell wrapper captures a program's output, exit code and timeout as JSON, an `Unknown error` from `vmrun start` gets a plain explanation, encrypted VMs are flagged, and the README warns about slow disks and closing the VM window. Setup uses VirtualBox by default, takes `--provider vmware`, and picks VMware by itself when VirtualBox is missing.
- **Agent download.** The agent zip now carries `server_url.txt`, so a downloaded agent pairs with the server it came from (`PUBLIC_API_URL` overrides), which removes the "agent still points at the old backend" class of problem we hit earlier.
- **Kept from ours.** The atomic pairing-code claim and its tests, the Cloudinary store, the pasted-message path, the share card, and our own server address as the fallback.

## What we found on the way
- `etap-002` (disable Windows Defender) had never loaded: a nested `and` the engine cannot read, skipped silently. Both copies fixed it independently.
- The engine matches `:` as a substring and cannot anchor, so exact values use `in` and `in~`.
- `etap-004` fires for any script host run from the sandbox folder. That is how a script attachment is caught and how the earlier live demo matched, so it stays.

## Checks
- `tests/test_sandbox_rules.py` (from the sibling): every rule loads, none is skipped, ids are sequential, each is original and MIT with an ATT&CK mapping, and each passes its own tests.
- `tests/test_sandbox_rules_everyday.py` (ours): a document being opened (Word, PDF reader, browser, a script run) matches none of the 63 rules except the intended etap-004 for a script.
- `tests/test_sandbox_vmware.py` (from the sibling, 43 tests): a fake `vmrun`; the output wrapper is run for real in PowerShell on this PC with the guest folders redirected.
- Backend 306, frontend 26, extension 27 pass.

## Not verified
- The rules have only been tested with synthetic events. The only one seen on a real VM is `etap-004` (the earlier invoice demo). A real run could still show a rule firing on a harmless sample.
- VMware: the sibling tried the read-only parts on a real machine (finding `vmrun`, listing VMs and snapshots, reading a real `.vmx`, a headless start, VMware Tools reporting running, a rejected login reported as one). It never ran a guest command, the PowerShell wrapper or a full job on real VMware, and neither have we.
