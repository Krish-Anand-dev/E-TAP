# E-TAP Sandbox Agent

The agent lets E-TAP run a **deeper attachment analysis** on a virtual machine you own. It runs on your Windows PC next to VirtualBox. Each attachment you choose to check is opened inside your VM's clean snapshot, and only what Windows recorded is sent back to E-TAP. The VM is restored to its clean snapshot after every run.

The agent only makes outbound HTTPS requests to the E-TAP server. Nothing connects in to your computer.

## What you need
- Windows 10 or 11 with **Python 3.10+** (from python.org; tick "Add to PATH").
- **VirtualBox** with a dedicated Windows VM that has:
  - Sysmon installed;
  - Guest Additions installed;
  - a local user with a password;
  - a snapshot taken in a clean state (for example `clean`).

  Use a VM kept only for this, never your everyday one.
- Windows Sandbox (Windows Pro) support is planned. It is not needed today.

## Start
1. Unzip the download and double-click `start-agent.cmd`. You can also run it from a terminal:
   ```
   python -m sandbox_agent
   ```
2. The agent checks the computer for VirtualBox and your VMs. It asks before each step, then asks which VM, snapshot and guest login to use, and shows a read-only checklist of the VM's isolation settings with a fix for anything that is not right (warnings never stop setup; run `check` to see it again). The password is stored protected by Windows for your user only.
3. It shows a pairing code such as `K7QM-4XPN`. In the Gmail extension choose **Deeper attachment analysis → Pair your sandbox** and enter the code. You can also enter it on the dashboard's **Settings** page. The extension then shows **Your sandbox: online**.
4. Leave the agent window open. When you ask for a deeper analysis, it collects the job, runs it and uploads the result, and the report updates by itself.

Pairing happens once. Next time, `start-agent.cmd` goes straight to waiting for jobs.

## Commands
| Command | What it does |
|---|---|
| `start` (default) | Set up if needed, pair if needed, then wait for jobs |
| `setup` | Check this computer and choose the VM again |
| `pair` | Show a new pairing code (for example to pair the dashboard too) |
| `run` | Wait for jobs |
| `check` | Read-only preflight, VM not started: VirtualBox, snapshot, VM isolation (network, clipboard, drag and drop, shared folders), Hyper-V warning, each with a one-line fix |
| `test` | Restore the VM once, check the guest login and Sysmon, and restore it again |
| `status` | Show the saved settings and pairing state |
| `forget` | Delete the saved settings |

Options:
- `--server URL` points the agent at another E-TAP server, for example `http://127.0.0.1:5000` for a local backend.
- `--from-env PATH` reads the VM settings from an existing E-TAP `.env` file.
- `--once` exits after one job.

Settings are saved in `%APPDATA%\E-TAP Sandbox Agent\config.json`.

## Limits
- Up to 3 attachments per email, 10 MB each. Script and executable types are opened first, and ZIP members are opened one by one.
- Office documents and anything that waits for a click usually come back **inconclusive**: nothing clicks inside the document yet.
- A result of "no behaviour observed" never lowers E-TAP's risk score. Matched behaviour can only raise it.
