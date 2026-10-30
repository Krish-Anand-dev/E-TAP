# E-TAP Sandbox Agent

The agent lets E-TAP run a **deeper attachment analysis** on a virtual machine you own. It runs on your Windows PC next to **VirtualBox or VMware Workstation Pro**. Each attachment you choose to check is opened inside your VM's clean snapshot, and only what Windows recorded is sent back to E-TAP. The VM is restored to its clean snapshot after every run.

The agent only makes outbound HTTPS requests to the E-TAP server. Nothing connects in to your computer.

## What you need
- Windows 10 or 11 with **Python 3.10+** (from python.org; tick "Add to PATH").
- **VirtualBox** or **VMware Workstation Pro** with a dedicated Windows VM that has:
  - Sysmon installed;
  - **Guest Additions** (VirtualBox) or **VMware Tools** (VMware) installed;
  - a local user with a password;
  - a snapshot taken in a clean state (for example `clean`).

  Use a VM kept only for this, never your everyday one. **The agent restores the snapshot after every run, which throws away anything done in the VM since.** A VM you use for other work (for example a security lab) is the wrong choice.
- Windows Sandbox (Windows Pro) and Hyper-V VMs are not supported yet.

### Using VMware Workstation Pro
- **Which one is used.** If VirtualBox is installed, setup uses it by default. For VMware run `start-agent.cmd setup --provider vmware`. If VirtualBox is not installed but VMware is, setup picks VMware by itself.
- **Finding the VM.** Setup lists the VMs from Workstation's recent list and the default `Documents\Virtual Machines` folder, and lets you type the path of any `.vmx` file. `vmrun.exe` is found in the usual VMware folder, on the PATH, or at the path in the `VMRUN_PATH` environment variable.
- **Prepare the VM in Workstation.** Install VMware Tools, take the clean snapshot with Windows signed in, and under *VM → Settings → Options → Guest Isolation* untick copy and paste and drag and drop. Remove the network adapter (or untick *Connected* and *Connect at power on*) and disable shared folders. `check` tells you which of these are still open. Encrypted VMs are not supported, because the agent cannot unlock them unattended.
- **How it differs.** The VM runs without a window. Programs are started through VMware Tools with the Windows user and password you gave setup. VMware cannot hand back what a program printed, so the agent runs each command through a small PowerShell wrapper in the guest that saves the output and exit code to `C:\sandbox\out`, and copies the result back.
- **Status.** This provider is tested against a stand-in for `vmrun` (including the real PowerShell wrapper), but has not yet been run against a real VMware VM. If `test` fails, tell us which step it reached.

## Start
1. Right-click the downloaded zip and choose **Extract All** (running `start-agent.cmd` from inside the zip viewer does not work: it needs the `sandbox_agent` folder next to it). Then open the extracted folder and double-click `start-agent.cmd`. You can also run it from a terminal:
   ```
   python -m sandbox_agent
   ```
2. The agent checks the computer for VirtualBox or VMware Workstation and your VMs. It asks before each step, then asks which VM, snapshot and guest login to use, starts the VM once to confirm Windows accepts the login (a wrong password is refused and asked again, up to three tries), and shows a read-only checklist of the VM's isolation settings with a fix for anything that is not right (warnings never stop setup; run `check` to see it again). The password is stored protected by Windows for your user only.
3. It shows a pairing code such as `K7QM-4XPN`. In the Gmail extension choose **Deeper attachment analysis → Pair your sandbox** and enter the code. You can also enter it on the dashboard's **Settings** page. The extension then shows **Your sandbox: online**.
4. Leave the agent window open. While it runs it re-checks every 20 seconds that VirtualBox or VMware, the VM, the clean snapshot and the login are still fine and reports that, so the dashboard shows *online*, *needs attention* (with the reason) or *offline* truthfully. When you ask for a deeper analysis, it collects the job, runs it and uploads the result, and the report updates by itself.

Pairing happens once. Next time, `start-agent.cmd` goes straight to waiting for jobs.

## Commands
| Command | What it does |
|---|---|
| `start` (default) | Set up if needed, pair if needed, then wait for jobs |
| `setup` | Check this computer and choose the VM again |
| `pair` | Show a new pairing code (for example to pair the dashboard too) |
| `run` | Wait for jobs |
| `check` | Read-only preflight, VM not started: VirtualBox or VMware, snapshot, VM isolation (network, clipboard, drag and drop, shared folders), Hyper-V warning, each with a one-line fix |
| `test` | Restore the VM once, check the guest login and Sysmon, and restore it again |
| `status` | Show the saved settings and pairing state |
| `forget` | Delete the saved settings |

Options:
- `--provider virtualbox|vmware` chooses the hypervisor (used by `setup`; the choice is saved).
- `--server URL` points the agent at another E-TAP server, for example `http://127.0.0.1:5000` for a local backend.
- `--from-env PATH` reads the VM settings from an existing E-TAP `.env` file.
- `--once` exits after one job.

Settings are saved in `%APPDATA%\E-TAP Sandbox Agent\config.json`.

## Keep the VM on a fast disk
Put the VM's files on an SSD, not a USB or external hard drive. On a slow disk Windows inside the VM freezes for a minute at a time, VMware Tools stop answering, and the agent's waits run out ("Guest did not become ready"). One real test on an external USB drive showed about 0.2 seconds per disk operation and exactly that failure. If `vmrun` says "Unknown error" when starting a VM, check that the **VMware Authorization Service** is running in Windows Services and that the drive VMware is installed on is connected.

## Limits
- Up to 3 attachments per email, 10 MB each. Script and executable types are opened first, and ZIP members are opened one by one.
- Office documents and anything that waits for a click usually come back **inconclusive**: nothing clicks inside the document yet.
- Only the events of the attachment's own processes are uploaded, never the whole Sysmon log, and the log is deleted from this PC after each run. If the upload still fails, the agent sends a short note so the report shows the run as incomplete instead of waiting.
- A result of "no behaviour observed" never lowers E-TAP's risk score. Matched behaviour can only raise it.
