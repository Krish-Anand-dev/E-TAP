"""
sandbox_agent.recon -- what this computer can offer as a sandbox.
=================================================================
Read-only checks: Windows, Python, VirtualBox and its VMs/snapshots, and
whether Windows Sandbox exists (support for it is planned). Nothing here
starts or changes a VM.
"""

from __future__ import annotations

import os
import platform
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from .vbox import (default_vboxmanage, list_snapshots, list_vms, show_vm_info, vboxmanage_version,
                   VBoxError)


@dataclass
class Check:
    name: str
    ok: bool
    detail: str
    fix: str = ""          # one plain line on how to fix a failed check


def system_checks(vboxmanage: str | None = None) -> tuple[list[Check], list[str]]:
    """(checks, VM names) for this machine."""
    checks = [
        Check("Windows", sys.platform == "win32", platform.platform()),
        Check("Python 3.10 or newer", sys.version_info >= (3, 10), platform.python_version()),
    ]
    exe = vboxmanage or os.getenv("VBOXMANAGE_PATH") or default_vboxmanage()
    version = vboxmanage_version(exe)
    checks.append(Check("VirtualBox", bool(version),
                        f"version {version}" if version else f"VBoxManage not found at {exe}"))
    vms: list[str] = []
    if version:
        try:
            vms = list_vms(exe)
        except VBoxError as exc:
            checks.append(Check("VirtualBox VMs", False, str(exc)))
        else:
            checks.append(Check("VirtualBox VMs", bool(vms), ", ".join(vms) if vms else "no VMs registered for this user"))
    windows_sandbox = Path(os.getenv("SystemRoot", r"C:\Windows")) / "System32" / "WindowsSandbox.exe"
    checks.append(Check("Windows Sandbox (planned)", windows_sandbox.exists(),
                        "available; E-TAP support is planned" if windows_sandbox.exists()
                        else "not installed (needs Windows Pro); not required"))
    return checks, vms


def vm_checks(vm: str, snapshot: str, vboxmanage: str | None = None) -> list[Check]:
    exe = vboxmanage or os.getenv("VBOXMANAGE_PATH") or default_vboxmanage()
    snapshots = list_snapshots(vm, exe)
    return [Check(f"Snapshot '{snapshot}'", snapshot in snapshots,
                  "found" if snapshot in snapshots else
                  ("available: " + ", ".join(snapshots)) if snapshots else "this VM has no snapshots")]


def hypervisor_present() -> bool | None:
    """True when Windows runs with its hypervisor on (Hyper-V, WSL2, Windows Sandbox,
    Memory integrity), which can slow VirtualBox badly. None when it cannot be told."""
    if sys.platform != "win32":
        return None
    try:
        p = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             "(Get-CimInstance Win32_ComputerSystem).HypervisorPresent"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    answer = (p.stdout or "").strip().lower()
    return {"true": True, "false": False}.get(answer)


def hypervisor_check(present: bool | None) -> Check:
    if present is None:
        return Check("Windows virtualisation features", True, "could not be checked; not required")
    if present:
        return Check("Windows virtualisation features", False,
                     "Windows is running with its hypervisor on (Hyper-V, WSL2 or Windows Sandbox). "
                     "VirtualBox still works, but runs can be much slower.",
                     "If runs time out, turn off Hyper-V and Virtual Machine Platform in 'Turn Windows features on or off', then restart.")
    return Check("Windows virtualisation features", True, "hypervisor is off")


def _vm_values(info: str) -> dict[str, str]:
    values: dict[str, str] = {}
    for line in info.splitlines():
        match = re.match(r'^([A-Za-z0-9_\-]+)="?(.*?)"?$', line.strip())
        if match:
            values[match.group(1)] = match.group(2)
    return values


def isolation_checks(info: str) -> list[Check]:
    """How well the VM is cut off from this PC and the network, from `showvminfo --machinereadable`.
    A setting that cannot be read counts as not isolated: unknown is never safe."""
    values = _vm_values(info)
    open_nics = [key for key, value in values.items()
                 if re.fullmatch(r"nic\d+", key) and value != "none"
                 and values.get(key.replace("nic", "cableconnected")) != "off"]
    shared = [key for key in values if key.startswith("SharedFolderNameMachineMapping")]
    clipboard, drag = values.get("clipboard"), values.get("draganddrop")
    return [
        Check("VM network off", not open_nics,
              "no network adapter is connected" if not open_nics else f"{len(open_nics)} network adapter(s) are connected",
              "VirtualBox > the VM > Settings > Network: untick 'Enable Network Adapter', then take a new clean snapshot."),
        Check("VM clipboard sharing off", clipboard == "disabled",
              "disabled" if clipboard == "disabled" else (clipboard or "could not be read"),
              "VirtualBox > Settings > General > Advanced: set Shared Clipboard to Disabled."),
        Check("VM drag and drop off", drag == "disabled",
              "disabled" if drag == "disabled" else (drag or "could not be read"),
              "VirtualBox > Settings > General > Advanced: set Drag'n'Drop to Disabled."),
        Check("VM shared folders off", not shared,
              "none" if not shared else f"{len(shared)} shared folder(s) are set up",
              "VirtualBox > Settings > Shared Folders: remove every folder."),
    ]


def preflight_checks(vm: str, snapshot: str, vboxmanage: str | None = None,
                     hypervisor: bool | None = None) -> list[Check]:
    """Everything that can be checked without starting the VM."""
    exe = vboxmanage or os.getenv("VBOXMANAGE_PATH") or default_vboxmanage()
    checks = vm_checks(vm, snapshot, exe)
    try:
        checks += isolation_checks(show_vm_info(vm, exe))
    except VBoxError as exc:
        checks.append(Check("VM isolation settings", False, str(exc), "Check the VM name, then run setup again."))
    checks.append(hypervisor_check(hypervisor))
    return checks


ENV_KEYS = {
    "SANDBOX_VM_NAME": "name",
    "SANDBOX_SNAPSHOT": "snapshot",
    "SANDBOX_GUEST_USER": "guest_user",
    "SANDBOX_GUEST_PASSWORD": "guest_password",
    "VBOXMANAGE_PATH": "vboxmanage",
    "SANDBOX_DWELL_SECONDS": "dwell_seconds",
    "SANDBOX_PDF_VIEWER": "pdf_viewer",
}


def read_env_file(path: str) -> dict:
    """VM settings from an existing E-TAP .env file (only the sandbox keys are read)."""
    found: dict = {}
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key = key.strip().removeprefix("export ").strip()
        if key in ENV_KEYS:
            value = value.strip()
            if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
                value = value[1:-1]
            found[ENV_KEYS[key]] = value
    return found
