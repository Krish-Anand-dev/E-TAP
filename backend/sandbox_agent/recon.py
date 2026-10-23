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
import sys
from dataclasses import dataclass
from pathlib import Path

from .vbox import default_vboxmanage, list_snapshots, list_vms, vboxmanage_version, VBoxError


@dataclass
class Check:
    name: str
    ok: bool
    detail: str


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
