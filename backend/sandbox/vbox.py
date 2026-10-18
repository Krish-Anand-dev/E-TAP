"""
sandbox.vbox — VirtualBox VM control via VBoxManage.
=====================================================
Wraps VBoxManage.exe for snapshot restore, start, guestcontrol,
file copy, process execution, and power off.
"""

from __future__ import annotations

import os
import base64
from pathlib import Path
import time
import subprocess
import logging

logger = logging.getLogger("E-TAP.sandbox.vbox")


class VBoxError(Exception):
    """Raised when a VBoxManage command fails."""
    pass


class GuestProcessTimeout(VBoxError):
    """A started guest process reached its observation limit."""


class VBox:
    """Controls a VirtualBox VM through VBoxManage CLI."""

    def __init__(self):
        self.exe = os.getenv(
            "VBOXMANAGE_PATH",
            r"C:\Program Files\Oracle\VirtualBox\VBoxManage.exe"
        )
        self.vm = os.environ["SANDBOX_VM_NAME"]
        self.snap = os.getenv("SANDBOX_SNAPSHOT", "clean")
        self.user = os.environ["SANDBOX_GUEST_USER"]
        self.pw = os.environ["SANDBOX_GUEST_PASSWORD"]
        self.dwell = int(os.getenv("SANDBOX_DWELL_SECONDS", "30"))

    def _run(self, *args, timeout: int = 180, check: bool = True) -> subprocess.CompletedProcess:
        """Execute a VBoxManage command."""
        cmd = [self.exe] + list(args)
        logger.debug("VBoxManage %s", " ".join(args[:4]))
        try:
            p = subprocess.run(
                cmd, capture_output=True, text=True, timeout=timeout
            )
        except subprocess.TimeoutExpired:
            raise VBoxError(f"VBoxManage {args[0]} timed out after {timeout}s")
        except FileNotFoundError:
            raise VBoxError(f"VBoxManage not found at {self.exe}")

        if check and p.returncode != 0:
            err = (p.stderr or p.stdout or "").strip()[:500]
            if "VERR_TIMEOUT" in err and "Reading from guest process" in err:
                raise GuestProcessTimeout(err)
            raise VBoxError(f"VBoxManage {args[0]} failed: {err}")
        return p

    def running(self) -> bool:
        """Check if the VM is currently running."""
        out = self._run("showvminfo", self.vm, "--machinereadable").stdout
        return 'VMState="running"' in out

    def _vm_state(self) -> str:
        """Get the current VM state: 'running', 'saved', 'poweroff', 'aborted', etc."""
        out = self._run("showvminfo", self.vm, "--machinereadable").stdout
        import re
        m = re.search(r'VMState="(\w+)"', out)
        return m.group(1) if m else "unknown"

    def poweroff(self):
        """Power off the VM if running or saved, wait until stopped."""
        state = self._vm_state()
        if state in ("running", "paused", "saved"):
            if state == "saved":
                # Discard saved state to power off
                self._run("discardstate", self.vm)
            else:
                self._run("controlvm", self.vm, "poweroff")
            for _ in range(30):
                if self._vm_state() == "poweroff":
                    return
                time.sleep(1)
            raise VBoxError("VM did not stop within 30s after poweroff")

    def restore(self):
        """Restore the clean snapshot (powers off first if needed)."""
        logger.info("Restoring snapshot '%s' on VM '%s'", self.snap, self.vm)
        self.poweroff()
        time.sleep(1)
        self._run("snapshot", self.vm, "restore", self.snap)
        logger.info("Snapshot restored")

    def start(self):
        """Start the VM in headless mode."""
        logger.info("Starting VM '%s' headless", self.vm)
        self._run("startvm", self.vm, "--type", "headless")

    def _gc(self, verb: str, *rest, timeout: int = 180) -> subprocess.CompletedProcess:
        """Run a guestcontrol command."""
        return self._run(
            "guestcontrol", self.vm, verb,
            "--username", self.user, "--password", self.pw,
            *rest, timeout=timeout
        )

    def wait_ready(self, limit: int = 240) -> bool:
        """
        Wait until the guest is responsive via guestcontrol.
        Returns True if ready, raises TimeoutError if not.
        """
        logger.info("Waiting for guest to become ready (limit: %ds)", limit)
        t = time.time()
        while time.time() - t < limit:
            try:
                result = self._gc(
                    "run", "--exe", r"C:\Windows\System32\cmd.exe",
                    "--timeout", "15000", "--wait-stdout", "--",
                    "/d", "/c", "echo", "ready",
                    timeout=30
                )
                if "ready" in (result.stdout or ""):
                    logger.info("Guest ready after %.1fs", time.time() - t)
                    return True
            except (VBoxError, subprocess.TimeoutExpired):
                pass
            except Exception:
                # Catch "terminated" guest session and other transient errors
                pass
            time.sleep(5)
        raise TimeoutError(f"Guest did not become ready within {limit}s")

    def copy_to(self, host_file: str, guest_dir: str):
        """Copy a file from host to guest. guest_dir must end with backslash."""
        # VBoxManage does not reliably resolve relative host paths on Windows.
        host_file = str(Path(host_file).resolve(strict=True))
        if not guest_dir.endswith("\\"):
            guest_dir += "\\"
        logger.debug("Copying %s -> guest:%s", os.path.basename(host_file), guest_dir)
        self._gc("copyto", "--target-directory", guest_dir, host_file)

    def run_exe(self, exe: str, *args, timeout_s: int = 60) -> subprocess.CompletedProcess:
        """
        Run an executable inside the guest.
        Returns the completed process (stdout/stderr available).
        """
        cmd_args = list(args)
        return self._gc(
            "run", "--exe", exe,
            "--timeout", str(timeout_s * 1000),
            "--wait-stdout", "--wait-stderr",
            "--", *cmd_args,
            timeout=timeout_s + 30
        )

    def run_cmd(self, command: str, timeout_s: int = 60) -> subprocess.CompletedProcess:
        """Run a cmd.exe /c command inside the guest.
        Note: Do NOT use shell redirects (>) when --wait-stdout is active;
        use export_to_guest_file() instead for file output."""
        # Encode the shell command to preserve quotes across VBox's Windows
        # argument serialization. Launch sample executables with run_exe().
        literal = command.replace("'", "''")
        return self.run_cmd_ps(f"& $env:ComSpec /d /s /c '{literal}'; exit $LASTEXITCODE", timeout_s)

    def run_cmd_quiet(self, command: str, timeout_s: int = 60) -> subprocess.CompletedProcess:
        """Run a cmd.exe command without capturing stdout (allows guest-side redirects)."""
        return self._gc(
            "run", "--exe", r"C:\Windows\System32\cmd.exe",
            "--timeout", str(timeout_s * 1000),
            "--", "/d", "/c", command,
            timeout=timeout_s + 30
        )

    def run_cmd_ps(self, command: str, timeout_s: int = 60) -> subprocess.CompletedProcess:
        """Run a PowerShell command inside the guest."""
        # Preserve pipes, quotes and literal paths through Windows argv parsing.
        encoded = base64.b64encode(command.encode("utf-16le")).decode("ascii")
        return self._gc(
            "run", "--exe", r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
            "--timeout", str(timeout_s * 1000),
            "--wait-stdout", "--wait-stderr",
            "--", "-NoProfile", "-NonInteractive", "-EncodedCommand", encoded,
            timeout=timeout_s + 30
        )

    def copy_from(self, guest_file: str, host_dest: str):
        """
        Copy a file from guest to host.
        host_dest is the destination FILE path (not directory).
        """
        logger.debug("Copying guest:%s -> %s", guest_file, host_dest)
        host_dest = str(Path(host_dest).resolve())
        self._gc("copyfrom", guest_file, host_dest)

    def export_sysmon(self, guest_output: str = r"C:\sandbox\out\sysmon.xml") -> str:
        """
        Export the Sysmon event log as XML to a guest file.
        Uses PowerShell Out-File to avoid '>' redirect issues with VBoxManage.
        Returns the guest file path.
        """
        ps_cmd = (
            f'wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:Events '
            f'| Out-File -Encoding utf8 "{guest_output}"; '
            'if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }'
        )
        self.run_cmd_ps(ps_cmd, timeout_s=30)
        return guest_output

    def clear_sysmon(self):
        """Clear the Sysmon event log."""
        self.run_exe(r"C:\Windows\System32\wevtutil.exe", "cl", "Microsoft-Windows-Sysmon/Operational", timeout_s=15)

    def take_screenshot(self, host_dest: str, display: int = 0):
        """Take a screenshot of the VM display."""
        self._run("controlvm", self.vm, "screenshotpng", host_dest)

    def full_cycle(self) -> 'VBox':
        """
        Convenience: restore snapshot -> start -> wait ready.
        Returns self for chaining.
        """
        self.restore()
        self.start()
        self.wait_ready()
        return self
