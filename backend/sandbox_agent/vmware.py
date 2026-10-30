"""
sandbox_agent.vmware -- VMware Workstation Pro VM control via vmrun.
====================================================================
The same job as vbox.VBox, for a VM managed by VMware Workstation: restore the
clean snapshot, start the VM without a window, copy files in and out, run
programs inside Windows and read what they printed. runner.py works with
either provider.

Differences from VirtualBox worth knowing:
  * A VM is identified by the path of its .vmx file, not a name.
  * Running programs inside the guest needs VMware Tools in the VM and the
    Windows user name and password (vmrun -gu / -gp).
  * `vmrun runProgramInGuest` does not return what the program printed, so every
    captured command runs through a small PowerShell wrapper that writes the
    output and exit code to a file in the guest, which is then copied back.
  * Reverting a snapshot taken while the VM was running can leave the VM
    suspended; start() resumes it.
"""

from __future__ import annotations

import base64
import json
import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
import uuid
from pathlib import Path

from .vbox import GuestLoginError, GuestProcessTimeout, VBoxError, is_login_failure

logger = logging.getLogger("E-TAP.sandbox.vmware")

POWERSHELL = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"
CMD = r"C:\Windows\System32\cmd.exe"
GUEST_OUT = "C:\\sandbox\\out"


class VMwareError(VBoxError):
    """Raised when a vmrun command fails (a VBoxError so runner.py handles both providers alike)."""


def _registry_install_dirs() -> list[str]:
    """Where the VMware installer says Workstation (or Player) is installed; works for custom folders."""
    if sys.platform != "win32":
        return []
    try:
        import winreg
    except ImportError:
        return []
    dirs: list[str] = []
    for view in (winreg.KEY_WOW64_64KEY, winreg.KEY_WOW64_32KEY):
        for product in ("VMware Workstation", "VMware Player"):
            try:
                with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, rf"SOFTWARE\VMware, Inc.\{product}", 0,
                                    winreg.KEY_READ | view) as key:
                    dirs.append(str(winreg.QueryValueEx(key, "InstallPath")[0]))
            except OSError:
                continue
    return dirs


def default_vmrun() -> str:
    """vmrun.exe from VMRUN_PATH, the installer's registered folder, the PATH, or the usual install folders."""
    configured = os.getenv("VMRUN_PATH")
    if configured:
        return configured
    for folder in _registry_install_dirs():
        candidate = Path(folder) / "vmrun.exe"
        if candidate.exists():
            return str(candidate)
    found = shutil.which("vmrun")
    if found:
        return found
    for variable in ("ProgramFiles(x86)", "ProgramFiles"):
        base = os.getenv(variable)
        if base:
            candidate = Path(base) / "VMware" / "VMware Workstation" / "vmrun.exe"
            if candidate.exists():
                return str(candidate)
    return r"C:\Program Files (x86)\VMware\VMware Workstation\vmrun.exe"


def _host_type() -> str:
    return os.getenv("VMRUN_HOST_TYPE", "ws")


def _ps_literal(text: str) -> str:
    return "'" + text.replace("'", "''") + "'"


def _quote_arg(arg: str) -> str:
    """One argument of a Windows command line (for Start-Process -ArgumentList)."""
    if arg == "":
        return '""'
    if not re.search(r'[\s"]', arg):
        return arg
    return '"' + arg.replace('"', '\\"') + '"'


def encode_powershell(script: str) -> str:
    return base64.b64encode(script.encode("utf-16le")).decode("ascii")


# Runs one program in the guest and writes {rc, out, err} as JSON, so the host can read it back.
# Placeholders (@@NAME@@) are filled in by VMware._capture_script.
_CAPTURE_TEMPLATE = r"""
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path @@DIR@@ | Out-Null
$o = @@OUT@@; $e = @@ERR@@; $r = @@RES@@
$code = '-1'; $note = ''
try {
  $p = Start-Process -FilePath @@EXE@@ @@ARGLIST@@ -RedirectStandardOutput $o -RedirectStandardError $e -PassThru -WindowStyle Hidden
  $null = $p.Handle
  if ($p.WaitForExit(@@MS@@)) { $code = [string]$p.ExitCode } else { $code = 'timeout' }
} catch { $note = $_.Exception.Message }
$enc = [Text.Encoding]::GetEncoding([Globalization.CultureInfo]::CurrentCulture.TextInfo.OEMCodePage)
function Read-Safe($f) {
  if (-not (Test-Path $f)) { return '' }
  try {
    $s = New-Object IO.FileStream($f, 'Open', 'Read', 'ReadWrite'); $sr = New-Object IO.StreamReader($s, $enc)
    $t = $sr.ReadToEnd(); $sr.Close(); $t
  } catch { '' }
}
$res = @{ rc = $code; out = (Read-Safe $o); err = ((Read-Safe $e) + $note) }
[IO.File]::WriteAllText($r, ($res | ConvertTo-Json -Compress), (New-Object Text.UTF8Encoding $false))
"""


class VMware:
    """Controls a VMware Workstation VM through vmrun. Mirrors vbox.VBox."""

    def __init__(self, vm: str | None = None, snapshot: str | None = None,
                 user: str | None = None, password: str | None = None,
                 dwell: int | None = None, exe: str | None = None):
        self.exe = exe or default_vmrun()
        self.vm = vm or os.environ["SANDBOX_VMX"]          # path of the .vmx file
        self.snap = snapshot or os.getenv("SANDBOX_SNAPSHOT", "clean")
        self.user = user or os.environ["SANDBOX_GUEST_USER"]
        self.pw = password if password is not None else os.environ["SANDBOX_GUEST_PASSWORD"]
        self.dwell = int(dwell if dwell is not None else os.getenv("SANDBOX_DWELL_SECONDS", "30"))

    # -- vmrun plumbing --------------------------------------------------------------

    def _run(self, *args, timeout: int = 180, check: bool = True) -> subprocess.CompletedProcess:
        """Run one vmrun command (authentication flags first, as vmrun requires)."""
        cmd = [self.exe, "-T", _host_type(), "-gu", self.user, "-gp", self.pw] + [str(a) for a in args]
        logger.debug("vmrun %s", " ".join(str(a) for a in args[:2]))
        try:
            p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        except subprocess.TimeoutExpired:
            raise VMwareError(f"vmrun {args[0]} timed out after {timeout}s") from None
        except FileNotFoundError:
            raise VMwareError(f"vmrun not found at {self.exe}") from None
        if check and p.returncode != 0:
            err = ((p.stdout or "") + " " + (p.stderr or "")).strip()[:500]
            if is_login_failure(err):
                raise GuestLoginError(f"Windows in the VM rejected the user name or password for '{self.user}'.")
            raise VMwareError(f"vmrun {args[0]} failed: {err}")
        return p

    def running(self) -> bool:
        return _same_path(self.vm, running_vms(self.exe))

    def poweroff(self) -> None:
        """Power the VM off if it is running; wait until it has stopped."""
        if not self.running():
            return
        self._run("stop", self.vm, "hard", timeout=120)
        for _ in range(30):
            if not self.running():
                return
            time.sleep(1)
        raise VMwareError("VM did not stop within 30s after power off")

    def restore(self) -> None:
        """Revert to the clean snapshot (powers off first)."""
        logger.info("Reverting VM '%s' to snapshot '%s'", self.vm, self.snap)
        self.poweroff()
        time.sleep(1)
        self._run("revertToSnapshot", self.vm, self.snap, timeout=240)

    def start(self) -> None:
        """Start (or resume) the VM without opening a window."""
        if self.running():
            return
        logger.info("Starting VM '%s' without a window", self.vm)
        try:
            self._run("start", self.vm, "nogui", timeout=240)
        except VMwareError as exc:
            if "unknown error" in str(exc).lower():
                # vmrun's own message says nothing. Seen when VMware's authorization service was not
                # running (for example its drive was not connected when Windows started).
                raise VMwareError(
                    "VMware could not start the VM (vmrun only said 'Unknown error'). Check that the "
                    "'VMware Authorization Service' is running in Windows Services and that the drive VMware is "
                    "installed on is connected, then try again.") from None
            raise

    def wait_ready(self, limit: int = 240) -> bool:
        """Wait until VMware Tools answer and Windows accepts the guest login."""
        logger.info("Waiting for the guest to become ready (limit: %ds)", limit)
        started = time.time()
        rejected = 0
        last = ""
        while time.time() - started < limit:
            try:
                self._run("runProgramInGuest", self.vm, CMD, "/d", "/c", "exit", "0", timeout=60)
                logger.info("Guest ready after %.1fs", time.time() - started)
                return True
            except GuestLoginError:
                # One rejection can happen while Windows is still starting; two in a row is a wrong password.
                rejected += 1
                if rejected >= 2:
                    raise GuestLoginError(
                        f"Windows in the VM rejected the user name or password for '{self.user}'.") from None
            except Exception as exc:
                rejected = 0
                last = str(exc)[:200]
            time.sleep(3 if rejected else 5)
        hint = " VMware Tools must be installed and running in the VM." if "tools" in last.lower() or not last else ""
        raise TimeoutError(f"Guest did not become ready within {limit}s.{hint}")

    # -- files -----------------------------------------------------------------------

    def make_dirs(self, *dirs: str) -> None:
        """Create guest folders (and their parents)."""
        listing = ", ".join(_ps_literal(d) for d in dirs)
        script = ("$ErrorActionPreference = 'Stop'; foreach ($d in @(" + listing + ")) "
                  "{ New-Item -ItemType Directory -Force -Path $d | Out-Null }")
        self._run("runProgramInGuest", self.vm, POWERSHELL, "-NoProfile", "-NonInteractive",
                  "-EncodedCommand", encode_powershell(script), timeout=120)

    def copy_to(self, host_file: str, guest_dir: str) -> None:
        """Copy a file from the host into a guest folder."""
        host_file = str(Path(host_file).resolve(strict=True))
        guest_path = guest_dir.rstrip("\\") + "\\" + os.path.basename(host_file)
        logger.debug("Copying %s -> guest:%s", os.path.basename(host_file), guest_path)
        self._run("CopyFileFromHostToGuest", self.vm, host_file, guest_path, timeout=300)

    def copy_from(self, guest_file: str, host_dest: str) -> None:
        """Copy a file from the guest to the host. host_dest is the destination FILE path."""
        logger.debug("Copying guest:%s -> %s", guest_file, host_dest)
        self._run("CopyFileFromGuestToHost", self.vm, guest_file, str(Path(host_dest).resolve()), timeout=600)

    # -- running programs ------------------------------------------------------------

    def _capture_script(self, exe: str, args: tuple, timeout_s: int, run_id: str) -> str:
        base = f"{GUEST_OUT}\\vmrun-{run_id}"
        arglist = " ".join(_quote_arg(str(a)) for a in args)
        values = {
            "DIR": _ps_literal(GUEST_OUT),
            "OUT": _ps_literal(base + ".out"), "ERR": _ps_literal(base + ".err"), "RES": _ps_literal(base + ".json"),
            "EXE": _ps_literal(exe), "MS": str(int(timeout_s * 1000)),
            "ARGLIST": f"-ArgumentList {_ps_literal(arglist)}" if arglist else "",
        }
        script = _CAPTURE_TEMPLATE
        for key, value in values.items():
            script = script.replace(f"@@{key}@@", value)
        return script

    def run_exe(self, exe: str, *args, timeout_s: int = 60) -> subprocess.CompletedProcess:
        """Run a program in the guest and return its exit code, stdout and stderr.

        Raises GuestProcessTimeout if it was still running after `timeout_s`; the
        program is left running (the run ends by restoring the snapshot).
        """
        run_id = uuid.uuid4().hex[:10]
        script = self._capture_script(exe, args, timeout_s, run_id)
        encoded = encode_powershell(script)
        if len(encoded) > 30000:
            raise VMwareError("The command is too long to send to the guest.")
        self._run("runProgramInGuest", self.vm, POWERSHELL, "-NoProfile", "-NonInteractive",
                  "-EncodedCommand", encoded, timeout=timeout_s + 120)
        with tempfile.TemporaryDirectory(prefix="etap-vmrun-") as tmp:
            result_file = Path(tmp) / "result.json"
            self.copy_from(f"{GUEST_OUT}\\vmrun-{run_id}.json", str(result_file))
            try:
                data = json.loads(result_file.read_text(encoding="utf-8-sig"))
            except (OSError, ValueError) as exc:
                raise VMwareError(f"Could not read the result of a guest command: {exc}") from None
        rc = str(data.get("rc", "-1"))
        out, err = data.get("out") or "", data.get("err") or ""
        if rc == "timeout":
            raise GuestProcessTimeout(f"VERR_TIMEOUT: {os.path.basename(exe)} still running after {timeout_s}s")
        try:
            code = int(rc)
        except ValueError:
            code = -1
        return subprocess.CompletedProcess([exe, *args], code, out, err)

    def run_cmd(self, command: str, timeout_s: int = 60) -> subprocess.CompletedProcess:
        """Run a cmd.exe /c command inside the guest."""
        literal = command.replace("'", "''")
        return self.run_cmd_ps(f"& $env:ComSpec /d /s /c '{literal}'; exit $LASTEXITCODE", timeout_s)

    def run_cmd_quiet(self, command: str, timeout_s: int = 60) -> subprocess.CompletedProcess:
        """Run a cmd.exe command (output is still captured here)."""
        return self.run_exe(CMD, "/d", "/c", command, timeout_s=timeout_s)

    def run_cmd_ps(self, command: str, timeout_s: int = 60) -> subprocess.CompletedProcess:
        """Run a PowerShell command inside the guest."""
        return self.run_exe(POWERSHELL, "-NoProfile", "-NonInteractive", "-EncodedCommand",
                            encode_powershell(command), timeout_s=timeout_s)

    def export_sysmon(self, guest_output: str = r"C:\sandbox\out\sysmon.xml") -> str:
        """Export the Sysmon event log as XML to a guest file; returns the guest path."""
        ps_cmd = (
            f'wevtutil qe Microsoft-Windows-Sysmon/Operational /f:xml /e:Events '
            f'| Out-File -Encoding utf8 "{guest_output}"; '
            'if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }'
        )
        self.run_cmd_ps(ps_cmd, timeout_s=120)
        return guest_output

    def clear_sysmon(self) -> None:
        """Clear the Sysmon event log."""
        self.run_exe(r"C:\Windows\System32\wevtutil.exe", "cl", "Microsoft-Windows-Sysmon/Operational", timeout_s=30)

    def full_cycle(self) -> "VMware":
        """Restore the snapshot, start the VM and wait until the guest answers."""
        self.restore()
        self.start()
        self.wait_ready()
        return self


# -- read-only helpers (no guest login needed) ----------------------------------------------

def _vmrun_plain(exe: str | None, *args, timeout: int = 60) -> subprocess.CompletedProcess:
    cmd = [exe or default_vmrun(), "-T", _host_type()] + [str(a) for a in args]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def _path_key(path: str) -> str:
    """A .vmx path in a comparable form: Windows paths ignore case and accept either slash."""
    return path.strip().replace("\\", "/").rstrip("/").lower()


def _same_path(path: str, others) -> bool:
    key = _path_key(path)
    return any(_path_key(o) == key for o in others)


def vmrun_version(exe: str | None = None) -> str | None:
    """vmrun's version, or None when vmrun cannot be run."""
    try:
        p = subprocess.run([exe or default_vmrun()], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.TimeoutExpired):
        return None
    match = re.search(r"vmrun version\s+([\w.\-]+)", (p.stdout or "") + (p.stderr or ""), re.I)
    return match.group(1) if match else "installed"


def running_vms(exe: str | None = None) -> list[str]:
    """The .vmx paths of the VMs that are powered on right now."""
    try:
        p = _vmrun_plain(exe, "list")
    except FileNotFoundError:
        raise VMwareError(f"vmrun not found at {exe or default_vmrun()}") from None
    except subprocess.TimeoutExpired:
        raise VMwareError("vmrun list timed out") from None
    if p.returncode != 0:
        raise VMwareError((p.stdout or p.stderr or "vmrun list failed").strip()[:300])
    return [line.strip() for line in (p.stdout or "").splitlines()
            if line.strip() and not line.lower().startswith("total running vms")]


def list_snapshots(vmx: str, exe: str | None = None) -> list[str]:
    """Snapshot names of one VM (empty when it has none or vmrun cannot read it)."""
    try:
        p = _vmrun_plain(exe, "listSnapshots", vmx)
    except (OSError, subprocess.TimeoutExpired):
        return []
    if p.returncode != 0:
        return []
    return [line.strip() for line in (p.stdout or "").splitlines()
            if line.strip() and not line.lower().startswith("total snapshots")]


def read_vmx(path: str) -> dict[str, str]:
    """A .vmx file as {lower-case key: value}. Raises VMwareError when it cannot be read."""
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        raise VMwareError(f"Could not read {path}: {exc}") from None
    values: dict[str, str] = {}
    for line in text.splitlines():
        match = re.match(r'^\s*([^=#\s][^=]*?)\s*=\s*"?(.*?)"?\s*$', line)
        if match:
            values[match.group(1).lower()] = match.group(2)
    return values


def discover_vms() -> dict[str, str]:
    """VMware VMs this user has opened or created: {display name: .vmx path}.

    Looks in Workstation's recent-VM list and in the default "Virtual Machines" folder.
    """
    paths: list[str] = []
    prefs = Path(os.getenv("APPDATA", "")) / "VMware" / "preferences.ini"
    if prefs.is_file():
        try:
            for line in prefs.read_text(encoding="utf-8", errors="replace").splitlines():
                match = re.match(r'^\s*pref\.mruVM\d+\.filename\s*=\s*"(.+?)"\s*$', line, re.I)
                if match:
                    paths.append(match.group(1))
        except OSError:
            pass
    default_dir = Path.home() / "Documents" / "Virtual Machines"
    if default_dir.is_dir():
        paths += [str(p) for p in sorted(default_dir.glob("*/*.vmx"))]
    found: dict[str, str] = {}
    seen: set[str] = set()
    for raw in paths:
        key = _path_key(raw)
        if key in seen or not raw.lower().endswith(".vmx") or not Path(raw).is_file():
            continue
        seen.add(key)
        name = Path(raw).stem
        if name in found:
            name = f"{name} ({Path(raw).parent.name})"
        found[name] = raw
    return found
