"""VMware Workstation support for the sandbox agent, tested without VMware.

A fake `vmrun` stands in for the real one. Where the VM would run PowerShell, the fake runs the
same script on this PC with the guest folders redirected to a temp directory, so the wrapper that
captures program output, exit codes and timeouts is exercised for real (Windows only).
"""
import base64
import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sandbox_agent import cli, config as cfgmod, recon, runner, vmware  # noqa: E402
from sandbox_agent.vbox import GuestLoginError, GuestProcessTimeout, VBox, VBoxError  # noqa: E402
from sandbox_agent.vmware import VMware, VMwareError  # noqa: E402

REAL_RUN = subprocess.run
ON_WINDOWS = sys.platform == "win32" and shutil.which("powershell") is not None
VMX = r"C:\VMs\sandbox\sandbox.vmx"


class FakeVmrun:
    """Behaves like vmrun.exe for the commands the agent uses. Records every call."""

    def __init__(self, guest_root: Path | None = None):
        self.calls: list[list[str]] = []
        self.running = False
        self.snapshots = ["clean"]
        self.login_ok = True
        self.start_fails = False            # vmrun start answers "Unknown error", as seen on a real install
        self.tools_ready_after = 0          # runProgramInGuest probes that fail before the guest answers
        self.guest_root = guest_root
        self._probes = 0

    def _local(self, guest_path: str) -> str:
        """Map a guest path to the temp directory standing in for the guest's disk."""
        if self.guest_root and guest_path.upper().startswith("C:\\SANDBOX"):
            return str(self.guest_root / guest_path[len("C:\\sandbox\\"):])
        return guest_path

    def __call__(self, cmd, capture_output=True, text=True, timeout=None, **kw):
        self.calls.append([str(c) for c in cmd])
        args = [str(c) for c in cmd[1:]]
        assert args[0] == "-T", "authentication flags must start the command"
        args = args[2:]
        auth = {}
        while args and args[0] in ("-gu", "-gp"):
            flag = args.pop(0)
            auth[flag] = args.pop(0)
        verb, rest = args[0], args[1:]
        ok = lambda out="": subprocess.CompletedProcess(cmd, 0, out, "")  # noqa: E731
        if verb == "list":
            return ok(f"Total running VMs: {1 if self.running else 0}\n" + (VMX + "\n" if self.running else ""))
        if verb == "stop":
            self.running = False
            return ok()
        if verb == "start":
            if self.start_fails:
                return subprocess.CompletedProcess(cmd, 255, "Error: Unknown error", "")
            self.running = True
            return ok()
        if verb == "revertToSnapshot":
            if rest[1] not in self.snapshots:
                return subprocess.CompletedProcess(cmd, 1, "Error: The snapshot does not exist", "")
            return ok()
        if verb == "listSnapshots":
            return ok(f"Total snapshots: {len(self.snapshots)}\n" + "\n".join(self.snapshots) + "\n")
        if verb == "runProgramInGuest":
            if not self.login_ok:
                return subprocess.CompletedProcess(cmd, 1, "Error: Invalid user name or password for the guest OS", "")
            program = rest[1]
            if program.lower().endswith("cmd.exe"):                    # the readiness probe
                self._probes += 1
                if self._probes <= self.tools_ready_after:
                    return subprocess.CompletedProcess(cmd, 1, "Error: The VMware Tools are not running in the virtual machine", "")
                return ok()
            if "-EncodedCommand" in rest:                              # a PowerShell script from the agent
                script = base64.b64decode(rest[rest.index("-EncodedCommand") + 1]).decode("utf-16le")
                if self.guest_root is None:
                    return ok()
                done = REAL_RUN(["powershell", "-NoProfile", "-NonInteractive", "-EncodedCommand",
                                 base64.b64encode(script.encode("utf-16le")).decode("ascii")],
                                capture_output=True, text=True, timeout=120)
                return subprocess.CompletedProcess(cmd, done.returncode, done.stdout, done.stderr)
            return ok()
        if verb in ("CopyFileFromHostToGuest", "CopyFileFromGuestToHost"):
            if self.guest_root is None:      # command-shape tests only: never touch real paths on this PC
                return ok()
            if verb == "CopyFileFromHostToGuest":
                dest = self._local(rest[2])
                Path(dest).parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(rest[1], dest)
            else:
                shutil.copyfile(self._local(rest[1]), rest[2])
            return ok()
        return subprocess.CompletedProcess(cmd, 1, f"Error: unknown command {verb}", "")


def make_vm(fake: FakeVmrun, **kw) -> VMware:
    vm = VMware(vm=VMX, snapshot="clean", user="sandbox", password="secret", dwell=1, exe="vmrun.exe", **kw)
    return vm


class FakeClock:
    """Replaces the `time` module inside sandbox_agent.vmware: every reading moves the clock on, sleeping is free."""

    def __init__(self):
        self.now = 0.0

    def time(self):
        self.now += 1.0
        return self.now

    def sleep(self, seconds):
        self.now += seconds


class VmrunCommandTests(unittest.TestCase):
    def setUp(self):
        self.fake = FakeVmrun()
        for target in (patch.object(vmware.subprocess, "run", self.fake), patch.object(vmware, "time", FakeClock())):
            target.start()
            self.addCleanup(target.stop)
        self.vm = make_vm(self.fake)

    def test_authentication_flags_come_before_the_command(self):
        self.vm.start()
        call = self.fake.calls[-1]
        self.assertEqual(call[:7], ["vmrun.exe", "-T", "ws", "-gu", "sandbox", "-gp", "secret"])
        self.assertEqual(call[7:], ["start", VMX, "nogui"])

    def test_restore_powers_off_a_running_vm_then_reverts(self):
        self.fake.running = True
        self.vm.restore()
        verbs = [c[7] for c in self.fake.calls if len(c) > 7]
        self.assertIn("stop", verbs)
        self.assertLess(verbs.index("stop"), verbs.index("revertToSnapshot"))
        self.assertFalse(self.fake.running)

    def test_restore_of_a_stopped_vm_only_reverts(self):
        self.vm.restore()
        self.assertNotIn("stop", [c[7] for c in self.fake.calls if len(c) > 7])
        self.assertIn(["revertToSnapshot", VMX, "clean"], [c[7:] for c in self.fake.calls])

    def test_start_resumes_a_suspended_vm_but_leaves_a_running_one_alone(self):
        self.vm.start()
        self.assertTrue(self.fake.running)
        starts = [c for c in self.fake.calls if len(c) > 7 and c[7] == "start"]
        self.vm.start()
        self.assertEqual(len([c for c in self.fake.calls if len(c) > 7 and c[7] == "start"]), len(starts))

    def test_an_unknown_error_on_start_names_the_likely_cause(self):
        self.fake.start_fails = True
        with self.assertRaisesRegex(VMwareError, "VMware Authorization Service"):
            self.vm.start()

    def test_running_matches_paths_regardless_of_case_and_slashes(self):
        self.fake.running = True
        with patch.object(vmware, "running_vms", return_value=[VMX.upper().replace("\\", "/")]):
            self.assertTrue(self.vm.running())

    def test_failed_restore_is_an_error_with_the_reason(self):
        self.fake.snapshots = []
        with self.assertRaisesRegex(VMwareError, "snapshot does not exist"):
            self.vm.restore()

    def test_wait_ready_succeeds_once_vmware_tools_answer(self):
        self.fake.tools_ready_after = 2
        self.assertTrue(self.vm.wait_ready(limit=240))

    def test_a_wrong_password_is_reported_as_a_login_error_not_a_slow_boot(self):
        self.fake.login_ok = False
        with self.assertRaises(GuestLoginError):
            self.vm.wait_ready(limit=240)

    def test_tools_never_answering_times_out_with_a_tools_hint(self):
        self.fake.tools_ready_after = 10 ** 6
        with self.assertRaisesRegex(TimeoutError, "VMware Tools"):
            self.vm.wait_ready(limit=60)

    def test_copy_to_names_the_destination_file_in_the_guest(self):
        with tempfile.TemporaryDirectory() as tmp:
            sample = Path(tmp) / "sample.js"
            sample.write_text("x")
            self.vm.copy_to(str(sample), "C:\\sandbox\\in")
        call = [c for c in self.fake.calls if c[7] == "CopyFileFromHostToGuest"][-1]
        self.assertEqual(call[8], VMX)
        self.assertTrue(call[9].endswith("sample.js"))
        self.assertEqual(call[10], "C:\\sandbox\\in\\sample.js")

    def test_missing_vmrun_is_a_clear_error(self):
        with patch.object(vmware.subprocess, "run", side_effect=FileNotFoundError()):
            with self.assertRaisesRegex(VMwareError, "vmrun not found"):
                self.vm.start()


@unittest.skipUnless(ON_WINDOWS, "needs Windows PowerShell")
class GuestCaptureTests(unittest.TestCase):
    """The PowerShell wrapper that returns program output, run for real on this PC."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.fake = FakeVmrun(guest_root=self.root)
        self.guest_out = str(self.root / "out")
        for target in (patch.object(vmware.subprocess, "run", self.fake), patch.object(vmware, "GUEST_OUT", self.guest_out)):
            target.start()
            self.addCleanup(target.stop)
        self.vm = make_vm(self.fake)
        self.cmd = r"C:\Windows\System32\cmd.exe"

    def test_stdout_stderr_and_exit_code_come_back(self):
        result = self.vm.run_exe(self.cmd, "/d", "/c", "echo out& echo err 1>&2& exit 3", timeout_s=30)
        self.assertEqual(result.returncode, 3)
        self.assertEqual(result.stdout.strip(), "out")
        self.assertEqual(result.stderr.strip(), "err")

    def test_arguments_with_spaces_and_quotes_arrive_intact(self):
        result = self.vm.run_exe(self.cmd, "/d", "/c", "echo", "hello world", timeout_s=30)
        self.assertIn("hello world", result.stdout)

    def test_a_program_that_outlives_the_time_limit_raises_the_timeout_error(self):
        with self.assertRaises(GuestProcessTimeout):
            self.vm.run_exe(r"C:\Windows\System32\ping.exe", "-n", "6", "127.0.0.1", timeout_s=1)

    def test_a_program_that_does_not_exist_is_reported_not_raised(self):
        result = self.vm.run_exe(r"C:\definitely\missing.exe", timeout_s=10)
        self.assertNotEqual(result.returncode, 0)
        self.assertTrue(result.stderr.strip())

    def test_powershell_output_is_captured_like_the_virtualbox_path(self):
        result = self.vm.run_cmd_ps("Write-Output 4211", timeout_s=60)
        self.assertEqual(result.stdout.strip(), "4211")
        self.assertEqual(result.returncode, 0)

    def test_powershell_exit_codes_and_errors_are_kept(self):
        result = self.vm.run_cmd_ps("[Console]::Error.WriteLine('boom'); exit 7", timeout_s=60)
        self.assertEqual(result.returncode, 7)
        self.assertIn("boom", result.stderr)

    def test_the_defender_checkpoint_works_on_this_provider(self):
        # The runner reads a record number from stdout; here the "log" is a stand-in command.
        with patch.object(self.vm, "run_cmd_ps", wraps=self.vm.run_cmd_ps):
            baseline, reason = runner.defender_checkpoint(self.vm)
        # Defender's log is not guaranteed to exist on a test machine; either answer must be well-formed.
        self.assertTrue((baseline >= 0 and reason is None) or (baseline == -1 and reason))

    def test_make_dirs_creates_nested_folders(self):
        target = self.root / "a" / "b"
        self.vm.make_dirs(str(target), str(self.root / "c"))
        self.assertTrue(target.is_dir() and (self.root / "c").is_dir())

    def test_files_round_trip_through_the_guest(self):
        host_file = self.root / "sample.js"
        host_file.write_text("WScript.Echo('hi')")
        self.vm.copy_to(str(host_file), "C:\\sandbox\\in")
        self.assertTrue((self.root / "in" / "sample.js").is_file())
        back = self.root / "back.js"
        self.vm.copy_from("C:\\sandbox\\in\\sample.js", str(back))
        self.assertEqual(back.read_text(), "WScript.Echo('hi')")


class VmxAndDiscoveryTests(unittest.TestCase):
    ISOLATED = '''.encoding = "windows-1252"
displayName = "Sandbox"
ethernet0.present = "TRUE"
ethernet0.startConnected = "FALSE"
isolation.tools.copy.disable = "TRUE"
isolation.tools.paste.disable = "TRUE"
isolation.tools.dnd.disable = "TRUE"
'''
    EXPOSED = '''displayName = "Sandbox"
ethernet0.present = "TRUE"
ethernet0.connectionType = "nat"
isolation.tools.copy.disable = "FALSE"
sharedFolder0.present = "TRUE"
sharedFolder.maxNum = "1"
encryption.keySafe = "vmware:key/list/pair/abc"
'''

    def parse(self, text):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "x.vmx"
            path.write_text(text, encoding="utf-8")
            return vmware.read_vmx(str(path))

    def test_vmx_is_parsed_with_case_insensitive_keys(self):
        values = self.parse(self.ISOLATED)
        self.assertEqual(values["ethernet0.startconnected"], "FALSE")
        self.assertEqual(values["displayname"], "Sandbox")

    def test_an_isolated_vm_passes_every_check(self):
        checks = recon.vmware_isolation_checks(self.parse(self.ISOLATED))
        self.assertTrue(all(c.ok for c in checks), [c.name for c in checks if not c.ok])

    def test_an_exposed_vm_fails_each_check_with_a_fix(self):
        checks = {c.name: c for c in recon.vmware_isolation_checks(self.parse(self.EXPOSED))}
        for name in ("VM network off", "VM clipboard sharing off", "VM drag and drop off", "VM shared folders off", "VM not encrypted"):
            self.assertFalse(checks[name].ok, name)
            self.assertTrue(checks[name].fix, name)

    def test_missing_settings_are_not_treated_as_safe(self):
        checks = {c.name: c for c in recon.vmware_isolation_checks({})}
        self.assertFalse(checks["VM clipboard sharing off"].ok)
        self.assertFalse(checks["VM drag and drop off"].ok)

    def test_unreadable_vm_file_is_a_failed_check_not_a_crash(self):
        with patch.object(recon, "vmware_list_snapshots", return_value=[]):
            checks = recon.vmware_preflight_checks(r"C:\nowhere\x.vmx", "clean", "vmrun.exe", False)
        self.assertFalse(next(c for c in checks if c.name == "VM file").ok)
        self.assertTrue(any(c.name == "VM isolation settings" and not c.ok for c in checks))

    def test_health_reports_each_reason(self):
        with tempfile.TemporaryDirectory() as tmp:
            vmx = Path(tmp) / "x.vmx"
            vmx.write_text(self.ISOLATED, encoding="utf-8")
            with patch.object(recon, "vmrun_version", return_value=None):
                self.assertIn("not responding", recon.vmware_vm_health(str(vmx), "clean")["reason"])
            with patch.object(recon, "vmrun_version", return_value="1.17"):
                self.assertIn("not found", recon.vmware_vm_health(str(Path(tmp) / "gone.vmx"), "clean")["reason"])
                with patch.object(recon, "vmware_list_snapshots", return_value=[]):
                    self.assertIn("no longer exists", recon.vmware_vm_health(str(vmx), "clean")["reason"])
                with patch.object(recon, "vmware_list_snapshots", return_value=["clean"]):
                    self.assertEqual(recon.vmware_vm_health(str(vmx), "clean"), {"ok": True, "reason": None})
                    self.assertIn("not been verified", recon.vmware_vm_health(str(vmx), "clean", login_verified=False)["reason"])
                vmx.write_text(self.EXPOSED, encoding="utf-8")
                self.assertIn("encrypted", recon.vmware_vm_health(str(vmx), "clean")["reason"])

    def test_discovery_finds_recent_and_default_folder_vms(self):
        with tempfile.TemporaryDirectory() as tmp:
            appdata, home = Path(tmp) / "AppData", Path(tmp) / "home"
            recent = Path(tmp) / "Elsewhere" / "Win11" / "Win11.vmx"
            recent.parent.mkdir(parents=True)
            recent.write_text("displayName = \"Win11\"")
            (appdata / "VMware").mkdir(parents=True)
            (appdata / "VMware" / "preferences.ini").write_text(
                f'pref.mruVM0.filename = "{recent}"\npref.mruVM1.filename = "{Path(tmp) / "gone.vmx"}"\n')
            default = home / "Documents" / "Virtual Machines" / "Lab" / "Lab.vmx"
            default.parent.mkdir(parents=True)
            default.write_text("x")
            with patch.dict(os.environ, {"APPDATA": str(appdata)}), patch.object(vmware.Path, "home", return_value=home):
                found = vmware.discover_vms()
        self.assertEqual(found, {"Win11": str(recent), "Lab": str(default)})

    def test_vmrun_is_found_in_a_custom_install_folder_from_the_registry(self):
        with tempfile.TemporaryDirectory() as tmp:
            (Path(tmp) / "vmrun.exe").write_text("")
            with patch.dict(os.environ, {"VMRUN_PATH": ""}), \
                 patch.object(vmware, "_registry_install_dirs", return_value=[r"C:\not\installed", tmp]):
                self.assertEqual(vmware.default_vmrun(), str(Path(tmp) / "vmrun.exe"))

    def test_an_explicit_vmrun_path_wins_over_the_registry(self):
        with patch.dict(os.environ, {"VMRUN_PATH": r"D:\mine\vmrun.exe"}), \
             patch.object(vmware, "_registry_install_dirs", return_value=[r"C:\other"]):
            self.assertEqual(vmware.default_vmrun(), r"D:\mine\vmrun.exe")

    def test_vmrun_version_is_read_from_its_usage_text(self):
        done = subprocess.CompletedProcess([], 1, "vmrun version 1.17.0 build-23775571\n", "")
        with patch.object(vmware.subprocess, "run", return_value=done):
            self.assertEqual(vmware.vmrun_version("vmrun.exe"), "1.17.0")
        with patch.object(vmware.subprocess, "run", side_effect=FileNotFoundError()):
            self.assertIsNone(vmware.vmrun_version("vmrun.exe"))

    def test_snapshot_listing_skips_the_total_line(self):
        done = subprocess.CompletedProcess([], 0, "Total snapshots: 2\nclean\nafter-office\n", "")
        with patch.object(vmware.subprocess, "run", return_value=done):
            self.assertEqual(vmware.list_snapshots(VMX, "vmrun.exe"), ["clean", "after-office"])


class ProviderSelectionTests(unittest.TestCase):
    def config(self, provider="virtualbox"):
        config = cfgmod.AgentConfig()
        config.vm.provider = provider
        config.vm.name, config.vm.vmx_path, config.vm.snapshot = "Sandbox", VMX, "clean"
        config.vm.guest_user = "sandbox"
        config.vm.set_guest_password("secret")
        config.vm.login_verified = True
        return config

    def test_provider_picks_the_matching_class(self):
        self.assertIsInstance(cli._vbox(self.config("vmware")), VMware)
        self.assertIsInstance(cli._vbox(self.config("virtualbox")), VBox)
        self.assertEqual(cli._vbox(self.config("vmware")).vm, VMX)

    def test_old_settings_files_load_as_virtualbox(self):
        with tempfile.TemporaryDirectory() as tmp, patch.dict(os.environ, {"ETAP_AGENT_HOME": tmp}):
            Path(tmp, "config.json").write_text(json.dumps({"server_url": "https://x", "vm": {"name": "old", "snapshot": "clean"}}))
            loaded = cfgmod.load()
        self.assertEqual(loaded.vm.provider, "virtualbox")
        self.assertEqual(loaded.vm.name, "old")

    def test_a_vmware_setup_needs_the_vmx_path(self):
        config = self.config("vmware")
        self.assertTrue(config.is_set_up)
        config.vm.vmx_path = ""
        self.assertFalse(config.is_set_up)
        config.vm.provider = "virtualbox"
        self.assertTrue(config.is_set_up)       # VirtualBox identifies the VM by name alone

    def test_summary_names_the_provider(self):
        with patch("sandbox_agent.vmware.vmrun_version", return_value="1.17.0"):
            summary = cli._vm_summary(self.config("vmware"))
        self.assertEqual((summary["provider"], summary["provider_version"]), ("vmware", "1.17.0"))

    def test_health_uses_the_matching_check(self):
        with patch.object(cli, "vmware_vm_health", return_value={"ok": True, "reason": None}) as vmw, \
             patch.object(cli, "vm_health", return_value={"ok": False, "reason": "vbox"}) as vbx:
            self.assertTrue(cli._health(self.config("vmware"))["ok"])
            self.assertFalse(cli._health(self.config("virtualbox"))["ok"])
        vmw.assert_called_once()
        vbx.assert_called_once()

    def test_runner_creates_guest_folders_through_the_provider(self):
        vm = MagicMock()
        vm.run_cmd_ps.return_value = subprocess.CompletedProcess([], 0, "5", "")
        vm.dwell = 0
        with tempfile.TemporaryDirectory() as tmp, patch.object(runner.time, "sleep"):
            runner.run_job("job1", [], Path(tmp) / "w", vbox=vm)
        vm.make_dirs.assert_called_once_with(r"C:\sandbox\in", r"C:\sandbox\out")

    def test_virtualbox_make_dirs_keeps_the_old_command(self):
        vbox = VBox(vm="v", snapshot="clean", user="u", password="p", exe="x")
        with patch.object(vbox, "_gc") as gc:
            vbox.make_dirs(r"C:\a", r"C:\b")
        gc.assert_called_once_with("mkdir", "--parents", r"C:\a", r"C:\b")


class SetupFlowTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        env = patch.dict(os.environ, {"ETAP_AGENT_HOME": self.home.name})
        env.start()
        self.addCleanup(env.stop)
        self.vmx = Path(self.home.name) / "Sandbox.vmx"
        self.vmx.write_text('displayName = "Sandbox"')

    def args(self, **kw):
        return SimpleNamespace(yes=True, server=None, from_env=None, provider=kw.get("provider"))

    def run_setup(self, args, vbox_ok):
        vbox_check = recon.Check("VirtualBox", vbox_ok, "version 7" if vbox_ok else "not found")
        vmware_checks = [recon.Check("VMware Workstation", True, "vmrun 1.17")]
        with patch.object(cli, "system_checks", return_value=([vbox_check], ["win11"] if vbox_ok else [])), \
             patch.object(cli, "vmware_system_checks", return_value=(vmware_checks, {"Sandbox": str(self.vmx)})), \
             patch.object(cli, "preflight_checks", return_value=[]), patch.object(cli, "vmware_preflight_checks", return_value=[]), \
             patch.object(cli, "hypervisor_present", return_value=False), \
             patch.object(cli, "verify_guest", return_value=(True, "")), patch.object(cli, "choose", side_effect=lambda q, o, d=None: o[0]), \
             patch("builtins.input", return_value="sandbox"), patch("getpass.getpass", return_value="secret"):
            return cli.cmd_setup(args, cfgmod.AgentConfig())

    def test_provider_flag_sets_up_vmware_even_when_virtualbox_is_installed(self):
        config = self.run_setup(self.args(provider="vmware"), vbox_ok=True)
        self.assertEqual((config.vm.provider, config.vm.name, config.vm.vmx_path), ("vmware", "Sandbox", str(self.vmx)))
        self.assertTrue(config.is_set_up)
        self.assertEqual(cfgmod.load().vm.provider, "vmware")

    def test_vmware_is_used_automatically_when_virtualbox_is_missing(self):
        config = self.run_setup(self.args(), vbox_ok=False)
        self.assertEqual(config.vm.provider, "vmware")

    def test_virtualbox_stays_the_default_when_it_is_installed(self):
        config = self.run_setup(self.args(), vbox_ok=True)
        self.assertEqual((config.vm.provider, config.vm.name), ("virtualbox", "win11"))

    def test_neither_hypervisor_installed_is_a_clear_stop(self):
        vbox_check = recon.Check("VirtualBox", False, "not found")
        nothing = [recon.Check("VMware Workstation", False, "not found")]
        with patch.object(cli, "system_checks", return_value=([vbox_check], [])), \
             patch.object(cli, "vmware_system_checks", return_value=(nothing, {})):
            with self.assertRaisesRegex(SystemExit, "VirtualBox \\(or VMware"):
                cli.cmd_setup(self.args(), cfgmod.AgentConfig())

    def test_a_vmx_path_that_does_not_exist_is_refused(self):
        env_args = SimpleNamespace(yes=True, server=None, from_env="x.env", provider="vmware")
        with patch.object(cli, "read_env_file", return_value={"vmx_path": str(self.vmx) + ".missing"}), \
             patch.object(cli, "vmware_system_checks", return_value=([recon.Check("VMware Workstation", True, "ok")], {})):
            with self.assertRaisesRegex(SystemExit, "not an existing .vmx"):
                cli.cmd_setup(env_args, cfgmod.AgentConfig())


if __name__ == "__main__":
    unittest.main()
