"""The agent program itself: saved secrets, .env import, one job. No VM is started."""
import base64
import gzip
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sandbox_agent import cli, config as cfgmod, runner  # noqa: E402
from sandbox_agent.protect import seal, unseal  # noqa: E402
from sandbox_agent.recon import read_env_file  # noqa: E402


class AgentConfigTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        env = patch.dict(os.environ, {"ETAP_AGENT_HOME": self.home.name})
        env.start()
        self.addCleanup(env.stop)

    def test_secrets_round_trip_and_are_not_stored_in_clear(self):
        sealed = seal("guest-pass-123")
        self.assertNotIn("guest-pass-123", sealed)
        self.assertEqual(unseal(sealed), "guest-pass-123")
        if sys.platform == "win32":
            self.assertTrue(sealed.startswith("dpapi:"))

    def test_config_saves_and_loads(self):
        config = cfgmod.AgentConfig(server_url="http://127.0.0.1:5010")
        config.vm.name, config.vm.guest_user = "Win11-Sandbox", "sandbox"
        config.vm.set_guest_password("pw")
        config.vm.login_verified = True
        config.agent_id = "agt_1"
        config.set_agent_token("eta_secret")
        path = cfgmod.save(config)
        text = path.read_text(encoding="utf-8")
        self.assertNotIn("eta_secret", text)
        loaded = cfgmod.load()
        self.assertTrue(loaded.is_set_up and loaded.is_registered)
        self.assertEqual((loaded.vm.guest_password, loaded.agent_token), ("pw", "eta_secret"))

    def test_env_import_reads_only_sandbox_keys(self):
        env = Path(self.home.name) / ".env"
        env.write_text('GEMINI_API_KEY=not-read\nSANDBOX_VM_NAME="Win 11"\nSANDBOX_GUEST_PASSWORD=p=w\n'
                       "# SANDBOX_SNAPSHOT=commented\nSANDBOX_DWELL_SECONDS=20\n", encoding="utf-8")
        self.assertEqual(read_env_file(str(env)), {"name": "Win 11", "guest_password": "p=w", "dwell_seconds": "20"})


class HandleJobTests(unittest.TestCase):
    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        env = patch.dict(os.environ, {"ETAP_AGENT_HOME": self.home.name})
        env.start()
        self.addCleanup(env.stop)
        self.config = cfgmod.AgentConfig()
        self.config.vm.name, self.config.vm.guest_user = "Win11-Sandbox", "sandbox"
        self.config.vm.set_guest_password("pw")

    def test_job_downloads_runs_and_uploads_with_indexes(self):
        client = MagicMock()
        client.sample.return_value = b"// fixture"
        client.result.return_value = {"status": "done"}
        job = {"job_id": "job_1", "samples": [
            {"index": 0, "filename": "a.zip / bad.js", "has_file": False, "inspection_error": "Unsafe archive member path"},
            {"index": 1, "filename": "invoice.js", "sha256": "ab", "has_file": True}]}
        seen = {}

        def fake_run(job_id, samples, work_dir, vbox=None, on_status=None):
            seen["samples"] = samples
            on_status("interacting")
            return {"items": [{"filename": s["filename"]} for s in samples], "sysmon_xml": "<Events></Events>",
                    "security_events": [], "error": None, "cleanup_error": None}

        with patch.object(runner, "run_job", side_effect=fake_run), patch.object(cli, "_vbox"), \
             patch.object(cli, "_vm_summary", return_value={"name": "Win11-Sandbox"}):
            answer = cli.handle_job(client, self.config, job)
        self.assertEqual(answer["status"], "done")
        client.sample.assert_called_once_with("job_1", 1)
        self.assertEqual(base64.b64decode(seen["samples"][1]["content_b64"]), b"// fixture")
        self.assertEqual(seen["samples"][0]["content_b64"], "")
        client.progress.assert_called_with("job_1", "interacting")
        payload = client.result.call_args.args[1]
        self.assertEqual([i["index"] for i in payload["items"]], [0, 1])
        self.assertEqual(gzip.decompress(base64.b64decode(payload["sysmon_xml_gz_b64"])), b"<Events></Events>")
        self.assertNotIn("pw", str(payload))

    def test_declined_job_is_reported_not_run(self):
        self.config.auto_run = False
        client = MagicMock()
        with patch("builtins.input", return_value="n"), patch.object(runner, "run_job") as run:
            cli.handle_job(client, self.config, {"job_id": "job_2", "samples": []})
        run.assert_not_called()
        self.assertIn("Declined", client.result.call_args.args[1]["error"])


class LoginVerificationTests(unittest.TestCase):
    """A wrong guest password must never count as a working sandbox."""

    def setUp(self):
        self.home = tempfile.TemporaryDirectory()
        self.addCleanup(self.home.cleanup)
        env = patch.dict(os.environ, {"ETAP_AGENT_HOME": self.home.name})
        env.start()
        self.addCleanup(env.stop)

    def test_rejected_password_fails_fast_not_after_four_minutes(self):
        import subprocess
        from sandbox_agent.vbox import GuestLoginError, VBox, VBoxError
        vbox = VBox(vm="v", snapshot="clean", user="sandbox", password="wrong", exe="x")
        denied = VBoxError("VBoxManage guestcontrol failed: VERR_AUTHENTICATION_FAILURE: The specified user was not able to logon on guest")
        with patch.object(vbox, "_gc", side_effect=denied), patch("sandbox_agent.vbox.time.sleep"):
            with self.assertRaises(GuestLoginError):
                vbox.wait_ready(limit=240)
        # A single early rejection while Windows is still starting is tolerated.
        ready = subprocess.CompletedProcess([], 0, "ready", "")
        with patch.object(vbox, "_gc", side_effect=[denied, ready]), patch("sandbox_agent.vbox.time.sleep"):
            self.assertTrue(vbox.wait_ready())

    def test_config_is_not_set_up_until_the_login_was_verified(self):
        config = cfgmod.AgentConfig()
        config.vm.name, config.vm.guest_user = "win 11", "sandbox"
        config.vm.set_guest_password("pw")
        self.assertFalse(config.is_set_up)
        config.vm.login_verified = True
        self.assertTrue(config.is_set_up)
        config.vm.set_guest_password("other")  # a new password has not been checked
        self.assertFalse(config.is_set_up)

    def test_verify_guest_reports_rejection_and_always_restores(self):
        from sandbox_agent.vbox import GuestLoginError
        config = cfgmod.AgentConfig()
        config.vm.name, config.vm.guest_user = "win 11", "sandbox"
        config.vm.set_guest_password("wrong")
        vbox = MagicMock()
        vbox.wait_ready.side_effect = GuestLoginError("rejected")
        with patch.object(cli, "_vbox", return_value=vbox):
            ok, message = cli.verify_guest(config)
        self.assertFalse(ok)
        self.assertIn("rejected the user 'sandbox'", message)
        self.assertEqual(vbox.restore.call_count, 2)  # before starting and after the check

    def test_setup_stops_without_a_working_login_when_the_vm_says_no(self):
        config = cfgmod.AgentConfig()
        args = MagicMock(yes=True, server=None, from_env=None)
        virtualbox_ok = MagicMock(ok=True)
        virtualbox_ok.name = "VirtualBox"
        with patch.object(cli, "system_checks", return_value=([virtualbox_ok], ["win 11"])), \
             patch.object(cli, "preflight_checks", return_value=[]), patch.object(cli, "hypervisor_present", return_value=False), \
             patch.object(cli, "verify_guest", return_value=(False, "rejected")), patch.object(cli, "choose", return_value="win 11"), \
             patch("builtins.input", return_value="sandbox"), patch("getpass.getpass", return_value="wrong"):
            with self.assertRaises(SystemExit) as stop:
                cli.cmd_setup(args, config)
        self.assertIn("nothing is set up", str(stop.exception))
        self.assertFalse(cfgmod.load().is_set_up)


class HealthTests(unittest.TestCase):
    def test_vm_health_names_what_is_wrong(self):
        from sandbox_agent import recon
        with patch.object(recon, "vboxmanage_version", return_value=None):
            self.assertIn("VirtualBox is not responding", recon.vm_health("v", "clean")["reason"])
        with patch.object(recon, "vboxmanage_version", return_value="7.2"), patch.object(recon, "list_vms", return_value=["other"]):
            self.assertIn("not found", recon.vm_health("v", "clean")["reason"])
        ok_env = dict(vboxmanage_version=MagicMock(return_value="7.2"), list_vms=MagicMock(return_value=["v"]),
                      show_vm_info=MagicMock(return_value='VMState="poweroff"'))
        with patch.multiple(recon, **ok_env), patch.object(recon, "list_snapshots", return_value=[]):
            self.assertIn("no longer exists", recon.vm_health("v", "clean")["reason"])
        with patch.multiple(recon, **ok_env), patch.object(recon, "list_snapshots", return_value=["clean"]):
            self.assertEqual(recon.vm_health("v", "clean"), {"ok": True, "reason": None})  # powered off is fine
            self.assertIn("not been verified", recon.vm_health("v", "clean", login_verified=False)["reason"])
        inaccessible = dict(ok_env, show_vm_info=MagicMock(return_value='VMState="inaccessible"'))
        with patch.multiple(recon, **inaccessible):
            self.assertIn("inaccessible", recon.vm_health("v", "clean")["reason"])


class DefenderCheckpointTests(unittest.TestCase):
    def test_slow_first_call_is_retried_and_reasons_are_kept(self):
        import subprocess
        from sandbox_agent.vbox import GuestProcessTimeout
        vbox = MagicMock()
        ready = subprocess.CompletedProcess([], 0, "4211" + chr(13) + chr(10), "")
        vbox.run_cmd_ps.side_effect = [GuestProcessTimeout("VERR_TIMEOUT"), ready]
        self.assertEqual(runner.defender_checkpoint(vbox), (4211, None))
        self.assertEqual(vbox.run_cmd_ps.call_args.kwargs["timeout_s"], runner.CHECKPOINT_TIMEOUT_S)

        vbox.run_cmd_ps.side_effect = [subprocess.CompletedProcess([], 0, "", "Access denied")] * 2
        baseline, reason = runner.defender_checkpoint(vbox)
        self.assertEqual(baseline, -1)
        self.assertIn("Access denied", reason)


if __name__ == "__main__":
    unittest.main()
