"""Agent preflight (read-only VM checks) and sample cleanup. No VM or VBoxManage is used."""
import io
import os
import sys
import unittest
from contextlib import redirect_stdout
from types import SimpleNamespace
from unittest.mock import patch

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
os.environ["USE_FAKE_DB"] = "1"

from db import connection  # noqa: E402
from db.fake_mongo import FakeDatabase  # noqa: E402
from sandbox import agent_queue  # noqa: E402
from sandbox_agent import cli, recon  # noqa: E402

ISOLATED = '''name="Win11-Sandbox"
VMState="poweroff"
nic1="none"
nic2="none"
clipboard="disabled"
draganddrop="disabled"
'''
EXPOSED = '''name="Win11-Sandbox"
nic1="nat"
cableconnected1="on"
nic2="none"
clipboard="bidirectional"
draganddrop="hosttoguest"
SharedFolderNameMachineMapping1="share"
'''


def by_name(checks):
    return {c.name: c for c in checks}


class IsolationChecks(unittest.TestCase):
    def test_a_fully_isolated_vm_passes_every_check(self):
        checks = recon.isolation_checks(ISOLATED)
        self.assertTrue(all(c.ok for c in checks), [c for c in checks if not c.ok])

    def test_exposed_vm_fails_each_check_with_a_fix(self):
        checks = by_name(recon.isolation_checks(EXPOSED))
        for name in ("VM network off", "VM clipboard sharing off", "VM drag and drop off", "VM shared folders off"):
            self.assertFalse(checks[name].ok, name)
            self.assertTrue(checks[name].fix, name)

    def test_a_disconnected_cable_counts_as_off(self):
        info = ISOLATED.replace('nic1="none"', 'nic1="nat"\ncableconnected1="off"')
        self.assertTrue(by_name(recon.isolation_checks(info))["VM network off"].ok)

    def test_unreadable_settings_are_not_treated_as_safe(self):
        checks = by_name(recon.isolation_checks('name="x"\n'))
        self.assertFalse(checks["VM clipboard sharing off"].ok)
        self.assertFalse(checks["VM drag and drop off"].ok)


class HypervisorCheck(unittest.TestCase):
    def test_hypervisor_on_warns_but_unknown_does_not_block(self):
        self.assertFalse(recon.hypervisor_check(True).ok)
        self.assertTrue(recon.hypervisor_check(True).fix)
        self.assertTrue(recon.hypervisor_check(False).ok)
        self.assertTrue(recon.hypervisor_check(None).ok)

    def test_detection_reads_the_windows_answer(self):
        for output, expected in (("True\r\n", True), ("False\r\n", False), ("", None)):
            with patch.object(recon.sys, "platform", "win32"), \
                 patch.object(recon.subprocess, "run", return_value=SimpleNamespace(stdout=output)):
                self.assertEqual(recon.hypervisor_present(), expected)
        with patch.object(recon.sys, "platform", "linux"):
            self.assertIsNone(recon.hypervisor_present())


class CheckCommand(unittest.TestCase):
    def test_check_is_read_only_and_points_to_test_for_the_guest(self):
        config = SimpleNamespace(
            is_set_up=True,
            vm=SimpleNamespace(name="Win11-Sandbox", snapshot="clean", vboxmanage=""))
        system = [recon.Check("VirtualBox", True, "version 7.1"), recon.Check("Windows Sandbox (planned)", False, "not installed")]
        out = io.StringIO()
        with patch.object(cli, "system_checks", return_value=(system, ["Win11-Sandbox"])), \
             patch.object(cli, "preflight_checks", return_value=[recon.Check("VM network off", False, "1 adapter", "untick it")]), \
             patch.object(cli, "hypervisor_present", return_value=False), \
             redirect_stdout(out):
            cli.cmd_check(SimpleNamespace(yes=False), config)
        text = out.getvalue()
        self.assertIn("Fix: untick it", text)
        self.assertIn("1 of 2 checks passed", text)
        self.assertNotIn("Windows Sandbox", text)   # planned feature is not a requirement
        self.assertIn("`test`", text)               # the VM-starting check stays opt-in

    def test_check_needs_setup_first(self):
        with self.assertRaises(SystemExit):
            cli.cmd_check(SimpleNamespace(yes=False), SimpleNamespace(is_set_up=False))


class SampleCleanup(unittest.TestCase):
    def setUp(self):
        self.db = FakeDatabase()
        connection.set_db(self.db)
        self.addCleanup(connection.reset_db)

    def test_only_samples_of_active_jobs_are_kept(self):
        self.db[agent_queue.JOBS].insert_one({"job_id": "live", "status": "queued"})
        self.db[agent_queue.JOBS].insert_one({"job_id": "done", "status": "done"})
        for job_id in ("live", "done", "missing"):
            self.db[agent_queue.FILES].insert_one({"job_id": job_id, "index": 0, "content_b64": "AAAA"})
        self.assertEqual(agent_queue.purge_orphan_samples(), 2)
        self.assertEqual(self.db[agent_queue.FILES].distinct("job_id"), ["live"])
        self.assertEqual(agent_queue.purge_orphan_samples(), 0)

    def test_housekeeping_starts_once(self):
        with patch.object(agent_queue, "_housekeeping_started", False), \
             patch.object(agent_queue.threading, "Thread") as thread:
            self.assertTrue(agent_queue.start_housekeeping())
            self.assertFalse(agent_queue.start_housekeeping())
        thread.assert_called_once()
        thread.return_value.start.assert_called_once()


if __name__ == "__main__":
    unittest.main()
