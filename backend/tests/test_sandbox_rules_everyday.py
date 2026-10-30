"""Everyday activity of an opened document must not trip any behaviour rule (a match raises the score)."""
import ntpath
import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sandbox.config import PROJECT_ROOT  # noqa: E402
from sandbox.rule_engine import evaluate, load_rules  # noqa: E402

SYSTEM32 = "C:\\Windows\\System32\\"


def proc(name, cmd="", parent=None, exe=None):
    return {"_category": "process", "event": {"action": "start"},
            "process": {"name": name, "executable": exe or SYSTEM32 + name, "command_line": cmd or name,
                        "args": (cmd or name).split(), "pe": {"original_file_name": name},
                        "parent": {"name": parent, "command_line": ""}}}


def file(proc_name, path):
    return {"_category": "file", "event": {"action": "creation"},
            "process": {"name": proc_name, "executable": SYSTEM32 + proc_name, "command_line": proc_name},
            "file": {"path": path, "name": ntpath.basename(path), "extension": ntpath.splitext(path)[1].lstrip(".")}}


def reg(proc_name, path):
    return {"_category": "registry", "event": {"action": "modification"},
            "process": {"name": proc_name, "executable": SYSTEM32 + proc_name, "command_line": proc_name},
            "registry": {"path": path, "data": {"strings": [""]}}}


def net(proc_name, ip, port):
    return {"_category": "network", "process": {"name": proc_name, "executable": SYSTEM32 + proc_name, "command_line": proc_name},
            "destination": {"ip": ip, "port": port}}


def dns(proc_name, name):
    return {"_category": "dns", "process": {"name": proc_name, "executable": SYSTEM32 + proc_name, "command_line": proc_name},
            "dns": {"question": {"name": name}}}


OFFICE = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE"
EVERYDAY = [
    proc("WINWORD.EXE", rf'"{OFFICE}" "C:\sandbox\in\sample.docx"', parent="cmd.exe", exe=OFFICE),
    proc("splwow64.exe", "splwow64.exe 12288", parent="WINWORD.EXE", exe="C:\\Windows\\splwow64.exe"),
    proc("AcroRd32.exe", r'AcroRd32.exe "C:\sandbox\in\sample.pdf"', parent="cmd.exe", exe=r"C:\Program Files\Adobe\AcroRd32.exe"),
    proc("notepad.exe", r"notepad.exe C:\sandbox\in\sample.txt", parent="cmd.exe"),
    proc("conhost.exe", "conhost.exe 0xffffffff", parent="cmd.exe"),
    proc("svchost.exe", "svchost.exe -k LocalService", parent="services.exe"),
    proc("msedge.exe", "msedge.exe --type=renderer", parent="msedge.exe", exe=r"C:\Program Files\Microsoft\Edge\msedge.exe"),
    file("WINWORD.EXE", r"C:\Users\sandbox\AppData\Local\Temp\~DF1234.tmp"),
    file("WINWORD.EXE", r"C:\Users\sandbox\AppData\Roaming\Microsoft\Word\Normal.dotm"),
    file("AcroRd32.exe", r"C:\Users\sandbox\AppData\Local\Adobe\Acrobat\DC\SharedDataEvents"),
    reg("WINWORD.EXE", r"HKU\S-1\Software\Microsoft\Office\16.0\Word\Resiliency\DocumentRecovery\1"),
    reg("explorer.exe", r"HKU\S-1\Software\Microsoft\Windows\CurrentVersion\Explorer\RecentDocs\.docx"),
    net("WINWORD.EXE", "52.113.194.132", 443),
    net("msedge.exe", "13.107.4.50", 443),
    dns("WINWORD.EXE", "login.microsoftonline.com"),
    dns("msedge.exe", "www.bing.com"),
]


class EverydayActivity(unittest.TestCase):
    def test_a_document_being_opened_matches_no_rule(self):
        rules, skipped = load_rules(str(PROJECT_ROOT / "backend" / "sandbox" / "rules"))
        self.assertEqual(skipped, {})
        for event in EVERYDAY:
            hits = [h["rule_id"] for h in evaluate(rules, [event])]
            self.assertEqual(hits, [], f"{event['_category']} event {event.get('process', {}).get('name')} wrongly matched {hits}")

    def test_a_script_attachment_is_still_caught_by_the_demo_rule(self):
        rules, _ = load_rules(str(PROJECT_ROOT / "backend" / "sandbox" / "rules"))
        event = proc("cscript.exe", r'cscript.exe //Nologo "C:\sandbox\in\sample_ab12.js"', parent="cmd.exe")
        self.assertEqual({h["rule_id"] for h in evaluate(rules, [event])}, {"etap-004"})


if __name__ == "__main__":
    unittest.main()
