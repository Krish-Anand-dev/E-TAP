"""The behavioural rule set: every rule loads, is original, and passes its own tests.

Each rules/*.toml carries [[tests]] events (expect = "match" / "no_match"). Those are checked
here through the real loader, and a Sysmon XML run is pushed through sample_tree_events and
evaluate() for the event types added in the original rule set (7, 8, 10, 17, 25).
"""
import os
import re
import sys
import tomllib
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from sandbox.config import PROJECT_ROOT  # noqa: E402
from sandbox.ecs_convert import sample_tree_events, to_ecs  # noqa: E402
from sandbox.rule_engine import Rule, evaluate, load_rules  # noqa: E402

RULES_DIR = PROJECT_ROOT / "backend" / "sandbox" / "rules"
MIN_RULES = 51  # the original set; new rules only add to it
TECHNIQUE = re.compile(r"^T\d{4}(\.\d{3})?$")


def rule_files():
    return sorted(RULES_DIR.glob("*.toml"))


class RuleSetTests(unittest.TestCase):
    def test_every_rule_loads_and_none_are_skipped(self):
        rules, skipped = load_rules(str(RULES_DIR))
        self.assertEqual(skipped, {}, f"rules the engine cannot evaluate: {skipped}")
        self.assertGreaterEqual(len(rules), MIN_RULES)

    def test_ids_are_unique_and_sequential(self):
        ids = [tomllib.loads(p.read_text(encoding="utf-8"))["rule"]["id"] for p in rule_files()]
        self.assertGreaterEqual(len(ids), MIN_RULES)
        self.assertEqual(sorted(ids), [f"etap-{i:03d}" for i in range(1, len(ids) + 1)])

    def test_every_rule_is_ours_and_documented(self):
        for path in rule_files():
            text = path.read_text(encoding="utf-8")
            with self.subTest(rule=path.name):
                self.assertNotRegex(text, r"(?i)elastic", "no third-party rule text or licence may remain")
                d = tomllib.loads(text)
                self.assertEqual(d["rule"].get("license"), "MIT")
                self.assertTrue(d["rule"].get("author"))
                self.assertGreater(len(d["rule"].get("description", "")), 20)
                threats = d.get("threat") or []
                self.assertTrue(threats, "needs at least one ATT&CK mapping")
                for t in threats:
                    self.assertTrue(t["tactic"]["name"])
                    for tech in t["technique"]:
                        self.assertRegex(tech["id"], TECHNIQUE)
                        self.assertTrue(tech["name"])

    def test_every_rule_passes_its_own_tests(self):
        total = 0
        for path in rule_files():
            d = tomllib.loads(path.read_text(encoding="utf-8"))
            rule = Rule(d, str(path))
            tests = d.get("tests") or []
            with self.subTest(rule=d["rule"]["id"]):
                self.assertTrue(any(t["expect"] == "match" for t in tests), "needs a positive test")
                self.assertTrue(any(t["expect"] == "no_match" for t in tests), "needs a negative test")
            for t in tests:
                total += 1
                with self.subTest(rule=d["rule"]["id"], test=t["name"]):
                    self.assertEqual(rule.matches(t["event"]), t["expect"] == "match")
        self.assertGreater(total, MIN_RULES * 2)

    def test_a_malicious_event_for_one_rule_is_found_by_the_whole_set(self):
        rules, _ = load_rules(str(RULES_DIR))
        event = {"_category": "process", "process": {"name": "vssadmin.exe", "command_line": "vssadmin.exe delete shadows /all /quiet"}}
        self.assertIn("etap-019", {h["rule_id"] for h in evaluate(rules, [event])})

    def test_defender_service_rule_now_loads(self):
        # etap-002 used to be silently skipped because its query had a malformed list.
        rules, _ = load_rules(str(RULES_DIR))
        self.assertIn("etap-002", {r.id for r in rules})

    def test_severity_tiers(self):
        rules, _ = load_rules(str(RULES_DIR))
        by_id = {r.id: r for r in rules}
        high = {r.id for r in rules if "kill_process" in r.actions}
        # Only one action exists, so a rule is either prevention-grade (score floor 85) or review-level (65).
        for r in rules:
            self.assertLessEqual(set(r.actions), {"kill_process"}, r.id)
        # Behaviour that is rarely benign from an attachment stays prevention-grade ...
        self.assertTrue({"etap-001", "etap-002", "etap-003", "etap-004", "etap-005"} <= high)
        # ... while a DNS lookup or a Run-key write by an unlisted program is only worth a look.
        for rule_id in ("etap-006", "etap-007"):
            self.assertNotIn(rule_id, high, by_id[rule_id].name)
        self.assertTrue(high and len(high) < len(rules), "both tiers must exist")


def sysmon(eid, **fields):
    from xml.sax.saxutils import escape
    data = "".join(f'<Data Name="{k}">{escape(v)}</Data>' for k, v in fields.items())
    return ('<Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event"><System>'
            f"<EventID>{eid}</EventID></System><EventData>{data}</EventData></Event>")


MARKER = "sample_job_rules_test_1"
ROOT, CHILD, OTHER = "{root-guid}", "{child-guid}", "{unrelated-guid}"
PUBLIC_EXE = r"C:\Users\Public\update.exe"


class SysmonEventTests(unittest.TestCase):
    def convert(self, eid, **fields):
        return to_ecs(eid, fields)

    def test_existing_fields_are_unchanged_and_new_ones_added(self):
        p = self.convert(1, Image=PUBLIC_EXE, CommandLine="update.exe /x", ProcessGuid=CHILD, ParentImage=r"C:\Windows\System32\cmd.exe",
                         ParentCommandLine="cmd.exe", ParentProcessGuid=ROOT, OriginalFileName="certutil.exe",
                         CurrentDirectory=r"C:\Users\Public", IntegrityLevel="Medium", User="PC\\bob")
        self.assertEqual(p["_category"], "process")
        self.assertEqual(p["process"]["name"], "update.exe")
        self.assertEqual(p["process"]["pe"]["original_file_name"], "certutil.exe")
        self.assertEqual(p["process"]["parent"]["name"], "cmd.exe")
        self.assertEqual(p["process"]["working_directory"], r"C:\Users\Public")

    def test_network_port_is_a_number(self):
        n = self.convert(3, Image=PUBLIC_EXE, ProcessGuid=CHILD, DestinationIp="203.0.113.5", DestinationPort="4444",
                         DestinationHostname="c2.test", Protocol="tcp")
        self.assertEqual(n["destination"]["port"], 4444)
        self.assertEqual(n["destination"]["domain"], "c2.test")
        self.assertEqual(n["network"]["transport"], "tcp")

    def test_new_event_types(self):
        lib = self.convert(7, Image=PUBLIC_EXE, ProcessGuid=CHILD, ImageLoaded=r"C:\Users\Public\version.dll", Signed="false")
        self.assertEqual((lib["_category"], lib["dll"]["name"], lib["dll"]["signed"]), ("library", "version.dll", "false"))
        thread = self.convert(8, SourceImage=PUBLIC_EXE, SourceProcessGuid=CHILD, TargetImage=r"C:\Windows\explorer.exe",
                              TargetProcessGuid="{t}", StartFunction="LoadLibraryA")
        self.assertEqual((thread["_category"], thread["process"]["name"], thread["target"]["process"]["name"]),
                         ("thread", "update.exe", "explorer.exe"))
        access = self.convert(10, SourceImage=PUBLIC_EXE, SourceProcessGUID=CHILD, TargetImage=r"C:\Windows\System32\lsass.exe",
                              TargetProcessGUID="{t}", GrantedAccess="0x1410")
        self.assertEqual((access["_category"], access["process_access"]["granted_access"]), ("process_access", "0x1410"))
        pipe = self.convert(17, Image=PUBLIC_EXE, ProcessGuid=CHILD, PipeName=r"\msagent_ab")
        self.assertEqual((pipe["_category"], pipe["pipe"]["name"]), ("pipe", r"\msagent_ab"))
        self.assertEqual(self.convert(18, Image=PUBLIC_EXE, ProcessGuid=CHILD, PipeName="x")["pipe"]["action"], "connected")
        tamper = self.convert(25, Image=PUBLIC_EXE, ProcessGuid=CHILD, Type="Image is replaced")
        self.assertEqual((tamper["_category"], tamper["tamper"]["type"]), ("tamper", "Image is replaced"))

    def test_sample_run_is_detected_end_to_end_and_unrelated_processes_are_ignored(self):
        xml = "<Events>" + "".join([
            sysmon(1, ProcessGuid=ROOT, ParentProcessGuid="{outside}", Image=r"C:\Windows\System32\wscript.exe",
                   CommandLine=rf"wscript.exe C:\sandbox\in\{MARKER}.js", ParentImage=r"C:\Windows\explorer.exe"),
            sysmon(1, ProcessGuid=CHILD, ParentProcessGuid=ROOT, Image=PUBLIC_EXE, CommandLine=PUBLIC_EXE,
                   ParentImage=r"C:\Windows\System32\wscript.exe"),
            sysmon(10, SourceProcessGUID=CHILD, SourceImage=PUBLIC_EXE, TargetProcessGUID="{lsass}",
                   TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1410"),
            sysmon(8, SourceProcessGuid=CHILD, SourceImage=PUBLIC_EXE, TargetProcessGuid="{t}",
                   TargetImage=r"C:\Windows\explorer.exe"),
            sysmon(17, ProcessGuid=CHILD, Image=PUBLIC_EXE, PipeName=r"\msagent_ab"),
            sysmon(7, ProcessGuid=CHILD, Image=PUBLIC_EXE, ImageLoaded=r"C:\Users\Public\version.dll", Signed="false"),
            sysmon(25, ProcessGuid=CHILD, Image=PUBLIC_EXE, Type="Image is replaced"),
            sysmon(3, ProcessGuid=CHILD, Image=PUBLIC_EXE, DestinationIp="203.0.113.5", DestinationPort="4444"),
            # an unrelated process doing the same thing must not count
            sysmon(10, SourceProcessGUID=OTHER, SourceImage=r"C:\Tools\other.exe", TargetProcessGUID="{lsass}",
                   TargetImage=r"C:\Windows\System32\lsass.exe", GrantedAccess="0x1fffff"),
        ]) + "</Events>"
        events = sample_tree_events(xml, MARKER)
        self.assertEqual(len(events), 8, [e["_category"] for e in events])
        rules, _ = load_rules(str(RULES_DIR))
        found = {h["rule_id"] for h in evaluate(rules, events)}
        for rule_id in ("etap-004", "etap-024", "etap-038", "etap-051", "etap-050", "etap-029", "etap-043", "etap-048"):
            self.assertIn(rule_id, found)
        lsass_hits = [h for h in evaluate(rules, events) if h["rule_id"] == "etap-038"]
        self.assertEqual(len(lsass_hits), 1, "only the sample's own LSASS access counts")


if __name__ == "__main__":
    unittest.main()
