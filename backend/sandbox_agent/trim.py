"""
sandbox_agent.trim -- keep only what the sample did before uploading the Sysmon log.
====================================================================================
A "log everything" Sysmon configuration records every process in the VM. Opening a
PDF in a browser alone can produce hundreds of thousands of events (tens or hundreds
of megabytes of XML). Uploading all of that is slow and can exhaust the server's
memory, so the full log never leaves this PC: only events that belong to each
sample's process tree are sent. The server runs the same tree logic again, so
trimming here does not change what it finds.

Streams the file (constant memory) and uses the standard library only.
"""

from __future__ import annotations

import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Iterable, Iterator

NS = "http://schemas.microsoft.com/win/2004/08/events/event"
_EVENT = f"{{{NS}}}Event"
_ID = f"{{{NS}}}System/{{{NS}}}EventID"
_DATA = f"{{{NS}}}EventData/{{{NS}}}Data"

# Sysmon events the server converts (ecs_convert.to_ecs): process, network, file, registry, DNS.
KEPT_EVENT_IDS = frozenset({1, 3, 11, 13, 22})
EMPTY = "<Events></Events>"

ET.register_namespace("", NS)


def _summarize(element: ET.Element) -> tuple[int, dict]:
    try:
        event_id = int(element.findtext(_ID, default="0"))
    except ValueError:
        event_id = 0
    return event_id, {d.get("Name"): (d.text or "") for d in element.findall(_DATA)}


def _stream(path: Path) -> Iterator[tuple[int, dict, ET.Element]]:
    """(event id, data fields, element) for every event; the element is only valid until the next one."""
    root = None
    for kind, element in ET.iterparse(str(path), events=("start", "end")):
        if kind == "start":
            if root is None:
                root = element
            continue
        if element.tag != _EVENT:
            continue
        event_id, data = _summarize(element)
        yield event_id, data, element
        root.clear()  # drop everything already read, so memory stays flat


def _tree_from(processes: Iterable[tuple[str, str, str]], markers: list[str]) -> set[str]:
    """(guid, parent guid, command line) of every process start -> guids of the samples' trees."""
    wanted = [m.lower() for m in markers if m]
    parents: dict[str, str] = {}
    tree: set[str] = set()
    for guid, parent, command in processes:
        parents[guid] = parent
        if any(marker in command.lower() for marker in wanted):
            tree.add(guid)
    changed = True
    while changed:  # children can be logged before their parents are known to belong to the tree
        changed = False
        for guid, parent in parents.items():
            if guid not in tree and parent in tree:
                tree.add(guid)
                changed = True
    return tree


def _trim_by_blocks(text: str, markers: list[str]) -> list[str]:
    """For a log that is not well-formed as a whole: handle each <Event> on its own, skipping broken ones."""
    parsed = []
    for block in re.findall(r"<Event[\s>].*?</Event>", text, flags=re.S):
        try:
            element = ET.fromstring(block)
        except ET.ParseError:
            continue
        event_id, data = _summarize(element)
        parsed.append((event_id, data, block))
    tree = _tree_from(((d["ProcessGuid"], d.get("ParentProcessGuid", ""), d.get("CommandLine", ""))
                       for i, d, _ in parsed if i == 1 and d.get("ProcessGuid")), markers)
    return [block for i, d, block in parsed if i in KEPT_EVENT_IDS and d.get("ProcessGuid") in tree]


def trim_sysmon(path: Path, markers: Iterable[str]) -> str:
    """Sysmon XML holding only the events of the samples' process trees ("<Events></Events>" when none)."""
    markers = [m for m in markers if m]
    if not markers:
        return EMPTY
    try:
        tree = _tree_from(((d["ProcessGuid"], d.get("ParentProcessGuid", ""), d.get("CommandLine", ""))
                           for i, d, _ in _stream(path) if i == 1 and d.get("ProcessGuid")), markers)
        if not tree:
            return EMPTY
        kept = [ET.tostring(element, encoding="unicode")
                for event_id, data, element in _stream(path)
                if event_id in KEPT_EVENT_IDS and data.get("ProcessGuid") in tree]
    except ET.ParseError:
        kept = _trim_by_blocks(Path(path).read_text(encoding="utf-8-sig", errors="replace"), markers)
    return "<Events>" + "".join(kept) + "</Events>" if kept else EMPTY
