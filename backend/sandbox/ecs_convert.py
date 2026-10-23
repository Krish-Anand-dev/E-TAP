"""Sysmon (wevtutil XML export) -> ECS-like dicts, restricted to the sample's process tree."""
from __future__ import annotations
import re, ntpath
import xml.etree.ElementTree as ET

NS = {'e': 'http://schemas.microsoft.com/win/2004/08/events/event'}

def win_split(cmd: str):
    return [a or b for a, b in re.findall(r'"([^"]*)"|(\S+)', cmd or '')]

def _proc(prefix_exe, prefix_cmd, d, guid_key):
    exe, cmd = d.get(prefix_exe, ''), d.get(prefix_cmd, '')
    args = win_split(cmd)
    return {'executable': exe, 'name': ntpath.basename(exe), 'command_line': cmd,
            'args': args, 'args_count': len(args), 'entity_id': d.get(guid_key)}

def parse_events(xml_text: str):
    """Parse Sysmon XML events. Handles both wrapped (<Events>) and raw XML."""
    # Strip XML declaration if present and wrap in <Events> if needed
    cleaned = re.sub(r'<\?xml[^>]*\?>', '', xml_text).strip()
    if not cleaned.startswith('<Events'):
        cleaned = '<Events>' + cleaned + '</Events>'
    root = ET.fromstring(cleaned)
    for ev in root.findall('e:Event', NS):
        eid = int(ev.findtext('e:System/e:EventID', default='0', namespaces=NS))
        d = {x.get('Name'): (x.text or '') for x in ev.findall('e:EventData/e:Data', NS)}
        yield eid, d

def to_ecs(eid: int, d: dict):
    """Convert a single Sysmon event to ECS-like dict."""
    if eid == 1:
        p = _proc('Image', 'CommandLine', d, 'ProcessGuid')
        p['pe'] = {'original_file_name': d.get('OriginalFileName')}
        par = _proc('ParentImage', 'ParentCommandLine', d, 'ParentProcessGuid')
        p['parent'] = par
        return {'_category': 'process', 'event': {'action': 'start', 'type': 'start'}, 'process': p,
                'user': {'name': d.get('User')}}
    if eid == 11:
        path = d.get('TargetFilename', '')
        return {'_category': 'file', 'event': {'action': 'creation', 'type': 'creation'},
                'process': _proc('Image', '', d, 'ProcessGuid'),
                'file': {'path': path, 'name': ntpath.basename(path), 'extension': ntpath.splitext(path)[1].lstrip('.')}}
    if eid == 13:
        return {'_category': 'registry', 'event': {'action': 'modification', 'type': 'change'},
                'process': _proc('Image', '', d, 'ProcessGuid'),
                'registry': {'path': d.get('TargetObject', ''), 'data': {'strings': [d.get('Details', '')]}}}
    if eid == 22:
        return {'_category': 'dns', 'event': {'action': 'lookup_requested'},
                'process': _proc('Image', '', d, 'ProcessGuid'),
                'dns': {'question': {'name': d.get('QueryName', '')}}}
    if eid == 3:
        return {'_category': 'network', 'event': {'action': 'connection_attempted'},
                'process': _proc('Image', '', d, 'ProcessGuid'),
                'destination': {'ip': d.get('DestinationIp'), 'port': d.get('DestinationPort')}}
    return None

def sample_tree_events(xml_text: str, sample_marker: str):
    """Keep only events from the process tree rooted at the first process whose command line contains `sample_marker`."""
    raw = [(eid, d) for eid, d in parse_events(xml_text)]
    tree = set()
    tree_guids = set()
    for eid, d in raw:                       # find root
        if eid == 1 and d.get('ProcessGuid') and sample_marker.lower() in d.get('CommandLine', '').lower():
            tree.add(d['ProcessGuid']); tree_guids.add(d['ProcessGuid'])
    changed = True
    while changed:                           # grow descendants (events arrive ordered, but loop is cheap)
        changed = False
        for eid, d in raw:
            if eid == 1:
                pid = d.get('ProcessGuid', '')
                ppid = d.get('ParentProcessGuid', '')
                if pid not in tree and ppid in tree_guids:
                    tree.add(pid); tree_guids.add(pid); changed = True
    # Match descendants by ProcessGuid, never by executable name: unrelated
    # processes can use the same cmd.exe/wscript.exe as a sample.
    out = []
    for eid, d in raw:
        if d.get('ProcessGuid') in tree_guids:
            e = to_ecs(eid, d)
            if e: out.append(e)
    return out
