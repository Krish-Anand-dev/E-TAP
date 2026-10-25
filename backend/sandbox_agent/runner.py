"""
sandbox_agent.runner -- one sandbox run inside a VirtualBox VM.
================================================================
restore clean snapshot -> start -> copy each sample in -> open it ->
wait -> export Sysmon and Defender events -> restore clean snapshot.

Shared by the paired E-TAP Sandbox Agent and the server's in-process
local worker (SANDBOX_BACKEND=virtualbox). It only *records* what
happened; rule evaluation and scoring run on the E-TAP server.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import time
import uuid
from pathlib import Path
from typing import Callable

from .vbox import VBox, VBoxError, GuestLoginError, GuestProcessTimeout
from .launchers import launcher_for
from .trim import trim_sysmon

logger = logging.getLogger("E-TAP.sandbox.runner")


def win_split(cmd: str):
    return [a or b for a, b in re.findall(r'"([^"]*)"|(\S+)', cmd or '')]


def run_job(job_id: str, samples: list[dict], work_dir: Path, *, vbox: VBox | None = None,
            on_status: Callable[[str], None] | None = None) -> dict:
    """Run every sample of one job in a freshly restored VM.

    `samples` are dicts with filename, sha256, content_b64 (and optionally
    archive, archive_member, inspection_error). Returns the raw record:
    {items, sysmon_xml, security_events, error, cleanup_error,
    defender_checkpoint_error}. The VM is
    restored to its clean snapshot before this returns, even on failure.
    """
    on_status = on_status or (lambda status: None)
    work_dir.mkdir(parents=True, exist_ok=True)
    vbox = vbox or VBox()
    record = {"items": [], "sysmon_xml": "", "security_events": [], "error": None, "cleanup_error": None,
              "defender_checkpoint_error": None, "login_error": False}

    on_status("starting")
    try:
        logger.info("Job %s: restoring VM", job_id)
        vbox.restore()
        vbox.start()
        vbox.wait_ready()
        vbox._gc("mkdir", "--parents", r"C:\sandbox\in", r"C:\sandbox\out")

        # Clear Sysmon log for clean baseline
        vbox.clear_sysmon()
        security_baseline, record["defender_checkpoint_error"] = _security_checkpoint(vbox)
        time.sleep(1)

        on_status("interacting")
        for sample in samples:
            record["items"].append(detonate_single(vbox, job_id, sample, work_dir))

        on_status("collecting")
        markers = [i.get("sample_marker") for i in record["items"] if i.get("launched")]
        record["sysmon_xml"] = _collect_sysmon(vbox, work_dir, markers)
        record["security_events"] = _collect_security_events(vbox, security_baseline)
    except Exception as exc:
        logger.exception("Job %s failed: %s", job_id, exc)
        record["error"] = str(exc)[:500]
        record["login_error"] = isinstance(exc, GuestLoginError)
    finally:
        on_status("restoring")
        try:
            vbox.restore()
        except Exception as exc:
            record["cleanup_error"] = f"Failed to restore clean VM: {exc}"[:500]
        _cleanup_work_dir(work_dir)
    return record


def detonate_single(vbox: VBox, job_id: str, candidate: dict, work_dir: Path) -> dict:
    """Copy one attachment into the VM and open it."""
    filename = candidate["filename"]
    sha256 = candidate.get("sha256", "unknown")
    b64_data = candidate.get("content_b64", "")

    ext = "." + filename.rsplit(".", 1)[-1].lower() if "." in filename else ""
    safe_name = f"sample_{job_id}_{uuid.uuid4().hex[:8]}{ext}"
    sample_marker = safe_name.rsplit(".", 1)[0]  # e.g., "sample_job_ab12"

    item = {
        "filename": filename,
        "sample": safe_name,
        "sha256": sha256,
        "verdict": "no_behavior_observed_inconclusive",
        "matches": [],
        "process_tree": [],
        "sample_marker": sample_marker,
        "launch_error": None,
        "event_count": 0,
        "interaction_log": [],
        "launched": False,
    }

    for key in ("archive", "archive_member"):
        if key in candidate:
            item[key] = candidate[key]
    if candidate.get("inspection_error"):
        item["verdict"] = "inspection_incomplete"
        item["note"] = candidate["inspection_error"]
        return item

    if not b64_data:
        item["verdict"] = "error"
        item["launch_error"] = "No attachment data available"
        return item

    # Write sample to host work directory
    sample_path = work_dir / safe_name
    try:
        raw_bytes = base64.b64decode(b64_data, validate=True)
        sample_path.write_bytes(raw_bytes)
    except Exception as exc:
        item["verdict"] = "error"
        item["launch_error"] = f"Failed to write sample: {exc}"
        return item

    # Copy to VM
    try:
        vbox.copy_to(str(sample_path), r"C:\sandbox\in")
    except VBoxError as exc:
        item["verdict"] = "error"
        item["launch_error"] = f"Failed to copy to VM: {exc}"
        return item

    # Launch
    guest_path = f"C:\\sandbox\\in\\{safe_name}"
    exe, args_template = launcher_for(filename)

    launch_started = time.monotonic()
    try:
        if args_template is None and exe is None:
            # No launcher configured (needs application not available)
            item["verdict"] = "inspection_incomplete"
            item["launch_error"] = f"No application configured for {ext}"
            item["interaction_log"].append({
                "action": "skip", "reason": f"application_not_installed for {ext}"
            })
            return item

        if exe is None:
            # Run directly
            cmd = args_template.replace("{file}", guest_path)
        else:
            args = args_template.replace("{file}", guest_path)
            cmd = f'"{exe}" {args}'

        logger.info("Job %s: launching %s", job_id, cmd)
        item["interaction_log"].append({"action": "launch", "command": cmd})

        # Track attempted launches even if a later timeout/error is reported;
        # Sysmon may still contain useful evidence from the process tree.
        item["launched"] = True
        if exe is None:
            result = vbox.run_exe(guest_path, timeout_s=vbox.dwell)
        else:
            result = vbox.run_exe(exe, *win_split(args), timeout_s=vbox.dwell)
        item["interaction_log"].append({
            "action": "launch_complete",
            "stdout": (result.stdout or "")[:500],
            "stderr": (result.stderr or "")[:500],
        })
        # VBoxManage's own exit code can be zero even if cscript reports a
        # guest runtime error. Surface it rather than claiming full execution.
        if "runtime error" in (result.stderr or "").lower() or "compilation error" in (result.stderr or "").lower():
            item["launch_error"] = (result.stderr or "").strip()[:500]

    except GuestProcessTimeout:
        item["interaction_log"].append({"action": "observation_limit", "seconds": vbox.dwell})
    except Exception as exc:
        item["launch_error"] = str(exc)[:300]
        item["interaction_log"].append({
            "action": "launch_failed", "error": str(exc)[:300]
        })
        logger.warning("Job %s: launch failed for %s: %s", job_id, filename, exc)

    # Dwell time
    time.sleep(max(0, vbox.dwell - (time.monotonic() - launch_started)))

    return item


CHECKPOINT_ATTEMPTS = 2
CHECKPOINT_TIMEOUT_S = 60


def defender_checkpoint(vbox: VBox) -> tuple[int, str | None]:
    """(latest Defender record id, None) or (-1, why it failed).

    The first PowerShell call after the VM resumes can be slow, so this
    allows a minute and tries twice before giving up.
    """
    reason = None
    for attempt in range(1, CHECKPOINT_ATTEMPTS + 1):
        try:
            result = vbox.run_cmd_ps(
                "$e = Get-WinEvent -LogName 'Microsoft-Windows-Windows Defender/Operational' "
                "-MaxEvents 1 -ErrorAction SilentlyContinue; if ($e) { $e.RecordId } else { 0 }",
                timeout_s=CHECKPOINT_TIMEOUT_S,
            )
            out = (result.stdout or "").strip()
            if out.isdigit():
                return int(out), None
            reason = f"unexpected output {out[:80]!r}" + (f", stderr {(result.stderr or '').strip()[:160]!r}" if result.stderr else "")
        except Exception as exc:
            reason = f"{type(exc).__name__}: {str(exc)[:200]}"
        logger.warning("Defender checkpoint attempt %d failed: %s", attempt, reason)
    return -1, reason


def _security_checkpoint(vbox: VBox) -> tuple[int, str | None]:
    """Checkpoint Defender so snapshot-era alerts cannot taint a new run."""
    baseline, reason = defender_checkpoint(vbox)
    if baseline < 0:
        logger.warning("Defender log checkpoint unavailable (%s); security block attribution disabled", reason)
    return baseline, reason


def _collect_security_events(vbox: VBox, baseline: int) -> list[dict]:
    if baseline < 0:
        return []
    try:
        result = vbox.run_cmd_ps(
            "$events = @(Get-WinEvent -FilterHashtable @{"
            "LogName='Microsoft-Windows-Windows Defender/Operational'; Id=1121,1116,1117,1122} "
            "-MaxEvents 50 -ErrorAction SilentlyContinue | "
            f"Where-Object {{ $_.RecordId -gt {baseline} }} | "
            "ForEach-Object { @{event_id=$_.Id; record_id=$_.RecordId; message=$_.Message} }); "
            "ConvertTo-Json -InputObject $events -Depth 3 -Compress",
            timeout_s=30,
        )
        events = json.loads(result.stdout.strip() or "[]")
        return events if isinstance(events, list) else [events]
    except Exception as exc:
        logger.warning("Could not collect guest security events: %s", exc)
        return []


def _collect_sysmon(vbox: VBox, work_dir: Path, markers=()) -> str:
    """Export the Sysmon log from the VM and return only the samples' own events.

    The full log is large and is deleted with the work folder; it never leaves this PC."""
    guest_xml = r"C:\sandbox\out\sysmon.xml"
    host_xml = work_dir / "sysmon.xml"

    vbox.export_sysmon(guest_xml)
    vbox.copy_from(guest_xml, str(host_xml))
    xml = trim_sysmon(host_xml, markers)
    logger.info("Sysmon log %.1f MB, %.1f MB kept for upload",
                host_xml.stat().st_size / 1e6, len(xml) / 1e6)
    return xml


def _cleanup_work_dir(work_dir: Path):
    """Remove sample files from work directory, keep metadata."""
    try:
        for f in work_dir.iterdir():
            # The samples and the (possibly huge) full Sysmon export are not kept.
            if f.is_file() and (f.name.startswith("sample_") or f.name == "sysmon.xml"):
                f.unlink()
    except Exception:
        pass
