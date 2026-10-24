"""
sandbox_agent.cli -- `python -m sandbox_agent [command]`.
=========================================================
  start   (default) set up if needed, pair if needed, then wait for jobs
  setup   check this computer and choose the VM to use
  pair    show a pairing code to enter in the E-TAP extension or dashboard
  run     wait for deeper-analysis jobs (the agent must be paired)
  check   read-only preflight: VirtualBox, snapshot, VM isolation, Hyper-V (VM is not started)
  test    restore the VM once and confirm the guest and Sysmon answer
  status  show the saved settings and whether the server sees this agent
  forget  delete this agent's saved settings
"""

from __future__ import annotations

import argparse
import base64
import getpass
import gzip
import logging
import os
import platform
import sys
import time
from pathlib import Path

from . import __version__, config as cfgmod
from .client import Client, ServerError
from .recon import hypervisor_present, preflight_checks, read_env_file, system_checks

POLL_SECONDS = 5

logger = logging.getLogger("E-TAP.agent")


def say(text: str = "") -> None:
    print(text, flush=True)


def ask_yes(question: str, default: bool, assume_yes: bool) -> bool:
    if assume_yes:
        return True
    suffix = " [Y/n] " if default else " [y/N] "
    while True:
        answer = input(question + suffix).strip().lower()
        if not answer:
            return default
        if answer in {"y", "yes"}:
            return True
        if answer in {"n", "no"}:
            return False


def choose(question: str, options: list[str], default: str | None = None) -> str:
    for number, option in enumerate(options, 1):
        say(f"  {number}. {option}")
    hint = f" [{default}]" if default else ""
    while True:
        answer = input(f"{question}{hint}: ").strip()
        if not answer and default:
            return default
        if answer.isdigit() and 1 <= int(answer) <= len(options):
            return options[int(answer) - 1]
        if answer in options:
            return answer


def print_checks(checks) -> None:
    for check in checks:
        say(f"  [{'ok' if check.ok else '--'}] {check.name}: {check.detail}")
        if not check.ok and check.fix:
            say(f"        Fix: {check.fix}")


# -- setup ----------------------------------------------------------------------

def cmd_setup(args, config: cfgmod.AgentConfig) -> cfgmod.AgentConfig:
    say("E-TAP Sandbox Agent setup")
    say("This will:")
    say("  - look at this computer for VirtualBox and its VMs (read-only)")
    say("  - save the VM you choose and its guest login in your user profile,")
    say(f"    protected by Windows ({cfgmod.config_path()})")
    say(f"  - connect to the E-TAP server at {args.server or config.server_url}")
    say("Nothing is changed in your VM during setup.")
    if not ask_yes("Continue?", True, args.yes):
        raise SystemExit("Setup cancelled.")
    if args.server:
        config.server_url = args.server

    imported = read_env_file(args.from_env) if args.from_env else {}
    if imported:
        say(f"Using the VM settings from {args.from_env} (the password is not shown).")

    say("\nChecking this computer:")
    checks, vms = system_checks(imported.get("vboxmanage") or config.vm.vboxmanage or None)
    print_checks(checks)
    if not any(c.ok for c in checks if c.name == "VirtualBox"):
        raise SystemExit("\nVirtualBox is needed for deeper analysis. Install it, create a Windows VM with Sysmon "
                         "and a clean snapshot, then run setup again.")
    if not vms:
        raise SystemExit("\nNo VirtualBox VM found for this Windows user.")

    vm = config.vm
    if imported.get("vboxmanage"):
        vm.vboxmanage = imported["vboxmanage"]
    if imported.get("name") in vms:
        vm.name = imported["name"]
    else:
        say("\nWhich VM should open attachments? Use a dedicated, isolated VM, never your everyday one.")
        vm.name = choose("VM", vms, vm.name if vm.name in vms else None)
    vm.snapshot = imported.get("snapshot") or (
        args.yes and vm.snapshot) or input(f"Clean snapshot name [{vm.snapshot}]: ").strip() or vm.snapshot
    say("\nChecking the VM (read-only; it is not started):")
    print_checks(preflight_checks(vm.name, vm.snapshot, vm.vboxmanage or None, hypervisor_present()))
    say("A '--' above is a warning, not a stop. Run `check` any time to see this list again.")
    vm.guest_user = imported.get("guest_user") or input(
        f"Guest Windows user{f' [{vm.guest_user}]' if vm.guest_user else ''}: ").strip() or vm.guest_user
    password = imported.get("guest_password")
    if password is None and (not vm.guest_password_sealed or not args.yes):
        typed = getpass.getpass("Guest Windows password (hidden; Enter keeps the saved one): ")
        password = typed or None
    if password is not None:
        vm.set_guest_password(password)
    if imported.get("dwell_seconds"):
        vm.dwell_seconds = int(imported["dwell_seconds"])
    if "pdf_viewer" in imported:
        vm.pdf_viewer = imported["pdf_viewer"]
    if not (vm.guest_user and vm.guest_password_sealed):
        raise SystemExit("A guest user and password are needed to open files inside the VM.")

    config.auto_run = ask_yes("\nWhen you ask E-TAP for a deeper analysis, open the attachments in this VM "
                              "automatically? (No = ask here each time)", True, args.yes)
    path = cfgmod.save(config)
    say(f"Saved to {path}.")
    return config


# -- pairing ----------------------------------------------------------------------

def _vm_summary(config: cfgmod.AgentConfig) -> dict:
    from .vbox import vboxmanage_version
    return {"name": config.vm.name, "snapshot": config.vm.snapshot, "provider": "virtualbox",
            "provider_version": vboxmanage_version(config.vm.vboxmanage or None) or ""}


def cmd_pair(args, config: cfgmod.AgentConfig) -> cfgmod.AgentConfig:
    if args.server:
        config.server_url = args.server
    client = Client(config.server_url)
    try:
        if config.is_registered:
            client.token = config.agent_token
            issued = client.new_pairing_code()
        else:
            issued = client.register(platform.node() or "My sandbox", _vm_summary(config))
            config.agent_id = issued["agent_id"]
            config.set_agent_token(issued["agent_token"])
            cfgmod.save(config)
            client.token = issued["agent_token"]
    except ServerError as exc:
        if exc.status == 401:
            say("The server no longer knows this agent; registering it again.")
            config.agent_id, config.agent_token_sealed = "", ""
            cfgmod.save(config)
            return cmd_pair(args, config)
        raise SystemExit(f"Pairing failed: {exc}")

    code = issued["pairing_code"]
    minutes = issued.get("pairing_expires_in", 600) // 60
    say("")
    say("=" * 44)
    say(f"   Your pairing code:   {code}")
    say("=" * 44)
    say("Enter it in the E-TAP extension (Deeper analysis > Pair) or on the")
    say(f"dashboard's Settings page. It works once and expires in {minutes} minutes.")
    say("Waiting for you to enter it...")
    # The server clears the code the moment a client claims it; a code that
    # stops being active before it expires has therefore been used.
    expires = time.time() + issued.get("pairing_expires_in", 600)
    while time.time() < expires - 2:
        time.sleep(3)
        try:
            me = client.me()
        except ServerError as exc:
            say(f"  (still waiting; {exc})")
            continue
        if not me.get("pairing_code_active"):
            if me.get("paired"):
                say("\nPaired. Your sandbox: online.")
                return config
            break
    raise SystemExit("The pairing code expired. Run `pair` again for a new one.")


# -- jobs --------------------------------------------------------------------------

def _vbox(config: cfgmod.AgentConfig):
    from .vbox import VBox
    vm = config.vm
    return VBox(vm=vm.name, snapshot=vm.snapshot, user=vm.guest_user, password=vm.guest_password,
                dwell=vm.dwell_seconds, exe=vm.vboxmanage or None)


def handle_job(client: Client, config: cfgmod.AgentConfig, job: dict, assume_yes: bool = False) -> dict:
    """Run one server job in the VM and upload the record. Returns the server's answer."""
    from . import runner

    job_id = job["job_id"]
    names = ", ".join(s["filename"] for s in job.get("samples") or []) or "no files"
    say(f"\nNew deeper-analysis job {job_id}: {names}")
    if not config.auto_run and not ask_yes("Open these attachments in your VM now?", True, assume_yes):
        say("Declined. E-TAP will show that the run was declined.")
        return client.result(job_id, {"items": [], "error": "Declined on the sandbox agent."})

    samples = []
    for sample in job.get("samples") or []:
        entry = {k: sample[k] for k in ("filename", "sha256", "archive", "archive_member", "inspection_error") if sample.get(k)}
        entry["content_b64"] = ""
        if sample.get("has_file"):
            entry["content_b64"] = base64.b64encode(client.sample(job_id, sample["index"])).decode("ascii")
        entry["index"] = sample["index"]
        samples.append(entry)

    if config.vm.pdf_viewer:
        os.environ["SANDBOX_PDF_VIEWER"] = config.vm.pdf_viewer

    def on_status(status: str) -> None:
        labels = {"starting": "Restoring the clean snapshot and starting the VM",
                  "interacting": "Opening the attachments", "collecting": "Collecting Sysmon events",
                  "restoring": "Restoring the clean snapshot"}
        say(f"  {labels.get(status, status)}...")
        try:
            client.progress(job_id, status)
        except ServerError as exc:
            logger.warning("Progress update failed: %s", exc)

    work_dir = cfgmod.config_dir() / "work" / job_id
    record = runner.run_job(job_id, samples, work_dir, vbox=_vbox(config), on_status=on_status)
    for item, sample in zip(record["items"], samples):
        item["index"] = sample["index"]
    payload = {
        "items": record["items"],
        "sysmon_xml_gz_b64": base64.b64encode(gzip.compress((record["sysmon_xml"] or "").encode("utf-8"))).decode("ascii"),
        "security_events": record["security_events"],
        "error": record["error"],
        "cleanup_error": record["cleanup_error"],
        "defender_checkpoint_error": record.get("defender_checkpoint_error"),
        "vm": _vm_summary(config),
    }
    for attempt in range(1, 4):
        try:
            answer = client.result(job_id, payload)
            say(f"  Done ({answer.get('status')}). The E-TAP report updates by itself.")
            return answer
        except ServerError as exc:
            if exc.status and exc.status < 500:
                say(f"  The server refused the result: {exc}")
                return {"status": "refused"}
            say(f"  Upload failed ({exc}); retrying ({attempt}/3)...")
            time.sleep(5 * attempt)
    say("  Could not upload the result; the report will show the run as incomplete.")
    return {"status": "upload_failed"}


def cmd_run(args, config: cfgmod.AgentConfig) -> None:
    if not config.is_registered:
        raise SystemExit("This agent is not paired yet. Run `pair` first.")
    client = Client(config.server_url, config.agent_token)
    try:
        if not client.me().get("paired"):
            raise SystemExit("This agent has no paired E-TAP client yet. Run `pair` first.")
    except ServerError as exc:
        raise SystemExit(f"Cannot use this agent: {exc}")
    say(f"\nYour sandbox: online ({config.vm.name}, snapshot '{config.vm.snapshot}').")
    say(f"Waiting for deeper-analysis requests from {config.server_url}. Press Ctrl+C to stop.")
    offline_since = None
    while True:
        try:
            job = client.next_job()
            if offline_since:
                say("Connection restored. Your sandbox: online.")
                offline_since = None
        except ServerError as exc:
            if exc.status == 401:
                raise SystemExit("The server no longer accepts this agent. Run `pair` again.")
            if not offline_since:
                say(f"Connection problem: {exc}. Retrying...")
                offline_since = time.time()
            time.sleep(POLL_SECONDS * 2)
            continue
        if job:
            handle_job(client, config, job, args.yes)
            if args.once:
                return
            continue
        time.sleep(POLL_SECONDS)


# -- diagnostics ---------------------------------------------------------------------

def cmd_check(args, config: cfgmod.AgentConfig) -> None:
    """Read-only preflight: nothing is started, restored or changed."""
    if not config.is_set_up:
        raise SystemExit("Run `setup` first.")
    say(f"Checking this computer and VM '{config.vm.name}' (read-only; the VM is not started):")
    checks, _vms = system_checks(config.vm.vboxmanage or None)
    checks = [c for c in checks if not c.name.startswith("Windows Sandbox")]
    checks += preflight_checks(config.vm.name, config.vm.snapshot, config.vm.vboxmanage or None, hypervisor_present())
    print_checks(checks)
    needs_attention = [c for c in checks if not c.ok]
    say(f"\n{len(checks) - len(needs_attention)} of {len(checks)} checks passed."
        + (f" {len(needs_attention)} need attention (see 'Fix' above)." if needs_attention else ""))
    say("These checks cannot see inside the VM. To confirm the guest login, Sysmon and Windows Defender,")
    say("run `test`; it restores the snapshot and starts the VM briefly.")


def cmd_test(args, config: cfgmod.AgentConfig) -> None:
    if not config.is_set_up:
        raise SystemExit("Run `setup` first.")
    say(f"This restores VM '{config.vm.name}' to snapshot '{config.vm.snapshot}', starts it in the background,")
    say("checks that the guest login and Sysmon work, and restores the snapshot again.")
    if not ask_yes("Go ahead?", False, args.yes):
        return
    vbox = _vbox(config)
    try:
        say("  Restoring and starting the VM (this can take a minute or two)...")
        vbox.full_cycle()
        say("  Guest login works.")
        result = vbox.run_exe(r"C:\Windows\System32\wevtutil.exe", "gli", "Microsoft-Windows-Sysmon/Operational", timeout_s=30)
        # `wevtutil gli` prints the log's numberOfLogRecords only when the log exists.
        ok = "numberoflogrecords" in (result.stdout or "").lower()
        say("  Sysmon log found." if ok else "  Sysmon log NOT found: install Sysmon in the VM and retake the snapshot.")
        from .runner import defender_checkpoint
        started = time.monotonic()
        baseline, reason = defender_checkpoint(vbox)
        took = time.monotonic() - started
        if baseline >= 0:
            say(f"  Windows Defender log readable (latest record {baseline}, {took:.0f} s).")
        else:
            say(f"  Windows Defender log NOT readable after {took:.0f} s: {reason}")
    except Exception as exc:
        say(f"  Test failed: {exc}")
    finally:
        say("  Restoring the clean snapshot...")
        try:
            vbox.restore()
        except Exception as exc:
            say(f"  Could not restore the snapshot: {exc}")
    say("Test finished.")


def cmd_status(args, config: cfgmod.AgentConfig) -> None:
    say(f"Settings file: {cfgmod.config_path()}")
    say(f"Server: {config.server_url}")
    say(f"VM: {config.vm.name or '(not set)'} / snapshot '{config.vm.snapshot}' / user {config.vm.guest_user or '(not set)'}")
    say(f"Open attachments automatically: {'yes' if config.auto_run else 'ask each time'}")
    if not config.is_registered:
        say("Pairing: not registered with the server yet.")
        return
    try:
        me = Client(config.server_url, config.agent_token).me()
        say(f"Pairing: {'paired' if me.get('paired') else 'registered, waiting for a code to be entered'}")
    except ServerError as exc:
        say(f"Pairing: could not check ({exc})")


def cmd_start(args, config: cfgmod.AgentConfig) -> None:
    if args.server and args.server.rstrip("/") != config.server_url.rstrip("/"):
        config.server_url = args.server
        config.agent_id, config.agent_token_sealed = "", ""
        cfgmod.save(config)
    if not config.is_set_up:
        config = cmd_setup(args, config)
    paired = False
    if config.is_registered:
        try:
            paired = bool(Client(config.server_url, config.agent_token).me().get("paired"))
        except ServerError as exc:
            if exc.status != 401:
                raise SystemExit(f"Cannot reach the E-TAP server: {exc}")
    if not paired:
        config = cmd_pair(args, config)
    cmd_run(args, config)


def main(argv: list[str] | None = None) -> None:
    parser = argparse.ArgumentParser(prog="python -m sandbox_agent", description=f"E-TAP Sandbox Agent {__version__}")
    parser.add_argument("command", nargs="?", default="start",
                        choices=["start", "setup", "pair", "run", "check", "test", "status", "forget"])
    parser.add_argument("--server", help=f"E-TAP server URL (default {cfgmod.DEFAULT_SERVER})")
    parser.add_argument("--from-env", metavar="PATH", help="read the VM settings from an E-TAP .env file")
    parser.add_argument("--yes", action="store_true", help="answer yes to every question")
    parser.add_argument("--once", action="store_true", help="exit after one job")
    parser.add_argument("--verbose", action="store_true")
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(levelname)s %(message)s")

    config = cfgmod.load()
    try:
        if args.command == "forget":
            if ask_yes("Delete this agent's saved settings (VM login and pairing)?", False, args.yes):
                say("Deleted." if cfgmod.forget() else "Nothing saved.")
        elif args.command == "setup":
            cmd_setup(args, config)
        elif args.command == "pair":
            cmd_pair(args, config)
        elif args.command == "run":
            cmd_run(args, config)
        elif args.command == "check":
            cmd_check(args, config)
        elif args.command == "test":
            cmd_test(args, config)
        elif args.command == "status":
            cmd_status(args, config)
        else:
            cmd_start(args, config)
    except KeyboardInterrupt:
        say("\nStopped. Your sandbox: offline.")
