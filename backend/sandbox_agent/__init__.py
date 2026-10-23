"""
E-TAP Sandbox Agent
===================
Runs on the user's own computer, next to their VirtualBox VM. It pairs once
with an E-TAP server, then asks the server for attachment jobs, opens each
attachment in the VM's clean snapshot and uploads what Sysmon recorded.
The server never reaches into the user's machine: every request is outbound.

Start it with `python -m sandbox_agent` (see README.md in this folder).
"""

__version__ = "0.1.0"
