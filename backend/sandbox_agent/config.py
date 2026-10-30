"""
sandbox_agent.config -- the agent's saved settings.
===================================================
One JSON file in the user's profile (%APPDATA%\\E-TAP Sandbox Agent on
Windows). Secrets inside it (the agent token and the VM guest password)
are sealed with DPAPI; see protect.py.
"""

from __future__ import annotations

import json
import os
from dataclasses import asdict, dataclass, field
from pathlib import Path

from .protect import seal, unseal

FALLBACK_SERVER = "https://etap-backend-2std.onrender.com"


def bundled_server() -> str:
    """The server this agent was downloaded from (server_url.txt in the zip), else the fallback."""
    try:
        text = Path(__file__).with_name("server_url.txt").read_text(encoding="utf-8").strip()
    except OSError:
        return FALLBACK_SERVER
    return text.rstrip("/") if text.startswith(("http://", "https://")) else FALLBACK_SERVER


DEFAULT_SERVER = bundled_server()


def config_dir() -> Path:
    override = os.getenv("ETAP_AGENT_HOME")
    if override:
        return Path(override)
    base = os.getenv("APPDATA") or str(Path.home() / ".config")
    return Path(base) / "E-TAP Sandbox Agent"


def config_path() -> Path:
    return config_dir() / "config.json"


PROVIDERS = ("virtualbox", "vmware")


@dataclass
class VMSettings:
    name: str = ""            # VirtualBox VM name, or a display name for a VMware VM
    snapshot: str = "clean"
    guest_user: str = ""
    guest_password_sealed: str = ""
    vboxmanage: str = ""
    # Which hypervisor runs the VM. Older settings files have none of these three and
    # load as VirtualBox, so an agent set up before VMware support keeps working.
    provider: str = "virtualbox"
    vmrun: str = ""           # path to vmrun.exe (VMware only; empty = find it)
    vmx_path: str = ""        # the VM's .vmx file (VMware only)
    dwell_seconds: int = 30
    pdf_viewer: str = ""
    # True only after the VM was started once and Windows accepted this user and password.
    login_verified: bool = False

    @property
    def guest_password(self) -> str:
        return unseal(self.guest_password_sealed)

    def set_guest_password(self, password: str) -> None:
        self.guest_password_sealed = seal(password)
        self.login_verified = False  # a new password has not been checked yet


@dataclass
class AgentConfig:
    server_url: str = DEFAULT_SERVER
    agent_id: str = ""
    agent_token_sealed: str = ""
    auto_run: bool = True
    vm: VMSettings = field(default_factory=VMSettings)

    @property
    def agent_token(self) -> str:
        return unseal(self.agent_token_sealed)

    def set_agent_token(self, token: str) -> None:
        self.agent_token_sealed = seal(token)

    @property
    def is_set_up(self) -> bool:
        vm = self.vm
        has_vm = bool(vm.name and (vm.vmx_path if vm.provider == "vmware" else True))
        return bool(has_vm and vm.guest_user and vm.guest_password_sealed and vm.login_verified)

    @property
    def is_registered(self) -> bool:
        return bool(self.agent_id and self.agent_token_sealed)


def load() -> AgentConfig:
    path = config_path()
    if not path.exists():
        return AgentConfig()
    data = json.loads(path.read_text(encoding="utf-8"))
    vm = VMSettings(**{k: v for k, v in (data.pop("vm", None) or {}).items() if k in VMSettings.__dataclass_fields__})
    return AgentConfig(vm=vm, **{k: v for k, v in data.items() if k in AgentConfig.__dataclass_fields__ and k != "vm"})


def save(config: AgentConfig) -> Path:
    path = config_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(asdict(config), indent=2), encoding="utf-8")
    return path


def forget() -> bool:
    path = config_path()
    if path.exists():
        path.unlink()
        return True
    return False
