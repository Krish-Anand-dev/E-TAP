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

DEFAULT_SERVER = "https://etap-backend-od1c.onrender.com"


def config_dir() -> Path:
    override = os.getenv("ETAP_AGENT_HOME")
    if override:
        return Path(override)
    base = os.getenv("APPDATA") or str(Path.home() / ".config")
    return Path(base) / "E-TAP Sandbox Agent"


def config_path() -> Path:
    return config_dir() / "config.json"


@dataclass
class VMSettings:
    name: str = ""
    snapshot: str = "clean"
    guest_user: str = ""
    guest_password_sealed: str = ""
    vboxmanage: str = ""
    dwell_seconds: int = 30
    pdf_viewer: str = ""

    @property
    def guest_password(self) -> str:
        return unseal(self.guest_password_sealed)

    def set_guest_password(self, password: str) -> None:
        self.guest_password_sealed = seal(password)


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
        return bool(self.vm.name and self.vm.guest_user and self.vm.guest_password_sealed)

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
