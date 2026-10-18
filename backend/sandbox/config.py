"""Sandbox paths are anchored to the repository, never the server's cwd."""
from pathlib import Path
import os

SANDBOX_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SANDBOX_DIR.parents[1]


def sandbox_path(variable: str, default_name: str) -> Path:
    configured = os.getenv(variable, "").strip()
    path = Path(configured).expanduser() if configured else SANDBOX_DIR / default_name
    if not path.is_absolute():
        path = PROJECT_ROOT / path
    return path.resolve()


def rules_path() -> Path:
    path = sandbox_path("SANDBOX_RULES_DIR", "rules")
    if not path.is_dir():
        raise ValueError(f"Sandbox rules directory does not exist: {path}")
    return path
