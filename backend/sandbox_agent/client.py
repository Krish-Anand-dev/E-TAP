"""
sandbox_agent.client -- the agent's HTTPS calls to the E-TAP server.
====================================================================
Standard library only, so the agent needs nothing installed beyond Python.
Every request is outbound; the server never connects to this machine.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from typing import Any

from . import __version__


class ServerError(Exception):
    def __init__(self, message: str, status: int | None = None):
        super().__init__(message)
        self.status = status


class Client:
    def __init__(self, server_url: str, token: str = "", timeout: int = 60):
        self.base = server_url.rstrip("/")
        self.token = token
        self.timeout = timeout

    def _request(self, method: str, path: str, body: Any = None, raw: bool = False,
                 timeout: int | None = None) -> Any:
        data = None
        headers = {"User-Agent": f"etap-sandbox-agent/{__version__}", "Accept": "application/json"}
        if body is not None:
            data = json.dumps(body).encode("utf-8")
            headers["Content-Type"] = "application/json"
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"
        request = urllib.request.Request(self.base + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(request, timeout=timeout or self.timeout) as response:
                payload = response.read()
        except urllib.error.HTTPError as exc:
            try:
                detail = json.loads(exc.read() or b"{}").get("detail")
            except ValueError:
                detail = None
            raise ServerError(detail or f"Server answered {exc.code}", exc.code) from None
        except (urllib.error.URLError, TimeoutError, OSError) as exc:
            raise ServerError(f"Cannot reach {self.base} ({getattr(exc, 'reason', exc)})") from None
        if raw:
            return payload
        return json.loads(payload or b"{}")

    # -- calls ------------------------------------------------------------
    def register(self, name: str, vm: dict) -> dict:
        return self._request("POST", "/sandbox/agent/register",
                             {"name": name, "version": __version__, "vm": vm})

    def me(self) -> dict:
        return self._request("GET", "/sandbox/agent/me")

    def new_pairing_code(self) -> dict:
        return self._request("POST", "/sandbox/agent/pairing-code", {})

    def next_job(self, health: dict | None = None) -> dict | None:
        """Ask for work. The VM's health rides along so the dashboard can tell the truth."""
        return self._request("POST", "/sandbox/agent/jobs/next", {"health": health} if health else {}).get("job")

    def sample(self, job_id: str, index: int) -> bytes:
        return self._request("GET", f"/sandbox/agent/jobs/{job_id}/samples/{index}", raw=True, timeout=180)

    def progress(self, job_id: str, status: str) -> None:
        self._request("POST", f"/sandbox/agent/jobs/{job_id}/progress", {"status": status})

    def result(self, job_id: str, payload: dict) -> dict:
        return self._request("POST", f"/sandbox/agent/jobs/{job_id}/result", payload, timeout=300)
