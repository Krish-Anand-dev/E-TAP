"""
sandbox_agent.protect -- keep the agent's secrets unreadable to other Windows users.
===================================================================================
Uses Windows DPAPI (CryptProtectData, current-user scope) so the saved
agent token and VM guest password can only be decrypted by the same
Windows account on the same machine. Other platforms store them as plain
base64 and say so.
"""

from __future__ import annotations

import base64
import sys

_DPAPI = "dpapi:"
_PLAIN = "plain:"


def _blob_type():
    import ctypes
    from ctypes import wintypes

    class DATA_BLOB(ctypes.Structure):
        _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_char))]

    return DATA_BLOB


def _dpapi(data: bytes, protect: bool) -> bytes:
    import ctypes
    DATA_BLOB = _blob_type()
    buffer = ctypes.create_string_buffer(data, len(data))
    blob_in = DATA_BLOB(len(data), ctypes.cast(buffer, ctypes.POINTER(ctypes.c_char)))
    blob_out = DATA_BLOB()
    crypt32 = ctypes.windll.crypt32
    fn = crypt32.CryptProtectData if protect else crypt32.CryptUnprotectData
    # CRYPTPROTECT_UI_FORBIDDEN = 0x1: never show a prompt.
    ok = fn(ctypes.byref(blob_in), None, None, None, None, 0x1, ctypes.byref(blob_out))
    if not ok:
        raise OSError("Windows could not protect or read the saved secret.")
    try:
        return ctypes.string_at(blob_out.pbData, blob_out.cbData)
    finally:
        ctypes.windll.kernel32.LocalFree(blob_out.pbData)


def is_protected_storage() -> bool:
    return sys.platform == "win32"


def seal(secret: str) -> str:
    if not secret:
        return ""
    raw = secret.encode("utf-8")
    if is_protected_storage():
        return _DPAPI + base64.b64encode(_dpapi(raw, True)).decode("ascii")
    return _PLAIN + base64.b64encode(raw).decode("ascii")


def unseal(stored: str) -> str:
    if not stored:
        return ""
    if stored.startswith(_DPAPI):
        return _dpapi(base64.b64decode(stored[len(_DPAPI):]), False).decode("utf-8")
    if stored.startswith(_PLAIN):
        return base64.b64decode(stored[len(_PLAIN):]).decode("utf-8")
    raise ValueError("Unrecognised saved secret.")
