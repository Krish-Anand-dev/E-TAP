"""
One big analysis at a time.

Parsing an email with a large attachment is memory hungry: the standard email parser, the base64
copy kept for each attachment and the later checks together need roughly ten times the attachment's
size at the peak (about 325 MB for a 25 MB file, measured). A free Render service has 512 MB and
already uses about 110 MB when idle, so two big analyses at once could run it out of memory.

`heavy_analysis(size)` lets small analyses through untouched and makes big ones take turns. It is
shared by the website routes and the WhatsApp bot, since they run in the same process. When a big
analysis ends it also hands freed memory back to the operating system where it can, so repeated big
files do not slowly grow the process.
"""
from __future__ import annotations

import contextlib
import ctypes
import gc
import threading

HEAVY_BYTES = 8 * 1024 * 1024
_gate = threading.Semaphore(1)


def release_memory() -> None:
    """Best effort: collect garbage and ask glibc to return free pages (Linux). Never raises."""
    try:
        gc.collect()
        ctypes.CDLL("libc.so.6").malloc_trim(0)
    except Exception:
        pass


@contextlib.contextmanager
def heavy_analysis(size: int):
    """Wrap the analysis of a message of `size` bytes; big ones wait their turn."""
    if size <= HEAVY_BYTES:
        yield
        return
    with _gate:
        try:
            yield
        finally:
            release_memory()
