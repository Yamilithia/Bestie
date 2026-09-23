"""Restore tokens in streamed text, where a token may be split across chunks."""

from __future__ import annotations

from collections.abc import Callable

from .tokens import partial_token_start


class StreamRehydrator:
    """Feed chunks in, get restored text out. Text that could still be the start
    of a token (``HOST_0``) is held back until the next chunk or ``flush()``."""

    def __init__(self, rehydrate: Callable[[str], str]) -> None:
        self._rehydrate = rehydrate
        self._buf = ""

    def feed(self, chunk: str) -> str:
        self._buf += chunk
        cut = partial_token_start(self._buf)
        if cut is None:
            ready, self._buf = self._buf, ""
        else:
            ready, self._buf = self._buf[:cut], self._buf[cut:]
        return self._rehydrate(ready)

    def flush(self) -> str:
        ready, self._buf = self._buf, ""
        return self._rehydrate(ready)
