"""The vault: a local, persistent, two-way map between real values and tokens."""

from __future__ import annotations

import ipaddress
import json
import os
import tempfile
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

from . import tokens as T

# Types whose values compare case-insensitively (dc01 == DC01).
_CASE_INSENSITIVE = {T.HOST, T.DOMAIN, T.USER, T.ORG, T.CUSTOMER, T.TERM, T.HASH, T.MAC, T.SID}


def normalize(type_: str, value: str) -> str:
    value = value.strip()
    if type_ == T.IP:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            return value.lower()
    if type_ == T.NET:
        try:
            return str(ipaddress.ip_network(value, strict=False))
        except ValueError:
            return value.lower()
    if type_ == T.DOMAIN:
        return value.lower().rstrip(".")
    if type_ == T.MAC:
        return value.lower().replace("-", ":")
    if type_ in _CASE_INSENSITIVE:
        return value.lower()
    return value


@dataclass(frozen=True)
class Entry:
    token: str
    type: str
    value: str


class Vault:
    def __init__(self, name: str = "default", path: Path | None = None) -> None:
        self.name = name
        self.path = path
        self._by_key: dict[tuple[str, str], str] = {}
        self._by_token: dict[str, Entry] = {}
        self._counters: dict[str, int] = {}
        self._lock = threading.RLock()
        self._dirty = False
        self.version = 0

    # -- persistence -------------------------------------------------------
    @classmethod
    def load(cls, name: str, path: Path | None) -> Vault:
        vault = cls(name, path)
        if path is not None and path.exists():
            data = json.loads(path.read_text())
            for item in data.get("entries", []):
                vault._add(Entry(item["token"], item["type"], item["value"]))
            for type_, n in data.get("counters", {}).items():
                vault._counters[type_] = max(vault._counters.get(type_, 0), int(n))
        vault._dirty = False
        return vault

    def save(self) -> None:
        with self._lock:
            if self.path is None or not self._dirty:
                return
            self.path.parent.mkdir(parents=True, exist_ok=True)
            os.chmod(self.path.parent, 0o700)
            data = {
                "version": 1,
                "name": self.name,
                "counters": self._counters,
                "entries": [e.__dict__ for e in self._by_token.values()],
            }
            fd, tmp = tempfile.mkstemp(dir=self.path.parent, prefix=".vault-")
            try:
                if hasattr(os, "fchmod"):  # POSIX only; Windows ACLs protect the profile dir
                    os.fchmod(fd, 0o600)
                with os.fdopen(fd, "w") as fh:
                    json.dump(data, fh, indent=1, ensure_ascii=False)
                os.replace(tmp, self.path)
            except BaseException:
                if os.path.exists(tmp):
                    os.unlink(tmp)
                raise
            self._dirty = False

    def snapshot(self) -> Vault:
        """In-memory copy that never persists (used by preview)."""
        with self._lock:
            copy = Vault(self.name, None)
            for entry in self._by_token.values():
                copy._add(entry)
            copy._counters = dict(self._counters)
            return copy

    # -- mapping -----------------------------------------------------------
    def _add(self, entry: Entry) -> None:
        self._by_key[(entry.type, normalize(entry.type, entry.value))] = entry.token
        self._by_token[entry.token] = entry
        number = int(entry.token.rsplit("_", 1)[1])
        self._counters[entry.type] = max(self._counters.get(entry.type, 0), number)
        self.version += 1

    def token_for(self, type_: str, value: str) -> str:
        if type_ not in T.TYPES:
            raise ValueError(f"unknown token type {type_!r}")
        key = (type_, normalize(type_, value))
        with self._lock:
            token = self._by_key.get(key)
            if token is None:
                token = T.format_token(type_, self._counters.get(type_, 0) + 1)
                self._add(Entry(token, type_, value.strip()))
                self._dirty = True
            return token

    def find(self, type_: str, value: str) -> str | None:
        return self._by_key.get((type_, normalize(type_, value)))

    def lookup(self, token: str) -> str | None:
        entry = self._by_token.get(token)
        return entry.value if entry else None

    def entries(self) -> Iterator[Entry]:
        with self._lock:
            yield from list(self._by_token.values())

    def __len__(self) -> int:
        return len(self._by_token)

    def clear(self) -> None:
        with self._lock:
            self._by_key.clear()
            self._by_token.clear()
            self._counters.clear()
            self._dirty = True
            self.version += 1
