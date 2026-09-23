"""Append-only JSONL audit trail. Records types and counts, never real values."""

from __future__ import annotations

import json
import os
import time
from collections.abc import Mapping
from pathlib import Path


def record(log_path: Path, event: str, **fields) -> None:
    entry = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S%z"), "event": event}
    for key, value in fields.items():
        entry[key] = dict(value) if isinstance(value, Mapping) else value
    log_path.parent.mkdir(parents=True, exist_ok=True)
    new = not log_path.exists()
    with open(log_path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
    if new:
        os.chmod(log_path, 0o600)


def tail(path: Path, n: int = 20) -> list[dict]:
    if not path.exists():
        return []
    lines = path.read_text(encoding="utf-8").splitlines()[-n:]
    return [json.loads(line) for line in lines if line.strip()]
