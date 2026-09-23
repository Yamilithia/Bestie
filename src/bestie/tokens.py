"""Placeholder token format.

Every sensitive value is replaced by a typed token such as ``HOST_001``. The type
tells the model what kind of thing it is looking at; the number keeps distinct
values distinct and identical values identical.
"""

from __future__ import annotations

import re

HOST = "HOST"
IP = "IP"
NET = "NET"
DOMAIN = "DOMAIN"
USER = "USER"
ORG = "ORG"
CUSTOMER = "CUSTOMER"
TERM = "TERM"
HASH = "HASH"
SECRET = "SECRET"
MAC = "MAC"
SID = "SID"

TYPES: tuple[str, ...] = (
    HOST,
    IP,
    NET,
    DOMAIN,
    USER,
    ORG,
    CUSTOMER,
    TERM,
    HASH,
    SECRET,
    MAC,
    SID,
)

# Longest names first so the alternation never stops at a shorter prefix.
_TYPE_ALT = "|".join(sorted(TYPES, key=len, reverse=True))

TOKEN_RE = re.compile(rf"(?<![A-Za-z0-9])(?:{_TYPE_ALT})_\d{{3,}}(?!\d)")
_TOKEN_FULL_RE = re.compile(rf"(?:{_TYPE_ALT})_\d{{3,}}")

# Trailing text that could still grow into a token (used while streaming).
_PARTIAL_RE = re.compile(r"(?<![A-Za-z0-9])[A-Z]{1,8}(?:_\d*)?$")


def format_token(type_: str, number: int) -> str:
    return f"{type_}_{number:03d}"


def is_token(value: str) -> bool:
    return _TOKEN_FULL_RE.fullmatch(value) is not None


def partial_token_start(text: str) -> int | None:
    """Return the index where an incomplete (or possibly still growing) token
    starts at the end of ``text``, or None if the tail is safe to emit."""
    m = _PARTIAL_RE.search(text)
    if not m:
        return None
    letters, sep, _ = m.group(0).partition("_")
    if sep:
        ok = letters in TYPES
    else:
        ok = any(t.startswith(letters) for t in TYPES)
    return m.start() if ok else None
