from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from typing import Protocol

# Span kinds: token types (HOST, IP, USER, ...) map 1:1 to a token. The lowercase
# composite kinds below are rendered from several tokens by the redactor.
FQDN = "fqdn"  # dc01.corp.acme.com -> HOST_001.DOMAIN_001
EMAIL = "email"  # jdoe@acme.com -> USER_001@DOMAIN_001
ADUSER = "aduser"  # ACME\jdoe -> ORG_001\USER_001

# Overlap tie-breakers (longest span wins first).
PRIO_VAULT = -1
PRIO_GENERIC = 0
PRIO_SPECIFIC = 1
PRIO_DICTIONARY = 2
PRIO_SECRET = 3


@dataclass(frozen=True)
class Span:
    start: int
    end: int
    kind: str
    value: str
    priority: int = PRIO_GENERIC

    @property
    def length(self) -> int:
        return self.end - self.start


class Detector(Protocol):
    def find(self, text: str) -> Iterable[Span]: ...
