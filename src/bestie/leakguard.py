"""Last line of defence: scan what is about to leave the machine."""

from __future__ import annotations

from collections.abc import Iterable

from .detect.dictionary import MIN_TERM_LENGTH, MIN_VAULT_LENGTH, terms_regex
from .redactor import Redactor


class LeakDetected(Exception):
    def __init__(self, problems: list[str]) -> None:
        self.problems = problems
        super().__init__("; ".join(problems))


class LeakGuard:
    def __init__(self, redactor: Redactor) -> None:
        self.redactor = redactor
        self._known = None
        self._known_version = -1
        self._known_kinds: dict[str, str] = {}

    def _known_regex(self):
        vault = self.redactor.vault
        if self._known is None or self._known_version != vault.version:
            # Same thresholds as the detectors, so anything they would mask counts.
            kinds = {t: k for t, k in self.redactor.dict_kinds.items() if len(t) >= MIN_TERM_LENGTH}
            for e in vault.entries():
                if len(e.value.strip()) >= MIN_VAULT_LENGTH:
                    kinds.setdefault(e.value.strip().lower(), e.type)
            self._known_kinds = kinds
            self._known = terms_regex(kinds, MIN_TERM_LENGTH)
            self._known_version = vault.version
        return self._known

    def problems(self, texts: Iterable[str], *, deep: bool = True) -> list[str]:
        """Descriptions of what leaked. Values are never included."""
        found: list[str] = []
        known = self._known_regex()
        for text in texts:
            if not text:
                continue
            if known is not None:
                for m in known.finditer(text):
                    kind = self._known_kinds.get(m.group(0).lower(), "value")
                    found.append(f"known {kind} value still present")
            if deep:
                for span in self.redactor.spans(text):
                    found.append(f"undetected {span.kind} value still present")
        return sorted(set(found))

    def check(self, texts: Iterable[str], *, deep: bool = True) -> None:
        problems = self.problems(texts, deep=deep)
        if problems:
            raise LeakDetected(problems)
