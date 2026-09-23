"""Exact-term detectors: your dictionary, and values already in the vault."""

from __future__ import annotations

import re
from collections.abc import Iterable, Iterator

from .base import PRIO_DICTIONARY, PRIO_VAULT, Span

# Values shorter than this are not matched on their own (too many false hits).
# Dictionary terms are explicit, so they may be shorter than learnt vault values
# (a learnt "soc" from soc@globex.com must not eat every "SOC" in the text).
MIN_TERM_LENGTH = 3
MIN_VAULT_LENGTH = 4


def terms_regex(terms: Iterable[str], min_length: int = MIN_TERM_LENGTH) -> re.Pattern[str] | None:
    """Case-insensitive alternation of whole-word terms, longest first."""
    unique = {t.strip() for t in terms if len(t.strip()) >= min_length}
    if not unique:
        return None
    alt = "|".join(re.escape(t) for t in sorted(unique, key=len, reverse=True))
    return re.compile(rf"(?i)(?<![\w])(?:{alt})(?![\w])")


class TermDetector:
    """Maps each term to a kind (token type)."""

    def __init__(
        self,
        terms: dict[str, str],
        priority: int = PRIO_DICTIONARY,
        min_length: int = MIN_TERM_LENGTH,
    ) -> None:
        self._kinds = {k.strip().lower(): v for k, v in terms.items()}
        self._rx = terms_regex(terms, min_length)
        self.priority = priority

    def find(self, text: str) -> Iterator[Span]:
        if self._rx is None:
            return
        for m in self._rx.finditer(text):
            kind = self._kinds.get(m.group(0).lower())
            if kind:
                yield Span(m.start(), m.end(), kind, m.group(0), self.priority)


def vault_detector(entries: Iterable[tuple[str, str]]) -> TermDetector:
    """Detector for (type, value) pairs already known to the vault."""
    return TermDetector({value: type_ for type_, value in entries}, PRIO_VAULT, MIN_VAULT_LENGTH)
