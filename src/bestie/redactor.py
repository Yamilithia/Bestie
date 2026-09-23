"""Redact text into tokens and restore tokens back into real values."""

from __future__ import annotations

import bisect
import json
import logging
import re
from collections import Counter
from collections.abc import Iterable

from . import tokens as T
from .config import Dictionary
from .detect.allowlist import Allowlist
from .detect.base import ADUSER, EMAIL, FQDN, Detector, Span
from .detect.dictionary import TermDetector, vault_detector
from .detect.domains import PLATFORM_SUFFIXES, registrable_split
from .detect.patterns import (
    ADUserDetector,
    EmailDetector,
    FQDNDetector,
    HashDetector,
    HostnamePatternDetector,
    IPDetector,
    KeyValueDetector,
    MACDetector,
    ProfilePathDetector,
    SecretDetector,
    SIDDetector,
    UNCDetector,
)
from .vault import Vault

log = logging.getLogger(__name__)

# Generic sub-domain labels kept readable: www.evil.com -> www.DOMAIN_002
COMMON_LABELS = frozenset(
    "www www2 mail smtp imap pop mx ns ns1 ns2 dns api cdn static img ftp vpn remote "
    "portal login auth sso webmail autodiscover m app apps secure".split()
)

_DICT_KINDS = (
    ("orgs", T.ORG),
    ("customers", T.CUSTOMER),
    ("internal_domains", T.DOMAIN),
    ("ad_domains", T.DOMAIN),
    ("hosts", T.HOST),
    ("users", T.USER),
    ("terms", T.TERM),
)


class Redactor:
    def __init__(
        self,
        vault: Vault,
        dictionary: Dictionary | None = None,
        *,
        redact_hashes: bool = True,
        platform_suffixes: Iterable[str] = (),
    ) -> None:
        self.vault = vault
        self.dictionary = dictionary or Dictionary()
        d = self.dictionary
        self.allow = Allowlist(d.allow)
        self.internal = sorted(
            {s.lower().strip(".") for s in d.internal_domains if s.strip(".")},
            key=len,
            reverse=True,
        )
        self.platforms = sorted(
            {s.lower().strip(".") for s in (*PLATFORM_SUFFIXES, *platform_suffixes)},
            key=len,
            reverse=True,
        )
        self.dict_kinds: dict[str, str] = {}
        for field, kind in _DICT_KINDS:
            for term in getattr(d, field):
                self.dict_kinds.setdefault(term.strip().lower(), kind)

        self.detectors: list[Detector] = [
            SecretDetector(),
            IPDetector(),
            EmailDetector(),
            ADUserDetector(),
            KeyValueDetector(),
            UNCDetector(),
            ProfilePathDetector(),
            MACDetector(),
            SIDDetector(),
            FQDNDetector(self.internal),
            HostnamePatternDetector(d.hostname_patterns),
            TermDetector(self.dict_kinds),
        ]
        if redact_hashes:
            self.detectors.append(HashDetector())
        self._vault_det: TermDetector | None = None
        self._vault_det_version = -1
        self.unknown_tokens: set[str] = set()

    # ------------------------------------------------------------ detection
    def _vault_detector(self) -> TermDetector:
        if self._vault_det is None or self._vault_det_version != self.vault.version:
            self._vault_det = vault_detector((e.type, e.value) for e in self.vault.entries())
            self._vault_det_version = self.vault.version
        return self._vault_det

    def _is_internal(self, domain: str) -> bool:
        d = domain.lower().rstrip(".")
        return any(d == s or d.endswith("." + s) for s in self.internal)

    def _platform(self, domain: str) -> str | None:
        d = domain.lower().rstrip(".")
        for p in self.platforms:
            if d == p or d.endswith("." + p):
                return p
        return None

    def _allowed(self, span: Span) -> bool:
        kind, value = span.kind, span.value
        if kind == T.IP:
            return self.allow.ip(value)
        if kind == T.NET:
            return self.allow.network(value)
        if kind == FQDN:
            if self._is_internal(value):
                return False
            platform = self._platform(value)
            if platform is not None:
                return value.lower().rstrip(".") == platform
            return self.allow.domain(value)
        if kind in (EMAIL, ADUSER):
            return self.allow.word(value)
        if kind in (T.SECRET, T.DOMAIN, T.ORG, T.CUSTOMER, T.TERM):
            return False
        return self.allow.word(value)

    def spans(self, text: str) -> list[Span]:
        """All sensitive spans in ``text``: validated, allowlist-filtered and
        overlap-resolved (longest wins, then priority)."""
        detectors = [*self.detectors, self._vault_detector()]
        candidates = [
            s
            for det in detectors
            for s in det.find(text)
            if s.length > 0 and not T.TOKEN_RE.search(s.value) and not self._allowed(s)
        ]
        candidates.sort(key=lambda s: (-s.length, -s.priority, s.start))
        starts: list[int] = []
        accepted: list[Span] = []
        for s in candidates:
            i = bisect.bisect_right(starts, s.start)
            if i > 0 and accepted[i - 1].end > s.start:
                continue
            if i < len(accepted) and accepted[i].start < s.end:
                continue
            starts.insert(i, s.start)
            accepted.insert(i, s)
        return accepted

    # ------------------------------------------------------------ rendering
    def _tok(self, kind: str, value: str) -> str:
        return self.vault.token_for(kind, value)

    def _tok_named(self, default_kind: str, value: str) -> str:
        """Prefer the dictionary's kind (acme.sharepoint.com -> ORG_001.sharepoint.com)."""
        return self._tok(self.dict_kinds.get(value.lower(), default_kind), value)

    def _render_prefix(self, prefix: str) -> str:
        if prefix.lower() in COMMON_LABELS:
            return prefix
        return self._tok_named(T.HOST, prefix)

    def _render_domain(self, domain: str) -> str:
        d = domain.rstrip(".")
        low = d.lower()
        for s in self.internal:
            if low == s:
                return self._tok_named(T.DOMAIN, d)
            if low.endswith("." + s):
                prefix, suffix = d[: -len(s) - 1], d[-len(s) :]
                return f"{self._render_prefix(prefix)}.{self._tok_named(T.DOMAIN, suffix)}"
        platform = self._platform(d)
        if platform is not None:
            if low == platform:
                return d
            prefix, suffix = d[: -len(platform) - 1], d[-len(platform) :]
            return f"{self._tok_named(T.DOMAIN, prefix)}.{suffix}"
        if self.allow.domain(d):
            return d
        prefix, registrable = registrable_split(d)
        if not prefix:
            return self._tok_named(T.DOMAIN, registrable)
        return f"{self._render_prefix(prefix)}.{self._tok_named(T.DOMAIN, registrable)}"

    def _render(self, span: Span) -> str:
        kind, value = span.kind, span.value
        if kind == FQDN:
            return self._render_domain(value)
        if kind == EMAIL:
            local, _, domain = value.rpartition("@")
            return f"{self._tok_named(T.USER, local)}@{self._render_domain(domain)}"
        if kind == ADUSER:
            netbios, sep, user = re.match(r"(.*?)(\\+)(.*)", value).groups()
            dkind = self.dict_kinds.get(netbios.lower(), T.DOMAIN)
            if dkind not in (T.ORG, T.CUSTOMER, T.DOMAIN):
                dkind = T.DOMAIN
            left = self._tok(dkind, netbios)
            right = user if self.allow.word(user) else self._tok_named(T.USER, user)
            return f"{left}{sep}{right}"
        return self._tok(kind, value)

    # ------------------------------------------------------------ public API
    def redact(self, text: str, stats: Counter | None = None) -> str:
        if not text:
            return text
        spans = self.spans(text)
        version = self.vault.version
        for span in spans:
            self._render(span)
        if self.vault.version != version:
            # New values were learnt; catch their bare mentions anywhere in the
            # text (e.g. "dc01" before "dc01.corp.acme.com" was seen).
            spans = self.spans(text)
        out: list[str] = []
        pos = 0
        for span in spans:
            rendered = self._render(span)
            out.append(text[pos : span.start])
            out.append(rendered)
            pos = span.end
            if stats is not None:
                for m in T.TOKEN_RE.finditer(rendered):
                    stats[m.group(0).rsplit("_", 1)[0]] += 1
        out.append(text[pos:])
        return "".join(out)

    def rehydrate(self, text: str, *, json_escape: bool = False) -> str:
        if not text:
            return text

        def sub(m):
            token = m.group(0)
            value = self.vault.lookup(token)
            if value is None:
                if token not in self.unknown_tokens:
                    log.warning("model used unknown token %s; left as-is", token)
                    self.unknown_tokens.add(token)
                return token
            return json.dumps(value, ensure_ascii=False)[1:-1] if json_escape else value

        return T.TOKEN_RE.sub(sub, text)
