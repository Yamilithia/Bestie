"""Regex + validation detectors for the structured values found in security data."""

from __future__ import annotations

import ipaddress
import re
from collections.abc import Iterable, Iterator

from .. import tokens as T
from .base import (
    ADUSER,
    EMAIL,
    FQDN,
    PRIO_GENERIC,
    PRIO_SECRET,
    PRIO_SPECIFIC,
    Span,
)
from .domains import FILE_EXTENSIONS, is_tld

# --------------------------------------------------------------------------- IPs

_IPV4_RE = re.compile(r"(?<![\w.])(\d{1,3}(?:\.\d{1,3}){3})(?:/(\d{1,2}))?(?![\w]|\.\d)")
_IPV6_RE = re.compile(
    r"(?<![\w:.])(?=[0-9A-Fa-f:.]*:[0-9A-Fa-f:.]*:)([0-9A-Fa-f:.]{2,45})(?:/(\d{1,3}))?(?![\w:])"
)


class IPDetector:
    def find(self, text: str) -> Iterator[Span]:
        for m in _IPV4_RE.finditer(text):
            yield from self._validate(m.group(1), m.group(2), m.start(), m.end(), text)
        for m in _IPV6_RE.finditer(text):
            addr = m.group(1)
            end = m.end()
            if m.group(2) is None:
                stripped = addr.rstrip(".:")
                end -= len(addr) - len(stripped)
                addr = stripped
            yield from self._validate(addr, m.group(2), m.start(), end, text)

    @staticmethod
    def _validate(addr: str, prefix: str | None, start: int, end: int, text: str):
        try:
            ipaddress.ip_address(addr)
        except ValueError:
            return
        if prefix is not None:
            try:
                ipaddress.ip_network(f"{addr}/{prefix}", strict=False)
            except ValueError:
                return
            yield Span(start, end, T.NET, text[start:end], PRIO_SPECIFIC)
        else:
            yield Span(start, end, T.IP, addr, PRIO_SPECIFIC)


# ----------------------------------------------------------------------- domains

_LABEL = r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
_FQDN_RE = re.compile(
    rf"(?<![\w.-])((?:{_LABEL}\.)+[A-Za-z][A-Za-z0-9-]{{0,61}}[A-Za-z0-9])\.?(?![\w-]|\.[A-Za-z0-9])"
)
_CAMEL_RE = re.compile(r"[a-z][A-Z]")


class FQDNDetector:
    def __init__(self, internal_suffixes: Iterable[str] = ()) -> None:
        self.internal = tuple(s.lower().strip(".") for s in internal_suffixes)

    def _is_internal(self, domain: str) -> bool:
        d = domain.lower()
        return any(d == s or d.endswith("." + s) for s in self.internal)

    def find(self, text: str) -> Iterator[Span]:
        for m in _FQDN_RE.finditer(text):
            domain = m.group(1)
            labels = domain.split(".")
            if not self._is_internal(domain):
                if not is_tld(labels[-1]):
                    continue
                if len(labels) == 2 and labels[-1].lower() in FILE_EXTENSIONS:
                    continue  # setup.py, payload.zip
                if any(_CAMEL_RE.search(label) for label in labels):
                    continue  # System.Net.WebClient, $obj.DownloadString
            yield Span(m.start(1), m.end(1), FQDN, domain, PRIO_GENERIC)


_EMAIL_RE = re.compile(
    rf"(?<![\w.+%-])([\w.%+-]{{1,64}})@((?:{_LABEL}\.)+[A-Za-z]{{2,63}})(?![\w-])"
)


class EmailDetector:
    def find(self, text: str) -> Iterator[Span]:
        for m in _EMAIL_RE.finditer(text):
            yield Span(m.start(), m.end(), EMAIL, m.group(0), PRIO_SPECIFIC)


# ------------------------------------------------------------ identities & hosts

# Netbios domain parts that are really Windows built-ins or path segments.
_NOT_AD_DOMAINS = frozenset(
    """
    authority builtin workgroup service apppool hklm hkcu hkcr hku hkcc hkey_local_machine
    hkey_current_user hkey_classes_root hkey_users hkey_current_config
    windows system32 syswow64 sysnative program files users programdata appdata temp local
    roaming microsoft software system currentcontrolset controlset001 services run runonce
    drivers config etc bin usr var opt tmp lib documents desktop downloads public default
    """.split()
)

# One or two backslashes: text pasted from JSON logs keeps them escaped.
_ADUSER_RE = re.compile(
    r"(?<![\w\\:/.%$-])([A-Za-z][\w.-]{0,14})\\{1,2}([A-Za-z0-9][\w.$-]{0,63})(?![\w\\])"
)


class ADUserDetector:
    def find(self, text: str) -> Iterator[Span]:
        for m in _ADUSER_RE.finditer(text):
            if m.group(1).lower() in _NOT_AD_DOMAINS:
                continue
            yield Span(m.start(), m.end(), ADUSER, m.group(0), PRIO_SPECIFIC)


_USER_KEYS = (
    r"user(?:[ _-]?name)?|account(?:[ _-]?name)?|target[ _-]?user(?:[ _-]?name)?"
    r"|subject[ _-]?user(?:[ _-]?name)?|src[ _-]?user|dst[ _-]?user|suser|duser"
    r"|logon[ _-]?user|samaccountname|login|owner|initiated[ _-]?by|actor"
)
_HOST_KEYS = (
    r"host(?:[ _-]?name)?|computer(?:[ _-]?name)?|workstation(?:[ _-]?name)?"
    r"|source[ _-]?workstation|device(?:[ _-]?name)?|machine(?:[ _-]?name)?"
    r"|src[ _-]?host|dst[ _-]?host|shost|dhost|client[ _-]?name|endpoint|agent[ _-]?name"
)
_KV_VALUE = r"[\"']?\s*[:=]\s*[\"']?\s*([A-Za-z0-9][\w.$-]*)"
_XML_VALUE = r"[\"']\s*>\s*([A-Za-z0-9][\w.$-]*)\s*<"

# Placeholder-ish values that are not identities.
_NON_VALUES = frozenset(
    "n/a na none null nil unknown true false yes no local localhost system - x".split()
)


class KeyValueDetector:
    """``user=jdoe``, ``"hostname": "wks-042"``, ``Account Name: jdoe``,
    ``<Data Name="TargetUserName">jdoe</Data>``."""

    def __init__(self) -> None:
        self._rules = []
        for kind, keys in ((T.USER, _USER_KEYS), (T.HOST, _HOST_KEYS)):
            kv = re.compile(rf"(?i)(?<![\w])(?:{keys})(?![\w]){_KV_VALUE}")
            xml = re.compile(rf"(?i)name\s*=\s*[\"'](?:{keys}){_XML_VALUE}")
            self._rules += [(kind, kv), (kind, xml)]

    def find(self, text: str) -> Iterator[Span]:
        for kind, rx in self._rules:
            for m in rx.finditer(text):
                value = m.group(1).rstrip(".")
                if len(value) < 2 or value.lower() in _NON_VALUES:
                    continue
                start = m.start(1)
                yield Span(start, start + len(value), kind, value, PRIO_SPECIFIC)


_UNC_RE = re.compile(r"(?<![\w:\\])\\\\(?:\\\\)?([A-Za-z0-9][\w-]{0,62})(?=[\\.])")


class UNCDetector:
    def find(self, text: str) -> Iterator[Span]:
        for m in _UNC_RE.finditer(text):
            yield Span(m.start(1), m.end(1), T.HOST, m.group(1), PRIO_SPECIFIC)


_NOT_PROFILE_USERS = frozenset("public default all users default user shared".split())
_PROFILE_RE = re.compile(
    r"(?i)(?:[a-z]:\\{1,2}(?:users|documents and settings)\\{1,2}|/home/|/Users/)"
    r"([A-Za-z0-9][\w.$-]{0,63})(?=[\\/]|$|[\s\"'])"
)
# Common service-account naming convention.
_SVC_RE = re.compile(r"(?i)(?<![\w.-])svc[_-][A-Za-z0-9][\w.-]*(?<![.-])")


class ProfilePathDetector:
    """Usernames inside profile paths: C:\\Users\\jdoe\\, /home/jdoe/."""

    def find(self, text: str) -> Iterator[Span]:
        for m in _PROFILE_RE.finditer(text):
            if m.group(1).lower() in _NOT_PROFILE_USERS:
                continue
            yield Span(m.start(1), m.end(1), T.USER, m.group(1), PRIO_SPECIFIC)
        for m in _SVC_RE.finditer(text):
            yield Span(m.start(), m.end(), T.USER, m.group(0), PRIO_SPECIFIC)


class HostnamePatternDetector:
    """Your naming conventions, e.g. ``[a-z]{2,4}-(dc|web|sql)\\d+``."""

    def __init__(self, patterns: Iterable[str]) -> None:
        compiled = []
        for p in patterns:
            p = p.strip().removeprefix("^").removesuffix("$")
            if p:
                compiled.append(re.compile(rf"(?i)(?<![\w.-])(?:{p})(?![\w-])"))
        self._patterns = compiled

    def find(self, text: str) -> Iterator[Span]:
        for rx in self._patterns:
            for m in rx.finditer(text):
                yield Span(m.start(), m.end(), T.HOST, m.group(0), PRIO_SPECIFIC)


# ------------------------------------------------------------- artefacts & keys

_HASH_RE = re.compile(r"(?<![\w])([0-9A-Fa-f]{64}|[0-9A-Fa-f]{40}|[0-9A-Fa-f]{32})(?![\w])")
_MAC_RE = re.compile(
    r"(?<![\w:-])(?:[0-9A-Fa-f]{2}([:-])(?:[0-9A-Fa-f]{2}\1){4}[0-9A-Fa-f]{2}"
    r"|[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4}\.[0-9A-Fa-f]{4})(?![\w:-])"
)
_SID_RE = re.compile(r"(?<![\w-])S-1-5-21(?:-\d+){3,4}(?![\w-])")


class HashDetector:
    def find(self, text: str) -> Iterator[Span]:
        for m in _HASH_RE.finditer(text):
            v = m.group(1)
            if v.isdigit() or v.isalpha():
                continue
            yield Span(m.start(1), m.end(1), T.HASH, v, PRIO_SPECIFIC)


class MACDetector:
    def find(self, text: str) -> Iterator[Span]:
        for m in _MAC_RE.finditer(text):
            yield Span(m.start(), m.end(), T.MAC, m.group(0), PRIO_SPECIFIC)


class SIDDetector:
    def find(self, text: str) -> Iterator[Span]:
        for m in _SID_RE.finditer(text):
            yield Span(m.start(), m.end(), T.SID, m.group(0), PRIO_SPECIFIC)


_SECRET_PATTERNS = [
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]+?-----END [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"(?<![\w])(?:AKIA|ASIA)[0-9A-Z]{16}(?![\w])"),
    re.compile(r"(?<![\w-])sk-(?:ant-)?[A-Za-z0-9_-]{20,}"),
    re.compile(r"(?<![\w])(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_\w{20,})"),
    re.compile(r"(?<![\w])xox[abposr]-[A-Za-z0-9-]{10,}"),
    re.compile(r"(?<![\w])eyJ[\w-]{5,}\.eyJ[\w-]{5,}\.[\w-]{5,}"),
    re.compile(r"(?<![\w])AIza[0-9A-Za-z_-]{35}"),
]
# Value-capturing secret patterns (group 1 is the secret).
_SECRET_KV = [
    re.compile(r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{16,})"),
    re.compile(r"(?i)\bbasic\s+([A-Za-z0-9+/=]{12,})"),
    re.compile(
        r"(?i)(?<![\w])(?:password|passwd|pwd|pass|passphrase|secret|client[_-]?secret"
        r"|api[_-]?key|apikey|access[_-]?key|secret[_-]?key|access[_-]?token|auth[_-]?token"
        r"|refresh[_-]?token|token|private[_-]?key|connection[_-]?string)"
        r"[\"']?\s*[:=]\s*[\"']?([^\s\"',;&<>)\]}]{4,}(?<![.]))"
    ),
]


class SecretDetector:
    def find(self, text: str) -> Iterator[Span]:
        for rx in _SECRET_PATTERNS:
            for m in rx.finditer(text):
                yield Span(m.start(), m.end(), T.SECRET, m.group(0), PRIO_SECRET)
        for rx in _SECRET_KV:
            for m in rx.finditer(text):
                yield Span(m.start(1), m.end(1), T.SECRET, m.group(1), PRIO_SECRET)
