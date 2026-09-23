"""Values that are safe (and useful) to show the model as-is."""

from __future__ import annotations

import ipaddress
from collections.abc import Iterable

from .domains import DEFAULT_ALLOWED_DOMAINS

DEFAULT_ALLOWED_NETWORKS = (
    "0.0.0.0/32",
    "127.0.0.0/8",
    "255.255.255.255/32",
    "169.254.169.254/32",
    "8.8.8.8/32",
    "8.8.4.4/32",
    "1.1.1.1/32",
    "1.0.0.1/32",
    "9.9.9.9/32",
    "149.112.112.112/32",
    "208.67.222.222/32",
    "208.67.220.220/32",
    "192.0.2.0/24",
    "198.51.100.0/24",
    "203.0.113.0/24",  # RFC 5737 documentation
    "::/128",
    "::1/128",
    "2001:db8::/32",
)

# Built-in Windows principals and generic accounts.
DEFAULT_ALLOWED_WORDS = (
    "system",
    "local service",
    "network service",
    "localsystem",
    "administrator",
    "administrators",
    "guest",
    "defaultaccount",
    "anonymous logon",
    "everyone",
    "nt authority",
    "builtin",
    "root",
    "nobody",
    "daemon",
    "www-data",
)


class Allowlist:
    def __init__(self, extra: Iterable[str] = ()) -> None:
        self.networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
        self.domains: set[str] = set()
        self.words: set[str] = set()
        for item in (
            *DEFAULT_ALLOWED_NETWORKS,
            *DEFAULT_ALLOWED_DOMAINS,
            *DEFAULT_ALLOWED_WORDS,
            *extra,
        ):
            self._add(item)

    def _add(self, item: str) -> None:
        item = item.strip()
        if not item:
            return
        try:
            self.networks.append(ipaddress.ip_network(item, strict=False))
            return
        except ValueError:
            pass
        low = item.lower().removeprefix("*.").rstrip(".")
        if "." in low or low in DEFAULT_ALLOWED_DOMAINS:
            self.domains.add(low)
        self.words.add(low)

    def ip(self, value: str) -> bool:
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False
        return any(addr.version == n.version and addr in n for n in self.networks)

    def network(self, value: str) -> bool:
        try:
            net = ipaddress.ip_network(value, strict=False)
        except ValueError:
            return False
        return any(
            net.version == n.version and net.subnet_of(n)  # type: ignore[arg-type]
            for n in self.networks
        )

    def domain(self, value: str) -> bool:
        d = value.lower().rstrip(".")
        parts = d.split(".")
        return any(".".join(parts[i:]) in self.domains for i in range(len(parts)))

    def word(self, value: str) -> bool:
        return value.strip().lower() in self.words
