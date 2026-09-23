from __future__ import annotations

from pathlib import Path

import pytest

from bestie.config import Dictionary
from bestie.leakguard import LeakGuard
from bestie.redactor import Redactor
from bestie.vault import Vault

FIXTURES = Path(__file__).parent / "fixtures"

DICTIONARY = Dictionary(
    orgs=["Acme"],
    customers=["Globex"],
    internal_domains=["corp.acme.com", "acme.com"],
    ad_domains=["ACME"],
    terms=["Project Falcon"],
    hostname_patterns=[r"(wks|jumpbox)-[a-z0-9]+(-\d+)?"],
)

# Real values in the fixtures that must never reach the AI.
SENSITIVE = {
    "edr_alert.json": [
        "WKS-FIN-042",
        "wks-fin-042",
        "corp.acme.com",
        "10.20.4.17",
        "jdoe",
        "john.doe",
        "acme.com",
        "evil-cdn.xyz",
        "update-check",
        "9f86d081884c7d659a2feaa0c55ad015",
        "185.220.101.47",
        "acme.sharepoint",
        "00:1A:2B:3C:4D:5E",
        "ACME",
    ],
    "windows_security.txt": [
        "DC01",
        "svc_backup",
        "S-1-5-21-1004336348",
        "JUMPBOX-02",
        "10.20.8.33",
        "ACME",
    ],
    "sysmon.xml": [
        "fs01",
        "mrossi",
        "10.20.12.9",
        "wks-hr-007",
        "45.137.21.9",
        "badstuff.top",
        "corp.acme.com",
        "ACME",
    ],
    "firewall.log": [
        "10.20.4.17",
        "185.220.101.47",
        "jdoe",
        "wks-fin-042",
        "fe80::1ff:fe23:4567:890a",
        "2a01:4f8:c0c:1234::1",
        "globex_contractor",
        "91.198.174.192",
        "10.30.0.0/16",
    ],
    "incident_notes.md": [
        "Acme",
        "Globex",
        "jdoe",
        "WKS-FIN-042",
        "evil-cdn.xyz",
        "185.220.101.47",
        "fs01",
        "svc_backup",
        "Winter2026!",
        "badstuff.top",
        "eyJhbGciOiJIUzI1NiJ9",
        "soc@globex",
        "Project Falcon",
        "AKIAIOSFODNN7EXAMPLE",
    ],
}


@pytest.fixture
def vault() -> Vault:
    return Vault()


@pytest.fixture
def redactor(vault: Vault) -> Redactor:
    return Redactor(vault, DICTIONARY)


@pytest.fixture
def guard(redactor: Redactor) -> LeakGuard:
    return LeakGuard(redactor)
