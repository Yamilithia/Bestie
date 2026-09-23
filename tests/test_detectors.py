from __future__ import annotations

import pytest

from bestie.config import Dictionary
from bestie.redactor import Redactor
from bestie.vault import Vault


def kinds(redactor: Redactor, text: str) -> list[tuple[str, str]]:
    return [(s.kind, s.value) for s in redactor.spans(text)]


@pytest.mark.parametrize(
    "text,expected",
    [
        ("from 10.20.4.17 to", [("IP", "10.20.4.17")]),
        ("net 10.0.0.0/8 here", [("NET", "10.0.0.0/8")]),
        ("addr fe80::1ff:fe23:4567:890a ok", [("IP", "fe80::1ff:fe23:4567:890a")]),
        ("connect 10.1.2.3:443.", [("IP", "10.1.2.3")]),
    ],
)
def test_ip_detection(redactor, text, expected):
    assert kinds(redactor, text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "at 12:30:45 today",  # time, not IPv6
        "version 999.1.1.1",  # invalid octet
        "v10.0.0.1 released",  # version string
        "resolver 8.8.8.8 and 1.1.1.1",  # allowlisted
        "doc range 192.0.2.10",  # RFC 5737
        "loopback 127.0.0.1 and ::1",
    ],
)
def test_ip_non_matches(redactor, text):
    assert kinds(redactor, text) == []


@pytest.mark.parametrize(
    "text",
    [
        "ran setup.py and payload.zip",
        "[System.Net.WebClient]::new().DownloadString",
        "MITRE T1059.001 and CVE-2024-3400",
        "see www.google.com and login.microsoftonline.com",
        "e.g. this, i.e. that",
    ],
)
def test_domain_non_matches(redactor, text):
    assert kinds(redactor, text) == []


def test_internal_host_keeps_structure(redactor):
    assert redactor.redact("dc01.corp.acme.com") == "HOST_001.DOMAIN_001"
    assert redactor.redact("DC01.CORP.ACME.COM") == "HOST_001.DOMAIN_001"
    assert redactor.redact("fs01.corp.acme.com") == "HOST_002.DOMAIN_001"


def test_external_domain_structure(redactor):
    out = redactor.redact("evil-cdn.xyz then cdn.evil-cdn.xyz then www.evil-cdn.xyz")
    assert out == "DOMAIN_001 then cdn.DOMAIN_001 then www.DOMAIN_001"


def test_platform_tenant_masked_suffix_kept(redactor):
    assert redactor.redact("https://acme.sharepoint.com/x") == "https://ORG_001.sharepoint.com/x"
    assert redactor.redact("c2.azurewebsites.net") == "DOMAIN_001.azurewebsites.net"


def test_allowlisted_domain_with_dictionary_term_inside(redactor):
    assert redactor.redact("acme.microsoft.com") == "ORG_001.microsoft.com"


def test_email(redactor):
    assert redactor.redact("mail john_doe@acme.com") == "mail USER_001@DOMAIN_001"
    assert redactor.redact("from bob@gmail.com") == "from USER_002@gmail.com"


@pytest.mark.parametrize(
    "text,expected",
    [
        (r"user ACME\jdoe logged", r"user ORG_001\USER_001 logged"),
        (r'"user": "ACME\\jdoe"', r'"user": "ORG_001\\USER_001"'),
        (r"NT AUTHORITY\SYSTEM", r"NT AUTHORITY\SYSTEM"),
        (r"C:\Windows\System32\cmd.exe", r"C:\Windows\System32\cmd.exe"),
        (r"HKLM\Software\Run", r"HKLM\Software\Run"),
        (r"ACME\Administrator", r"ORG_001\Administrator"),
    ],
)
def test_ad_users(redactor, text, expected):
    assert redactor.redact(text) == expected


@pytest.mark.parametrize(
    "text,expected",
    [
        ("user=jdoe dst=x", "user=USER_001 dst=x"),
        ('{"hostname": "wks-042"}', '{"hostname": "HOST_001"}'),
        ("Account Name:\t\tsvc_backup", "Account Name:\t\tUSER_001"),
        (
            '<Data Name="TargetUserName">mrossi</Data>',
            '<Data Name="TargetUserName">USER_001</Data>',
        ),
        ("Account Name:\t\t-", "Account Name:\t\t-"),
        (r"\\fs01\share", r"\\HOST_001\share"),
        (r'"\\\\fs01\\share"', r'"\\\\HOST_001\\share"'),
        (r"C:\Users\mrossi\AppData", r"C:\Users\USER_001\AppData"),
        ("/home/alice/.ssh/id_rsa", "/home/USER_001/.ssh/id_rsa"),
        (r"C:\Users\Public\x", r"C:\Users\Public\x"),
    ],
)
def test_identity_patterns(redactor, text, expected):
    assert redactor.redact(text) == expected


@pytest.mark.parametrize(
    "text",
    [
        "password=Hunter2!",
        "Authorization: Bearer abcdefghijklmnopqrstuvwxyz012345",
        "key AKIAIOSFODNN7EXAMPLE",
        "sk-ant-api03-abcdefghijklmnopqrstuvwxyz",
        "ghp_abcdefghijklmnopqrstuvwxyz0123456789",
        "jwt eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJqZG9lIn0.c2lnbmF0dXJl",
        "-----BEGIN RSA PRIVATE KEY-----\nMIIEow\n-----END RSA PRIVATE KEY-----",
    ],
)
def test_secrets(redactor, text):
    out = redactor.redact(text)
    assert "SECRET_001" in out


def test_secret_keeps_trailing_punctuation(redactor):
    assert redactor.redact("(password=Winter2026!).") == "(password=SECRET_001)."


def test_hash_mac_sid(redactor):
    out = redactor.redact(
        "sha256 9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08 "
        "mac 00:1A:2B:3C:4D:5E sid S-1-5-21-1004336348-1177238915-682003330-512 "
        "well-known S-1-5-18"
    )
    assert out == "sha256 HASH_001 mac MAC_001 sid SID_001 well-known S-1-5-18"


def test_hashes_can_be_disabled():
    r = Redactor(Vault(), Dictionary(), redact_hashes=False)
    h = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"
    assert r.redact(h) == h


def test_dictionary_terms_case_insensitive(redactor):
    assert redactor.redact("Globex's SOC and GLOBEX") == "CUSTOMER_001's SOC and CUSTOMER_001"
    assert redactor.redact("Project Falcon status") == "TERM_001 status"


def test_hostname_patterns(redactor):
    assert redactor.redact("seen on WKS-FIN-042 and jumpbox-02") == "seen on HOST_001 and HOST_002"


def test_user_allowlist_addition():
    r = Redactor(Vault(), Dictionary(allow=["10.99.0.0/16", "partner.example-corp.com"]))
    assert r.redact("10.99.1.1 partner.example-corp.com") == "10.99.1.1 partner.example-corp.com"
