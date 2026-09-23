from __future__ import annotations

import pytest
from conftest import DICTIONARY, FIXTURES, SENSITIVE

from bestie.leakguard import LeakDetected, LeakGuard
from bestie.redactor import Redactor
from bestie.vault import Vault


@pytest.mark.parametrize("name", sorted(SENSITIVE))
def test_fixture_no_sensitive_value_survives(name):
    redactor = Redactor(Vault(), DICTIONARY)
    text = (FIXTURES / name).read_text()
    out = redactor.redact(text)
    for value in SENSITIVE[name]:
        assert value.lower() not in out.lower(), f"{value!r} leaked from {name}"
    assert LeakGuard(redactor).problems([out]) == []


@pytest.mark.parametrize("name", sorted(SENSITIVE))
def test_fixture_round_trip(name):
    redactor = Redactor(Vault(), DICTIONARY)
    text = (FIXTURES / name).read_text()
    # Case-insensitive types restore to their first-seen spelling.
    assert redactor.rehydrate(redactor.redact(text)).lower() == text.lower()


@pytest.mark.parametrize("name", sorted(SENSITIVE))
def test_redaction_is_idempotent(name):
    redactor = Redactor(Vault(), DICTIONARY)
    out = redactor.redact((FIXTURES / name).read_text())
    assert redactor.redact(out) == out


def test_consistent_tokens_across_calls(redactor):
    a = redactor.redact("dc01.corp.acme.com talked to 10.20.4.17")
    b = redactor.redact("later 10.20.4.17 and dc01.corp.acme.com again")
    assert a == "HOST_001.DOMAIN_001 talked to IP_001"
    assert b == "later IP_001 and HOST_001.DOMAIN_001 again"


def test_bare_mention_before_first_structured_sighting(redactor):
    out = redactor.redact("jdoe opened it. Later user=jdoe logged in.")
    assert out == "USER_001 opened it. Later user=USER_001 logged in."


def test_short_learnt_values_do_not_eat_words(redactor):
    out = redactor.redact("Contacted Globex's SOC (soc@globex.com)")
    assert "SOC (" in out


def test_rehydrate_ignores_unknown_tokens(redactor):
    redactor.redact("10.20.4.17")
    assert redactor.rehydrate("IP_001 and IP_099") == "10.20.4.17 and IP_099"
    assert "IP_099" in redactor.unknown_tokens


def test_rehydrate_json_escape(redactor):
    redactor.redact(r"ACME\jdoe")
    assert redactor.rehydrate(r"ORG_001\\USER_001", json_escape=True) == r"ACME\\jdoe"


def test_vault_persistence(tmp_path):
    path = tmp_path / "v.json"
    v1 = Vault.load("t", path)
    r1 = Redactor(v1, DICTIONARY)
    out1 = r1.redact("dc01.corp.acme.com 10.20.4.17")
    v1.save()
    assert oct(path.stat().st_mode & 0o777) == "0o600"
    v2 = Vault.load("t", path)
    r2 = Redactor(v2, DICTIONARY)
    assert (
        r2.redact("10.20.4.17 dc01.corp.acme.com 10.9.9.9") == "IP_001 HOST_001.DOMAIN_001 IP_002"
    )
    assert r2.rehydrate(out1) == "dc01.corp.acme.com 10.20.4.17"


def test_leak_guard_blocks_known_value(redactor, guard):
    redactor.redact("host=wks-fin-042")
    with pytest.raises(LeakDetected) as exc:
        guard.check(["the model should never see wks-fin-042"])
    assert "HOST" in str(exc.value)
    assert "wks-fin-042" not in str(exc.value)  # never echo values


def test_leak_guard_blocks_undetected_value(guard):
    with pytest.raises(LeakDetected):
        guard.check(["raw 10.20.4.17 slipped through"])


def test_leak_guard_passes_clean_text(redactor, guard):
    out = redactor.redact((FIXTURES / "incident_notes.md").read_text())
    guard.check([out])
