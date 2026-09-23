from __future__ import annotations

from conftest import DICTIONARY, FIXTURES
from typer.testing import CliRunner

from bestie.cli import app
from bestie.config import Settings, write_dictionary

runner = CliRunner()


def test_redact_restore_preview(tmp_path):
    write_dictionary(Settings(home=tmp_path).dictionary_path, DICTIONARY)
    env = {"BESTIE_HOME": str(tmp_path)}
    text = (FIXTURES / "firewall.log").read_text()

    res = runner.invoke(app, ["redact", "-"], input=text, env=env)
    assert res.exit_code == 0, res.output
    redacted = res.stdout
    assert "10.20.4.17" not in redacted and "IP_001" in redacted

    res = runner.invoke(app, ["restore", "-"], input=redacted, env=env)
    assert res.exit_code == 0
    assert res.stdout == text

    # Preview never persists new mappings.
    res = runner.invoke(app, ["preview", "-"], input="new host 10.77.7.7", env=env)
    assert res.exit_code == 0
    res = runner.invoke(app, ["vault", "show"], env=env)
    assert "10.77.7.7" not in res.stdout


def test_dict_add_and_vaults(tmp_path):
    env = {"BESTIE_HOME": str(tmp_path)}
    assert runner.invoke(app, ["dict", "add", "customer", "Initech"], env=env).exit_code == 0
    res = runner.invoke(app, ["redact", "-", "--vault", "IR-7"], input="Initech breach", env=env)
    assert res.stdout == "CUSTOMER_001 breach"
    res = runner.invoke(app, ["vault", "ls"], env=env)
    assert "IR-7" in res.stdout
    assert runner.invoke(app, ["vault", "clear", "IR-7", "--yes"], env=env).exit_code == 0
    assert runner.invoke(app, ["dict", "add", "bogus", "x"], env=env).exit_code == 2
