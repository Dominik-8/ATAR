"""`atar identities` — the quickstart discoverability command.

Regression: a new user running the README quickstart had no way to see the
identities they just created (`atar list` shows vouches, not identities).
"""

from __future__ import annotations

from click.testing import CliRunner

from atar.cli import cli


def test_identities_lists_names_and_dids_without_keys(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    runner.invoke(cli, ["keygen", "--name", "bob"])

    r = runner.invoke(cli, ["identities"])
    assert r.exit_code == 0
    assert "alice" in r.output and "bob" in r.output
    assert r.output.count("did:key:") == 2
    # private keys must never appear
    import json
    keys = json.loads((tmp_path / "keys.json").read_text())
    for rec in keys.values():
        assert rec["private"] not in r.output


def test_identities_empty_home_guides_to_keygen(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    r = CliRunner().invoke(cli, ["identities"])
    assert r.exit_code == 0
    assert "atar keygen" in r.output
