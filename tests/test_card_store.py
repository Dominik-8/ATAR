"""Regression: `atar card` must reflect the persistent vouch store.

The card command used to scan loose *.json files in ATAR_HOME instead of the
store (vouches.json), so cards came out with 0 vouches even when the store
held valid ones. The store is the single source of truth - the CrewAI plugin
builds cards from it the same way (SPEC §11.2).
"""

import json

from click.testing import CliRunner

from atar.atc import _trust_params
from atar.cli import cli


def _alice_vouches_bob(tmp_path):
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen", "--name", "alice"]).exit_code == 0
    assert runner.invoke(cli, ["keygen", "--name", "bob"]).exit_code == 0
    keys = json.loads((tmp_path / "keys.json").read_text())
    vouch_path = tmp_path / "vouch.json"
    r = runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "alice",
            "--for",
            keys["bob"]["did"],
            "--score",
            "0.9",
            "--scope",
            "coding",
            "--out",
            str(vouch_path),
        ],
    )
    assert r.exit_code == 0, r.output
    return vouch_path


def test_card_includes_vouches_from_store(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    vouch_path = _alice_vouches_bob(tmp_path)
    r = runner.invoke(cli, ["add", str(vouch_path)])
    assert r.exit_code == 0, r.output

    card_path = tmp_path / "card.json"
    r = runner.invoke(cli, ["card", "--name", "bob", "--out", str(card_path)])
    assert r.exit_code == 0, r.output
    assert "1 vouch(es)" in r.output
    card = json.loads(card_path.read_text())
    assert len(_trust_params(card)["vouches"]) == 1


def test_card_ignores_loose_files_not_in_store(tmp_path, monkeypatch):
    """A loose vouch file in ATAR_HOME that was never added to the store must
    not leak into the card - only admitted (verified, deduped) vouches count."""
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    _alice_vouches_bob(tmp_path)  # writes vouch.json but never `atar add`s it

    card_path = tmp_path / "card.json"
    runner = CliRunner()
    r = runner.invoke(cli, ["card", "--name", "bob", "--out", str(card_path)])
    assert r.exit_code == 0, r.output
    assert "0 vouch(es)" in r.output
    card = json.loads(card_path.read_text())
    assert _trust_params(card)["vouches"] == []
