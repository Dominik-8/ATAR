import os
import json

from click.testing import CliRunner

from atar.cli import cli


def test_card_and_verify_card(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    r1 = runner.invoke(cli, ["keygen", "--name", "alice"])
    assert r1.exit_code == 0
    r2 = runner.invoke(cli, ["keygen", "--name", "bob"])
    assert r2.exit_code == 0
    bob_did = [l for l in r2.output.splitlines() if l.startswith("did:agent:")][0]
    # alice vouches for bob
    out = tmp_path / "sub" / "v.json"
    out.parent.mkdir()
    r3 = runner.invoke(cli, ["vouch", "--from", "alice", "--for", bob_did,
                             "--score", "0.9", "--scope", "coding", "--out", str(out)])
    assert r3.exit_code == 0
    # bob builds his agent card (collects the vouch where he is subject)
    # copy the vouch into ATAR_HOME so `card` can find it
    import shutil
    shutil.copy(out, tmp_path / "vouch-alice.json")
    r4 = runner.invoke(cli, ["card", "--name", "bob", "--out", str(tmp_path / "card.json")])
    assert r4.exit_code == 0
    assert "1 vouch" in r4.output
    # verify the card
    r5 = runner.invoke(cli, ["verify-card", str(tmp_path / "card.json")])
    assert r5.exit_code == 0
    assert "valid vouches   : 1" in r5.output
