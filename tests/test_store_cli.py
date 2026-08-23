import os
import json

from click.testing import CliRunner

from atar.cli import cli


def test_add_and_list_store(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    # create a vouch via the existing vouch command
    runner.invoke(cli, ["keygen", "--name", "alice"])
    r2 = runner.invoke(cli, ["keygen", "--name", "bob"])
    bob_did = [l for l in r2.output.splitlines() if l.startswith("did:agent:")][0]
    out = tmp_path / "sub" / "v.json"
    out.parent.mkdir()
    runner.invoke(cli, ["vouch", "--from", "alice", "--for", bob_did,
                        "--score", "0.9", "--scope", "coding", "--out", str(out)])
    # add it to the persistent store
    r3 = runner.invoke(cli, ["add", str(out)])
    assert r3.exit_code == 0
    assert "added" in r3.output
    # list should show it
    r4 = runner.invoke(cli, ["list"])
    assert r4.exit_code == 0
    assert bob_did in r4.output
    # re-adding the same vouch is rejected (dedup)
    r5 = runner.invoke(cli, ["add", str(out)])
    assert r5.exit_code == 1
    assert "rejected" in r5.output


def test_store_survives_restart(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    r2 = runner.invoke(cli, ["keygen", "--name", "bob"])
    bob_did = [l for l in r2.output.splitlines() if l.startswith("did:agent:")][0]
    out = tmp_path / "sub" / "v.json"
    out.parent.mkdir()
    runner.invoke(cli, ["vouch", "--from", "alice", "--for", bob_did,
                        "--score", "0.9", "--scope", "coding", "--out", str(out)])
    runner.invoke(cli, ["add", str(out)])
    # a fresh CLI invocation (new process context) must still see the vouch
    r = runner.invoke(cli, ["list"])
    assert bob_did in r.output
