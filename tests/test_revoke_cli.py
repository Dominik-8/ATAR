import os
import json
import tempfile

from click.testing import CliRunner

from atar.cli import cli


def test_revoke_cli_writes_revocation(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    # register an agent + create a vouch (export it to a file)
    runner.invoke(cli, ["keygen", "--name", "alice"])
    r2 = runner.invoke(cli, ["keygen", "--name", "bob"])
    bob_did = [l for l in r2.output.splitlines() if l.startswith("did:agent:")][0]
    out = tmp_path / "v.json"
    runner.invoke(cli, ["vouch", "--from", "alice", "--for", bob_did,
                        "--score", "0.9", "--scope", "coding", "--out", str(out)])
    # revoke it
    r3 = runner.invoke(cli, ["revoke", str(out)])
    assert r3.exit_code == 0
    assert "revoked" in r3.output.lower()
    # revocation list persisted
    rl = tmp_path / "revocations.json"
    assert rl.exists()
    data = json.loads(rl.read_text())
    assert len(data["revocations"]) == 1


def test_revoke_unknown_issuer_fails(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    # a vouch whose issuer we don't have a key for
    v = {"payload": {"type": "vouch", "issuer": "did:agent:UNKNOWN",
                     "subject": "did:agent:X", "score": 0.5, "scope": "x",
                     "claim": None, "ts": 1}, "signature": "deadbeef"}
    vf = tmp_path / "orphan.json"
    vf.write_text(json.dumps(v))
    r = runner.invoke(cli, ["revoke", str(vf)])
    assert r.exit_code == 1
    assert "no local key" in r.output.lower()
