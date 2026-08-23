import os
import json
import tempfile

from click.testing import CliRunner

from atar.cli import cli
from atar.revocation import RevocationList, revoke_vouch, revoke_payload_id


def _make_vouch_file(home, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    r2 = runner.invoke(cli, ["keygen", "--name", "bob"])
    bob_did = [l for l in r2.output.splitlines() if l.startswith("did:agent:")][0]
    out = os.path.join(home, "v.json")
    runner.invoke(cli, ["vouch", "--from", "alice", "--for", bob_did,
                        "--score", "0.9", "--scope", "coding", "--out", out])
    return out


def test_add_accepts_valid_vouch(tmp_path, monkeypatch):
    out = _make_vouch_file(str(tmp_path), monkeypatch)
    r = CliRunner().invoke(cli, ["add", out])
    assert r.exit_code == 0
    assert "added" in r.output.lower()


def test_add_rejects_revoked_vouch(tmp_path, monkeypatch):
    out = _make_vouch_file(str(tmp_path), monkeypatch)
    # revoke it first (writes to revocations.json)
    rr = CliRunner().invoke(cli, ["revoke", out])
    assert rr.exit_code == 0
    # now add must reject it
    r = CliRunner().invoke(cli, ["add", out])
    assert r.exit_code == 1
    assert "revoked" in r.output.lower()
    # store must still be empty
    from atar.store import VouchStore
    assert VouchStore(os.path.join(str(tmp_path), "vouches.json")).count() == 0
