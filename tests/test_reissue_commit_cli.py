import os
import json

from click.testing import CliRunner

from atar.cli import cli
from atar.vouch import verify_vouch
from atar.revocation import RevocationList, revoke_payload_id
from atar.store import VouchStore


def _seed_seed_agent_with_vouch(home, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "seed_agent"])
    runner.invoke(cli, ["keygen", "--name", "bob"])
    keys = json.load(open(os.path.join(home, "keys.json")))
    bob = keys["bob"]["did"]
    r = runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "seed_agent",
            "--for",
            bob,
            "--score",
            "0.9",
            "--scope",
            "intelligence",
            "--out",
            os.path.join(home, "v.json"),
        ],
    )
    assert r.exit_code == 0
    runner.invoke(cli, ["add", os.path.join(home, "v.json")])


def test_reissue_commit_adds_new_and_revokes_old(tmp_path, monkeypatch):
    _seed_seed_agent_with_vouch(str(tmp_path), monkeypatch)
    runner = CliRunner()
    runner.invoke(cli, ["rotate", "--name", "seed_agent"])
    # commit: re-issue under new key AND revoke the old-key vouch
    r = runner.invoke(cli, ["reissue", "--name", "seed_agent", "--commit"])
    assert r.exit_code == 0
    # store now contains the re-issued vouch (valid under new key)
    store = VouchStore(os.path.join(str(tmp_path), "vouches.json"))
    vouches = store.all()
    assert len(vouches) >= 1
    # at least one vouch is validly signed under the NEW key
    keys = json.load(open(os.path.join(str(tmp_path), "keys.json")))
    new_did = keys["seed_agent"]["did"]
    assert any(v["payload"]["issuer"] == new_did and verify_vouch(v) for v in vouches)
    # the OLD vouch (issuer == rotated_from) is now on the revocation list
    rl = RevocationList.load(os.path.join(str(tmp_path), "revocations.json"))
    old_did = keys["seed_agent"]["rotated_from"]
    old_vouch = [v for v in vouches if v["payload"]["issuer"] == old_did]
    if old_vouch:
        assert rl.is_revoked(revoke_payload_id(old_vouch[0]))


def test_reissue_without_commit_leaves_store_untouched(tmp_path, monkeypatch):
    _seed_seed_agent_with_vouch(str(tmp_path), monkeypatch)
    runner = CliRunner()
    runner.invoke(cli, ["rotate", "--name", "seed_agent"])
    runner.invoke(cli, ["reissue", "--name", "seed_agent"])  # no --commit
    # store still has only the original (old-key) vouch, nothing revoked
    store = VouchStore(os.path.join(str(tmp_path), "vouches.json"))
    assert store.count() == 1
    rl = RevocationList.load(os.path.join(str(tmp_path), "revocations.json"))
    assert rl.all() == []
