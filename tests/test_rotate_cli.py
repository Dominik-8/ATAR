import os
import json

from click.testing import CliRunner

from atar.cli import cli
from atar.vouch import verify_vouch
from atar.rotation import RotationStatement, verify_rotation


def _bob_did(home):
    keys = json.load(open(os.path.join(home, "keys.json")))
    return keys["bob"]["did"]


def _seed_seed_agent_with_vouch(home, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "seed_agent"])
    runner.invoke(cli, ["keygen", "--name", "bob"])
    r = runner.invoke(cli, ["vouch", "--from", "seed_agent", "--for",
                            _bob_did(home), "--score", "0.9",
                            "--scope", "intelligence", "--out",
                            os.path.join(home, "v.json")])
    assert r.exit_code == 0
    runner.invoke(cli, ["add", os.path.join(home, "v.json")])


def test_rotate_changes_did_and_writes_statement(tmp_path, monkeypatch):
    _seed_seed_agent_with_vouch(str(tmp_path), monkeypatch)
    runner = CliRunner()
    r = runner.invoke(cli, ["rotate", "--name", "seed_agent"])
    assert r.exit_code == 0
    keys = json.load(open(os.path.join(str(tmp_path), "keys.json")))
    assert "rotated_from" in keys["seed_agent"]
    # rotation statement file written + verifiable
    stmt_path = os.path.join(str(tmp_path), "rotation.json")
    assert os.path.exists(stmt_path)
    stmt = RotationStatement.from_dict(json.load(open(stmt_path)))
    assert verify_rotation(stmt) is True


def test_reissue_re_signs_vouches_under_new_key(tmp_path, monkeypatch):
    _seed_seed_agent_with_vouch(str(tmp_path), monkeypatch)
    runner = CliRunner()
    runner.invoke(cli, ["rotate", "--name", "seed_agent"])
    r = runner.invoke(cli, ["reissue", "--name", "seed_agent"])
    assert r.exit_code == 0
    reissued = json.load(open(os.path.join(str(tmp_path), "reissued.json")))
    assert len(reissued) >= 1
    # re-issued vouch is validly signed under the NEW key
    assert verify_vouch(reissued[0]) is True
    # and its issuer matches the new seed_agent did
    keys = json.load(open(os.path.join(str(tmp_path), "keys.json")))
    assert reissued[0]["payload"]["issuer"] == keys["seed_agent"]["did"]
