import json
import os
import time

from click.testing import CliRunner

from atar.cli import cli
from atar.identity import generate_identity
from atar.vouch import create_vouch


def _seed_audit_home(home, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "seed_agent"])
    runner.invoke(cli, ["keygen", "--name", "bob"])
    with open(os.path.join(home, "keys.json")) as _f:
        keys = json.load(_f)
    bob = keys["bob"]["did"]
    # a valid, fresh vouch
    runner.invoke(
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
            os.path.join(home, "v1.json"),
        ],
    )
    runner.invoke(cli, ["add", os.path.join(home, "v1.json")])
    # an EXPIRED vouch (ts far in past) — build directly + add to store
    iss = generate_identity()
    sub = generate_identity()
    old = create_vouch(
        iss,
        sub.public_key,
        score=0.8,
        scope="intelligence",
        ts=int(time.time()) - 999999,
    )
    from atar.store import VouchStore

    VouchStore(os.path.join(home, "vouches.json")).add(old)
    return keys


def test_audit_reports_valid_and_expired(tmp_path, monkeypatch):
    _seed_audit_home(str(tmp_path), monkeypatch)
    r = CliRunner().invoke(cli, ["audit", "--max-age", "86400"])
    # unhealthy (has an expired vouch) -> exit 2, but report still printed
    assert r.exit_code == 2
    out = r.output
    assert "valid" in out.lower()
    assert "expired" in out.lower()
    # the expired one should be flagged
    assert "expired : 1" in out


def test_audit_reports_revoked(tmp_path, monkeypatch):
    _seed_audit_home(str(tmp_path), monkeypatch)
    runner = CliRunner()
    # revoke the valid v1 vouch
    runner.invoke(cli, ["revoke", os.path.join(str(tmp_path), "v1.json")])
    r = runner.invoke(cli, ["audit"])
    assert r.exit_code == 2  # unhealthy
    assert "revoked" in r.output.lower()


def test_audit_clean_network_exits_zero(tmp_path, monkeypatch):
    """A store with only valid, unrevoked, fresh vouches is healthy (exit 0)."""
    home = str(tmp_path)
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "seed_agent"])
    runner.invoke(cli, ["keygen", "--name", "bob"])
    with open(os.path.join(home, "keys.json")) as _f:
        keys = json.load(_f)
    bob = keys["bob"]["did"]
    runner.invoke(
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
    runner.invoke(cli, ["add", os.path.join(home, "v.json")])
    r = runner.invoke(cli, ["audit"])
    assert r.exit_code == 0
    assert "valid   : 1" in r.output
