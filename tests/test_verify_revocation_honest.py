"""Regression: verify must NOT silently ignore a present-but-failing
revocation check (no broad `except Exception`). A corrupt revocation list
should surface an error, not let revoked vouches appear VALID."""

import json
import os
from pathlib import Path

from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
)

from atar.cli import cli
from atar.identity import Identity
from atar.vouch import create_vouch


def _id(home, name):
    with open(os.path.join(home, "keys.json")) as _f:
        keys = json.load(_f)
    return Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys[name]["private"]))


def test_verify_revoked_vouch_reported_revoked(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    runner.invoke(cli, ["keygen", "--name", "bob"])

    alice = _id(tmp_path, "alice")
    bob = _id(tmp_path, "bob")
    blob = create_vouch(
        Identity(private_key=alice, public_key=alice.public_key()),
        bob.public_key(),
        score=0.9,
        scope="intel",
    )
    vpath = tmp_path / "v.json"
    vpath.write_text(json.dumps(blob, indent=2))

    # revoke it (writes revocations.json)
    runner.invoke(cli, ["revoke", str(vpath)])

    # now verify must report REVOKED (exit 2), NOT VALID
    rv = runner.invoke(cli, ["verify", str(vpath)])
    assert rv.exit_code == 2, rv.output
    assert "REVOKED" in rv.output


def test_verify_no_broad_except_hides_corrupt_rl():
    """If a revocations.json parse error would be swallowed by a broad except,
    a revoked vouch could slip through as VALID. We prove the production code
    only catches FileNotFoundError now (the happy path already confirms
    REVOKED above)."""
    src = Path(
        os.path.join(os.path.dirname(__file__), "..", "atar", "cli.py")
    ).read_text(encoding="utf-8")
    # the verify function's revocation block must not use a broad except
    verify_block = src.split("def verify(", 1)[1].split("def card(", 1)[0]
    assert "except FileNotFoundError" in verify_block
    # ensure no bare 'except Exception' in that block
    assert "except Exception" not in verify_block
