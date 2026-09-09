"""Freshness expiry: a stale vouch must be reported EXPIRED (not VALID) when
checked with --max-age. This is the negative side of Phase 24 (time-bounded
trust) that was never tested — only the "fresh" happy path was. If freshness
were broken, a 3-year-old vouch would still show VALID, defeating the whole
point of TTL-based trust decay."""

import json
import os
import time

from click.testing import CliRunner

from atar.cli import cli
from atar.identity import Identity
from atar.vouch import create_vouch


def _fresh_vouch(issuer_priv, subject_pub, age_seconds):
    return create_vouch(
        Identity(private_key=issuer_priv, public_key=issuer_priv.public_key()),
        subject_pub,
        score=0.9,
        scope="core",
        ts=int(time.time()) - age_seconds,
    )


def test_verify_reports_expired_with_max_age(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    runner.invoke(cli, ["keygen", "--name", "bob"])

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    keys = json.load(open(os.path.join(tmp_path, "keys.json")))
    alice = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(keys["alice"]["private"])
    )
    bob = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["bob"]["private"]))

    # vouch from 1 year ago
    old_blob = _fresh_vouch(alice, bob.public_key(), age_seconds=365 * 24 * 3600)
    vpath = tmp_path / "old.json"
    vpath.write_text(json.dumps(old_blob, indent=2))

    # with a short max-age, it must be EXPIRED (exit 1)
    rv = runner.invoke(cli, ["verify", str(vpath), "--max-age", "3600"])
    assert rv.exit_code == 1, rv.output
    assert "EXPIRED" in rv.output

    # without max-age, it's still VALID (no TTL enforcement)
    rv2 = runner.invoke(cli, ["verify", str(vpath)])
    assert rv2.exit_code == 0, rv2.output
    assert "VALID" in rv2.output


def test_audit_flags_expired_vouch(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    runner.invoke(cli, ["keygen", "--name", "bob"])

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    keys = json.load(open(os.path.join(tmp_path, "keys.json")))
    alice = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(keys["alice"]["private"])
    )
    bob = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["bob"]["private"]))

    old_blob = _fresh_vouch(alice, bob.public_key(), age_seconds=365 * 24 * 3600)
    vpath = tmp_path / "old.json"
    vpath.write_text(json.dumps(old_blob, indent=2))
    runner.invoke(cli, ["add", str(vpath)])

    # audit with max-age should flag it as expired (exit 2 = unhealthy)
    rv = runner.invoke(cli, ["audit", "--max-age", "3600"])
    assert rv.exit_code == 2, rv.output
    assert "expired" in rv.output.lower()


def test_watch_once_flags_expired(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    runner.invoke(cli, ["keygen", "--name", "bob"])

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    keys = json.load(open(os.path.join(tmp_path, "keys.json")))
    alice = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(keys["alice"]["private"])
    )
    bob = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["bob"]["private"]))

    old_blob = _fresh_vouch(alice, bob.public_key(), age_seconds=365 * 24 * 3600)
    vpath = tmp_path / "old.json"
    vpath.write_text(json.dumps(old_blob, indent=2))
    runner.invoke(cli, ["add", str(vpath)])

    # watch --once should exit 2 (unhealthy) on expired vouch
    rv = runner.invoke(cli, ["watch", "--once", "--max-age", "3600"])
    assert rv.exit_code == 2, rv.output
