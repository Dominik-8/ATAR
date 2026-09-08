import os
import json
import tempfile

from click.testing import CliRunner

from atar.cli import cli
from atar.store import VouchStore
from atar.revocation import RevocationList, revoke_vouch, revoke_payload_id
from atar.identity import generate_identity, did_from_public


def _seed_alice_with_vouch(home, monkeypatch):
    """Register alice via the CLI keygen path (so revoke can find her key)."""
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    r2 = runner.invoke(cli, ["keygen", "--name", "bob"])
    bob_did = [l for l in r2.output.splitlines() if l.startswith("did:key:")][0]
    out = os.path.join(home, "v.json")
    runner.invoke(cli, ["vouch", "--from", "alice", "--for", bob_did,
                        "--score", "0.9", "--scope", "intelligence", "--out", out])
    # add the vouch into the persistent store (like the real flow: vouch -> add)
    runner.invoke(cli, ["add", out])
    return bob_did, out


def test_sync_propagates_revocation(tmp_path, monkeypatch):
    alice = os.path.join(str(tmp_path), "alice")
    bob = os.path.join(str(tmp_path), "bob")
    os.makedirs(alice)
    os.makedirs(bob)
    _seed_alice_with_vouch(alice, monkeypatch)

    # alice revokes the vouch
    monkeypatch.setenv("ATAR_HOME", alice)
    runner = CliRunner()
    # write the vouch to a file, then revoke it
    from atar.store import VouchStore
    v = VouchStore(os.path.join(alice, "vouches.json")).all()[0]
    vf = os.path.join(alice, "v.json")
    json.dump(v, open(vf, "w"))
    r = runner.invoke(cli, ["revoke", vf])
    assert r.exit_code == 0
    assert RevocationList.load(os.path.join(alice, "revocations.json")).is_revoked(
        revoke_payload_id(v))

    # sync alice -> bob should carry the revocation too
    runner.invoke(cli, ["sync", "--with", bob])
    bob_rl = RevocationList.load(os.path.join(bob, "revocations.json"))
    assert bob_rl.is_revoked(revoke_payload_id(v))


def test_revoked_vouch_rejected_after_sync(tmp_path, monkeypatch):
    alice = os.path.join(str(tmp_path), "alice")
    bob = os.path.join(str(tmp_path), "bob")
    os.makedirs(alice)
    os.makedirs(bob)
    _seed_alice_with_vouch(alice, monkeypatch)

    monkeypatch.setenv("ATAR_HOME", alice)
    runner = CliRunner()
    from atar.store import VouchStore
    v = VouchStore(os.path.join(alice, "vouches.json")).all()[0]
    vf = os.path.join(alice, "v.json")
    json.dump(v, open(vf, "w"))
    runner.invoke(cli, ["revoke", vf])
    runner.invoke(cli, ["sync", "--with", bob])

    # bob now has the vouch (via prior sync) AND the revocation
    # a revocation-aware verify on bob must reject it
    from atar.revocation import verify_vouch_revocation_aware
    bob_rl = RevocationList.load(os.path.join(bob, "revocations.json"))
    assert verify_vouch_revocation_aware(v, bob_rl) is False
