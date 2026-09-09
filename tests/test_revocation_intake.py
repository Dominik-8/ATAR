"""Stage A3: revocation entries are verified at every intake path.

SPEC §6 defines signed revocations, but before this change the sync/merge,
import and load paths accepted entries without ever checking the signature
against ``revoked_by`` — a peer could gossip forged revocations and kill
other agents' vouches. These tests pin the fix.
"""

import json
import os
from base64 import b64encode

from click.testing import CliRunner

from atar.cli import cli
from atar.identity import did_from_public, generate_identity
from atar.revocation import (
    RevocationList,
    revoke_payload_id,
    revoke_vouch,
    verify_revocation_entry,
    verify_vouch_revocation_aware,
)
from atar.vouch import create_vouch


def _vouch():
    issuer = generate_identity()
    subject = generate_identity()
    return issuer, create_vouch(issuer, subject.public_key, score=0.9, scope="coding")


def _entry_for(vid, signer, revoked_by=None, ts=1690000000):
    """A revocation entry signed by ``signer`` (well-formed unless told otherwise)."""
    rb = revoked_by or did_from_public(signer.public_key)
    msg = f"{vid}|{rb}|{ts}".encode()
    return {
        "vid": vid,
        "revoked_by": rb,
        "ts": ts,
        "signature": b64encode(signer.sign(msg)).decode("ascii"),
    }


def test_signature_checked_against_revoked_by_not_just_any_key():
    issuer, v = _vouch()
    attacker = generate_identity()
    vid = revoke_payload_id(v)
    # attacker signs but CLAIMS to be the issuer -> signature check fails
    entry = _entry_for(vid, attacker, revoked_by=did_from_public(issuer.public_key))
    assert verify_revocation_entry(entry) is False
    rl = RevocationList()
    assert (
        rl.add(entry["revoked_by"], entry["vid"], entry["ts"], entry["signature"])
        is False
    )
    assert rl.all() == []


def test_attacker_self_signed_entry_never_revokes():
    _issuer, v = _vouch()
    attacker = generate_identity()
    vid = revoke_payload_id(v)
    # well-formed entry: attacker signs as themselves -> verifies standalone
    entry = _entry_for(vid, attacker)
    assert verify_revocation_entry(entry) is True
    rl = RevocationList()
    assert (
        rl.add(entry["revoked_by"], entry["vid"], entry["ts"], entry["signature"])
        is True
    )
    # ...but it is inert: only the issuer's revocation applies (SPEC §6)
    assert verify_vouch_revocation_aware(v, rl) is True
    # and when the vouch is known at intake, the entry is rejected outright
    rl2 = RevocationList()
    assert (
        rl2.add(
            entry["revoked_by"], entry["vid"], entry["ts"], entry["signature"], vouch=v
        )
        is False
    )


def test_legit_revocation_still_applies():
    issuer, v = _vouch()
    rl = RevocationList()
    assert revoke_vouch(rl, issuer, revoke_payload_id(v)) is True
    assert verify_vouch_revocation_aware(v, rl) is False


def test_load_drops_forged_and_malformed_entries(tmp_path):
    issuer, v = _vouch()
    attacker = generate_identity()
    vid = revoke_payload_id(v)
    good = _entry_for(vid, issuer)
    forged = _entry_for(vid, attacker, revoked_by=did_from_public(issuer.public_key))
    malformed = {"vid": "vouch:deadbeef"}  # missing required fields
    path = os.path.join(str(tmp_path), "revocations.json")
    with open(path, "w", encoding="utf-8") as f:
        json.dump({"revocations": [good, forged, malformed]}, f)
    rl = RevocationList.load(path)
    assert rl.all() == [good]


def test_load_corrupt_file_is_clean(tmp_path):
    path = os.path.join(str(tmp_path), "revocations.json")
    with open(path, "w", encoding="utf-8") as f:
        f.write("{not json")
    assert RevocationList.load(path).all() == []


def test_sync_does_not_import_forged_revocation(tmp_path, monkeypatch):
    """A peer cannot kill your vouches by gossiping revocations they signed."""
    alice_home = os.path.join(str(tmp_path), "alice")
    mallory_home = os.path.join(str(tmp_path), "mallory")
    os.makedirs(alice_home)
    os.makedirs(mallory_home)
    runner = CliRunner()
    # alice: identity + vouch for bob, admitted to her store
    monkeypatch.setenv("ATAR_HOME", alice_home)
    runner.invoke(cli, ["keygen", "--name", "alice"])
    r = runner.invoke(cli, ["keygen", "--name", "bob"])
    bob_did = next(
        line for line in r.output.splitlines() if line.startswith("did:key:")
    )
    vf = os.path.join(alice_home, "v.json")
    runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "alice",
            "--for",
            bob_did,
            "--score",
            "0.9",
            "--scope",
            "coding",
            "--out",
            vf,
        ],
    )
    runner.invoke(cli, ["add", vf])
    with open(vf, encoding="utf-8") as f:
        v = json.load(f)
    vid = revoke_payload_id(v)
    # mallory receives the vouch via legitimate sync, then forges a revocation
    monkeypatch.setenv("ATAR_HOME", mallory_home)
    runner.invoke(cli, ["sync", "--with", alice_home])
    mallory = generate_identity()
    forged = _entry_for(vid, mallory)  # well-formed, but not from the issuer
    with open(
        os.path.join(mallory_home, "revocations.json"), "w", encoding="utf-8"
    ) as f:
        json.dump({"revocations": [forged]}, f)
    # alice syncs with mallory: the forged entry must not enter alice's list
    monkeypatch.setenv("ATAR_HOME", alice_home)
    r = runner.invoke(cli, ["sync", "--with", mallory_home])
    assert r.exit_code == 0, r.output
    alice_rl = RevocationList.load(os.path.join(alice_home, "revocations.json"))
    assert alice_rl.all() == []
    assert verify_vouch_revocation_aware(v, alice_rl) is True


def test_reissue_commit_revocation_verifiable_and_old_key_retired(
    tmp_path, monkeypatch
):
    """Rotation: the retirement revocation is signed by the OLD key (SPEC §6),
    and the locally retained old key is deleted after commit."""
    home = str(tmp_path)
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "a"])
    r = runner.invoke(cli, ["keygen", "--name", "b"])
    b_did = next(line for line in r.output.splitlines() if line.startswith("did:key:"))
    vf = os.path.join(home, "v.json")
    runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "a",
            "--for",
            b_did,
            "--score",
            "0.9",
            "--scope",
            "coding",
            "--out",
            vf,
        ],
    )
    runner.invoke(cli, ["add", vf])
    with open(vf, encoding="utf-8") as f:
        v = json.load(f)
    runner.invoke(cli, ["rotate", "--name", "a"])
    with open(os.path.join(home, "keys.json")) as _f:
        keys = json.load(_f)
    assert "old_private" in keys["a"]  # retained to sign retirement revocations
    r = runner.invoke(cli, ["reissue", "--name", "a", "--commit"])
    assert r.exit_code == 0, r.output
    rl = RevocationList.load(os.path.join(home, "revocations.json"))
    vid = revoke_payload_id(v)
    assert rl.is_revoked(vid)
    entry = rl.entries[vid]
    assert entry["revoked_by"] == v["payload"]["issuer"]  # signed by old DID's key
    assert verify_revocation_entry(entry) is True
    with open(os.path.join(home, "keys.json")) as _f:
        keys = json.load(_f)
    assert "old_private" not in keys["a"]  # retired after commit
