"""Stage C3: score semantics (evidence references) + signed disputes (SPEC 3.2, 7, 8.2)."""

import json
import os

import pytest
from click.testing import CliRunner

from atar.cli import cli
from atar.dispute import (DISPUTE_TRUST_THRESHOLD, DisputeList, create_dispute,
                          verify_dispute_entry)
from atar.identity import generate_identity, did_from_public
from atar.store import VouchStore
from atar.transparency import TrustGraph, canonical_vouch_id
from atar.vouch import create_vouch


def _vouch(issuer=None, subject=None, score=0.9, scope="coding", **kw):
    issuer = issuer or generate_identity()
    subject = subject or generate_identity()
    return create_vouch(issuer, subject.public_key, score=score, scope=scope, **kw), issuer, subject


# --- evidence references (score semantics) -----------------------------------

def test_evidence_is_signed_and_optional():
    v, _, _ = _vouch(evidence=["https://ops.example/task/42", "ticket:ATAR-7"])
    assert v["payload"]["evidence"] == ["https://ops.example/task/42", "ticket:ATAR-7"]
    from atar.vouch import verify_vouch
    assert verify_vouch(v)
    # tampering with evidence breaks the signature
    v["payload"]["evidence"] = ["https://evil.example/fake"]
    assert not verify_vouch(v)


def test_evidence_joins_content_address():
    a, b = generate_identity(), generate_identity()
    with_ev, _, _ = _vouch(a, b, evidence=["x"], ts=1000)
    without, _, _ = _vouch(a, b, ts=1000)
    assert canonical_vouch_id(with_ev) != canonical_vouch_id(without)


# --- dispute creation + verification ------------------------------------------

def test_create_and_verify_dispute():
    v, _, _ = _vouch()
    disputer = generate_identity()
    e = create_dispute(disputer, v, reason="observed fraud in task output", ts=1000)
    assert verify_dispute_entry(e)
    assert e["vid"] == canonical_vouch_id(v)
    assert e["disputed_by"] == did_from_public(disputer.public_key)


def test_issuer_cannot_dispute_own_vouch():
    v, issuer, _ = _vouch()
    with pytest.raises(ValueError):
        create_dispute(issuer, v, reason="changed my mind")  # -> revoke instead


def test_tampered_dispute_dropped_on_load(tmp_path):
    v, _, _ = _vouch()
    e = create_dispute(generate_identity(), v, reason="fraud", ts=1000)
    path = str(tmp_path / "disputes.json")
    DisputeList().add(e)
    dl = DisputeList()
    dl.add(e)
    dl.save(path)
    # tamper with the file
    data = json.load(open(path))
    data["disputes"][0]["reason"] = "totally different reason"
    json.dump(data, open(path, "w"))
    assert DisputeList.load(path).all() == []


def test_dispute_dedup():
    v, _, _ = _vouch()
    d = generate_identity()
    e1 = create_dispute(d, v, reason="fraud", ts=1000)
    e2 = create_dispute(d, v, reason="fraud", ts=2000)  # same statement, new ts
    dl = DisputeList()
    assert dl.add(e1)
    assert not dl.add(e2)  # content-addressed: same vid+disputer+reason
    e3 = create_dispute(d, v, reason="different reason", ts=1000)
    assert dl.add(e3)


# --- disputes in trust computation (SPEC 8.2) ---------------------------------

def _graph_with_chain():
    """seed --0.9--> alice --0.9--> bob (scope=coding)."""
    seed, alice, bob = generate_identity(), generate_identity(), generate_identity()
    v_sa, _, _ = _vouch(seed, alice, score=0.9)
    v_ab, _, _ = _vouch(alice, bob, score=0.9)
    g = TrustGraph()
    g.add(v_sa)
    g.add(v_ab)
    return g, seed, alice, bob, v_sa, v_ab


def test_untrusted_disputer_does_not_move_scores():
    g, seed, alice, bob, _, v_ab = _graph_with_chain()
    sybil = generate_identity()  # nobody trusts the Sybil
    dl = DisputeList()
    dl.add(create_dispute(sybil, v_ab, reason="spam", ts=1000))
    with_d = g.compute_trust(seed_did=did_from_public(seed.public_key),
                             scope="coding", disputes=dl)
    without = g.compute_trust(seed_did=did_from_public(seed.public_key), scope="coding")
    assert with_d == without


def test_trusted_disputer_discounts_vouch():
    g, seed, alice, bob, _, v_ab = _graph_with_chain()
    dl = DisputeList()
    dl.add(create_dispute(seed, v_ab, reason="bob's output failed review", ts=1000))
    with_d = g.compute_trust(seed_did=did_from_public(seed.public_key),
                             scope="coding", disputes=dl)
    assert did_from_public(bob.public_key) not in with_d or with_d[did_from_public(bob.public_key)] == 0.0
    # alice's own trust is untouched (the dispute targeted her vouch FOR bob)
    assert with_d[did_from_public(alice.public_key)] > 0.0


def test_threshold_boundary():
    # carol is a third party trusted at exactly 0.9 (>= 0.5): her dispute counts
    g, seed, alice, bob, v_sa, v_ab = _graph_with_chain()
    carol = generate_identity()
    v_sc, _, _ = _vouch(seed, carol, score=0.9)
    g.add(v_sc)
    dl = DisputeList()
    dl.add(create_dispute(carol, v_ab, reason="reviewed and failed", ts=1000))
    with_d = g.compute_trust(seed_did=did_from_public(seed.public_key),
                             scope="coding", disputes=dl)
    assert with_d.get(did_from_public(bob.public_key), 0.0) == 0.0
    assert DISPUTE_TRUST_THRESHOLD == 0.5


# --- CLI ----------------------------------------------------------------------

def test_dispute_cli_and_listing(tmp_path, monkeypatch):
    home = str(tmp_path)
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "watcher"])
    v, _, _ = _vouch()
    vf = str(tmp_path / "v.json")
    json.dump(v, open(vf, "w"))
    r = runner.invoke(cli, ["dispute", vf, "--from", "watcher", "--reason", "bad output"])
    assert r.exit_code == 0, r.output
    assert "dispute recorded" in r.output
    r2 = runner.invoke(cli, ["disputes"])
    assert "bad output" in r2.output
    # duplicate is rejected
    r3 = runner.invoke(cli, ["dispute", vf, "--from", "watcher", "--reason", "bad output"])
    assert r3.exit_code == 1


def test_dispute_cli_issuer_rejected(tmp_path, monkeypatch):
    home = str(tmp_path)
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    keys = json.load(open(os.path.join(home, "keys.json")))
    alice_did = keys["alice"]["did"]
    # alice vouches for someone; she cannot dispute her own vouch
    _, subject = generate_identity(), generate_identity()
    from atar.identity import public_key_from_did
    import atar.identity as I
    priv_hex = keys["alice"]["private"]
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(priv_hex))
    from atar.identity import Identity
    ident = Identity(private_key=priv, public_key=priv.public_key())
    v = create_vouch(ident, subject.public_key, score=0.9, scope="coding")
    vf = str(tmp_path / "v.json")
    json.dump(v, open(vf, "w"))
    r = runner.invoke(cli, ["dispute", vf, "--from", "alice", "--reason", "oops"])
    assert r.exit_code == 1
    assert "revoke" in r.output


def test_verify_warns_about_disputes(tmp_path, monkeypatch):
    home = str(tmp_path)
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    v, _, _ = _vouch()
    vf = str(tmp_path / "v.json")
    json.dump(v, open(vf, "w"))
    dl = DisputeList()
    dl.add(create_dispute(generate_identity(), v, reason="suspicious", ts=1000))
    dl.save(os.path.join(home, "disputes.json"))
    r = runner.invoke(cli, ["verify", vf])
    assert r.exit_code == 0
    assert "VALID" in r.output
    assert "dispute" in (r.stderr or "").lower()


# --- gossip -------------------------------------------------------------------

def test_disputes_sync_over_filesystem(tmp_path, monkeypatch):
    home_a = str(tmp_path / "a")
    home_b = str(tmp_path / "b")
    os.makedirs(home_a)
    os.makedirs(home_b)
    monkeypatch.setenv("ATAR_HOME", home_a)
    v, _, _ = _vouch()
    dl = DisputeList()
    dl.add(create_dispute(generate_identity(), v, reason="fraud", ts=1000))
    dl.save(os.path.join(home_a, "disputes.json"))
    runner = CliRunner()
    r = runner.invoke(cli, ["sync", "--with", home_b])
    assert r.exit_code == 0, r.output
    assert "+1 disputes" in r.output
    assert len(DisputeList.load(os.path.join(home_b, "disputes.json")).all()) == 1


def test_disputes_sync_over_http(tmp_path, monkeypatch):
    from atar.peer import run_peer
    home_b = str(tmp_path / "b")
    os.makedirs(home_b)
    srv = run_peer(port=0, bind="127.0.0.1", home=home_b, _block=False)
    url = f"http://127.0.0.1:{srv.server_address[1]}"
    try:
        home_a = str(tmp_path / "a")
        os.makedirs(home_a)
        monkeypatch.setenv("ATAR_HOME", home_a)
        v, _, _ = _vouch()
        dl = DisputeList()
        dl.add(create_dispute(generate_identity(), v, reason="fraud", ts=1000))
        dl.save(os.path.join(home_a, "disputes.json"))
        runner = CliRunner()
        r = runner.invoke(cli, ["sync", "--with", url])
        assert r.exit_code == 0, r.output
        assert len(DisputeList.load(os.path.join(home_b, "disputes.json")).all()) == 1
    finally:
        srv.shutdown()
        srv.server_close()
