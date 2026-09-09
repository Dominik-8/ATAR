import os
import json
import tempfile

from click.testing import CliRunner

from atar.cli import cli
from atar.store import VouchStore


def _agent_home(base, name):
    p = os.path.join(base, name)
    os.makedirs(p, exist_ok=True)
    return p


def _make_vouch(home, issuer_name, subject_did, score, scope):
    # create a vouch in `home` by registering issuer + subject identities there
    from atar.agent_bootstrap import AgentRegistry

    reg = AgentRegistry()
    reg.register(issuer_name)
    # subject may live in another home; we just need a DID string to vouch for
    reg._agents[subject_did] = {"did": subject_did, "private": "00" * 32}
    reg._save()
    return reg.vouch(issuer_name, subject_did, score=score, scope=scope)


def test_sync_exchanges_vouches_between_stores(tmp_path, monkeypatch):
    # two agent stores: alice and bob
    alice = _agent_home(str(tmp_path), "alice")
    bob = _agent_home(str(tmp_path), "bob")
    monkeypatch.setenv("ATAR_HOME", alice)
    runner = CliRunner()

    # alice creates a vouch for some DID
    from atar.identity import generate_identity, did_from_public

    subj = generate_identity()
    subj_did = did_from_public(subj.public_key)
    _make_vouch(alice, "alice_agent", subj_did, 0.9, "intelligence")

    # bob starts empty
    bob_store = VouchStore(os.path.join(bob, "vouches.json"))
    assert bob_store.count() == 0

    # sync alice -> bob
    r = runner.invoke(cli, ["sync", "--with", bob])
    assert r.exit_code == 0

    # bob now has alice's vouch
    bob_store2 = VouchStore(os.path.join(bob, "vouches.json"))
    assert bob_store2.count() == 1


def test_sync_is_idempotent(tmp_path, monkeypatch):
    alice = _agent_home(str(tmp_path), "alice")
    bob = _agent_home(str(tmp_path), "bob")
    monkeypatch.setenv("ATAR_HOME", alice)
    runner = CliRunner()
    from atar.identity import generate_identity, did_from_public

    subj = generate_identity()
    subj_did = did_from_public(subj.public_key)
    _make_vouch(alice, "alice_agent", subj_did, 0.9, "intelligence")

    runner.invoke(cli, ["sync", "--with", bob])
    c1 = VouchStore(os.path.join(bob, "vouches.json")).count()
    runner.invoke(cli, ["sync", "--with", bob])
    c2 = VouchStore(os.path.join(bob, "vouches.json")).count()
    assert c1 == c2 == 1  # no duplication


def test_sync_bidirectional(tmp_path, monkeypatch):
    alice = _agent_home(str(tmp_path), "alice")
    bob = _agent_home(str(tmp_path), "bob")
    runner = CliRunner()
    from atar.identity import generate_identity, did_from_public

    # alice has a vouch
    monkeypatch.setenv("ATAR_HOME", alice)
    s1 = generate_identity()
    _make_vouch(
        alice, "alice_agent", did_from_public(s1.public_key), 0.9, "intelligence"
    )
    # bob has a different vouch
    monkeypatch.setenv("ATAR_HOME", bob)
    s2 = generate_identity()
    _make_vouch(bob, "bob_agent", did_from_public(s2.public_key), 0.8, "intelligence")

    # sync both directions
    monkeypatch.setenv("ATAR_HOME", alice)
    runner.invoke(cli, ["sync", "--with", bob])
    monkeypatch.setenv("ATAR_HOME", bob)
    runner.invoke(cli, ["sync", "--with", alice])

    assert VouchStore(os.path.join(alice, "vouches.json")).count() == 2
    assert VouchStore(os.path.join(bob, "vouches.json")).count() == 2
