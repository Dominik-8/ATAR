"""SPEC §8.1: trust computation counts only valid, unrevoked, unexpired
vouches. Regression tests for the audit finding that `atar graph` /
compute_trust propagated trust through revoked and expired vouches.
"""

import json
import time

from click.testing import CliRunner

from atar.cli import cli
from atar.dispute import DisputeList, create_dispute
from atar.identity import did_from_public, generate_identity
from atar.revocation import RevocationList, revoke_payload_id, revoke_vouch
from atar.transparency import TrustGraph
from atar.vouch import create_vouch

NOW = int(time.time())


def _chain():
    """seed -> alice -> bob, all scope 'coding'."""
    seed, alice, bob = (generate_identity() for _ in range(3))
    v_sa = create_vouch(seed, alice.public_key, score=0.9, scope="coding")
    v_ab = create_vouch(alice, bob.public_key, score=0.9, scope="coding")
    g = TrustGraph()
    g.add(v_sa)
    g.add(v_ab)
    return g, seed, alice, bob, v_sa, v_ab


def test_revoked_vouch_propagates_no_trust():
    g, seed, alice, bob, v_sa, _v_ab = _chain()
    rl = RevocationList()
    assert revoke_vouch(rl, seed, revoke_payload_id(v_sa))
    trust = g.compute_trust(
        seed_did=did_from_public(seed.public_key), scope="coding", revocations=rl
    )
    # alice's only inbound vouch is revoked: no trust for her or downstream bob
    assert trust.get(did_from_public(alice.public_key), 0.0) == 0.0
    assert trust.get(did_from_public(bob.public_key), 0.0) == 0.0
    # sanity: without the revocation list the same graph trusts both
    unfiltered = g.compute_trust(
        seed_did=did_from_public(seed.public_key), scope="coding"
    )
    assert unfiltered[did_from_public(bob.public_key)] > 0.0


def test_revocation_by_non_issuer_does_not_apply():
    """SPEC §6: only the issuer's revocation kills a vouch."""
    g, seed, alice, _bob, v_sa, _ = _chain()
    mallory = generate_identity()
    rl = RevocationList()
    # mallory "revokes" alice's vouch - entry verifies against her own key
    # but is not issuer-bound, so it must not apply
    assert revoke_vouch(rl, mallory, revoke_payload_id(v_sa))
    trust = g.compute_trust(
        seed_did=did_from_public(seed.public_key), scope="coding", revocations=rl
    )
    assert trust[did_from_public(alice.public_key)] > 0.0


def test_expired_vouch_propagates_no_trust():
    seed, alice = generate_identity(), generate_identity()
    stale = create_vouch(
        seed, alice.public_key, score=0.9, scope="coding", ts=NOW - 200 * 24 * 3600
    )  # 200 days old
    g = TrustGraph()
    g.add(stale)
    trust = g.compute_trust(
        seed_did=did_from_public(seed.public_key),
        scope="coding",
        ttl=180 * 24 * 3600,
        now=NOW,
    )
    assert trust.get(did_from_public(alice.public_key), 0.0) == 0.0
    # same vouch, no TTL given: library default stays unfiltered
    unfiltered = g.compute_trust(
        seed_did=did_from_public(seed.public_key), scope="coding"
    )
    assert unfiltered[did_from_public(alice.public_key)] > 0.0


def test_dispute_and_revocation_compose():
    """A revoked disputer's warnings count for nothing (pass 1 is filtered)."""
    g, seed, _alice, bob, _v_sa, v_ab = _chain()
    carol = generate_identity()
    v_sc = create_vouch(seed, carol.public_key, score=0.9, scope="coding")
    g.add(v_sc)
    rl = RevocationList()
    assert revoke_vouch(rl, seed, revoke_payload_id(v_sc))  # carol defrocked
    dl = DisputeList()
    dl.add(create_dispute(carol, v_ab, reason="sour grapes", ts=NOW))
    trust = g.compute_trust(
        seed_did=did_from_public(seed.public_key),
        scope="coding",
        revocations=rl,
        disputes=dl,
    )
    # carol's pass-1 trust is 0 (her vouch is revoked), so her dispute must
    # NOT discount alice->bob
    assert trust[did_from_public(bob.public_key)] > 0.0


def test_graph_cli_filters_revoked_and_expired(tmp_path, monkeypatch):
    """End to end: `atar graph` over the store hides revoked/expired trust."""
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    for name in ("seed", "alice", "mallory"):
        assert runner.invoke(cli, ["keygen", "--name", name]).exit_code == 0
    keys = json.loads((tmp_path / "keys.json").read_text())
    seed_did, alice_did = keys["seed"]["did"], keys["alice"]["did"]

    vouch_path = tmp_path / "v.json"
    assert (
        runner.invoke(
            cli,
            [
                "vouch",
                "--from",
                "seed",
                "--for",
                alice_did,
                "--score",
                "0.9",
                "--scope",
                "coding",
                "--out",
                str(vouch_path),
            ],
        ).exit_code
        == 0
    )
    assert runner.invoke(cli, ["add", str(vouch_path)]).exit_code == 0

    r = runner.invoke(cli, ["graph", "--seed", seed_did, "--scope", "coding"])
    assert r.exit_code == 0 and alice_did in r.output  # trusted before revoke

    assert runner.invoke(cli, ["revoke", str(vouch_path)]).exit_code == 0
    r = runner.invoke(cli, ["graph", "--seed", seed_did, "--scope", "coding"])
    assert r.exit_code == 0
    assert alice_did not in r.output  # revoked: no trust, not listed
