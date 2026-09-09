"""Stage A3: proof-of-possession challenge for agent cards (SPEC §11.3).

Without PoP, anyone who copies Bob's agent card can present it as their own -
the card carries Bob's DID and vouches but nothing binds the presenter to the
card's key. These tests pin the challenge-response fix.
"""

import json
import os

from click.testing import CliRunner

from atar.atc import (
    make_agent_card,
    new_pop_challenge,
    sign_pop_proof,
    verify_pop_proof,
)
from atar.cli import cli
from atar.identity import did_from_public, generate_identity


def test_pop_roundtrip():
    bob = generate_identity()
    did = did_from_public(bob.public_key)
    nonce = new_pop_challenge()
    proof = sign_pop_proof(bob, did, nonce)
    assert verify_pop_proof(did, nonce, proof) is True


def test_pop_wrong_nonce_rejected():
    """A proof captured from an earlier presentation does not replay."""
    bob = generate_identity()
    did = did_from_public(bob.public_key)
    proof = sign_pop_proof(bob, did, new_pop_challenge())
    assert verify_pop_proof(did, new_pop_challenge(), proof) is False


def test_pop_wrong_key_rejected():
    """Mallory's signature over the nonce does not prove she is Bob."""
    bob = generate_identity()
    mallory = generate_identity()
    did = did_from_public(bob.public_key)
    nonce = new_pop_challenge()
    proof = sign_pop_proof(mallory, did, nonce)  # signed by the wrong key
    assert verify_pop_proof(did, nonce, proof) is False


def test_pop_tampered_signature_rejected():
    bob = generate_identity()
    did = did_from_public(bob.public_key)
    nonce = new_pop_challenge()
    proof = sign_pop_proof(bob, did, nonce)
    proof["signature"] = "00" * 64
    assert verify_pop_proof(did, nonce, proof) is False


def test_pop_missing_or_malformed_proof_rejected():
    bob = generate_identity()
    did = did_from_public(bob.public_key)
    nonce = new_pop_challenge()
    assert verify_pop_proof(did, nonce, None) is False
    assert verify_pop_proof(did, nonce, {}) is False
    assert verify_pop_proof(did, nonce, {"nonce": nonce}) is False
    assert verify_pop_proof(did, nonce, {"nonce": nonce, "signature": "zz"}) is False


def test_copied_card_without_pop_fails_verification():
    """The attack this closes: Mallory copies Bob's card and presents it."""
    bob = generate_identity()
    did = did_from_public(bob.public_key)
    from atar.atc import _trust_params, card_identity

    card = make_agent_card(did=did, name="bob", vouches=[])  # what Mallory copies
    nonce = new_pop_challenge()  # recipient's fresh challenge
    # Mallory cannot produce a proof - she does not hold Bob's key
    assert (
        verify_pop_proof(card_identity(card), nonce, _trust_params(card).get("proof"))
        is False
    )


def _keygen(runner, name):
    r = runner.invoke(cli, ["keygen", "--name", name])
    return next(line for line in r.output.splitlines() if line.startswith("did:key:"))


def test_cli_card_challenge_and_verify(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    _keygen(runner, "bob")
    nonce = new_pop_challenge()
    card_path = os.path.join(str(tmp_path), "card.json")
    r = runner.invoke(
        cli, ["card", "--name", "bob", "--challenge", nonce, "--out", card_path]
    )
    assert r.exit_code == 0, r.output
    with open(card_path) as _f:
        card = json.load(_f)
    from atar.atc import _trust_params

    proof = _trust_params(card).get("proof")
    assert proof and proof["nonce"] == nonce
    # A2A signed agent card: the CLI-signed card carries a valid signature
    from atar.atc import verify_card_signature

    assert verify_card_signature(card)
    # the real verifier's nonce passes
    r = runner.invoke(cli, ["verify-card", card_path, "--challenge", nonce])
    assert r.exit_code == 0, r.output
    assert "proof-of-possession : VALID" in r.output
    # any other nonce (replay attempt) fails
    r = runner.invoke(
        cli, ["verify-card", card_path, "--challenge", new_pop_challenge()]
    )
    assert r.exit_code == 1
    assert "proof-of-possession : INVALID" in r.output


def test_cli_verify_card_challenge_without_proof_fails(tmp_path, monkeypatch):
    """A card presented where PoP is requested must carry a proof."""
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    _keygen(runner, "bob")
    card_path = os.path.join(str(tmp_path), "card.json")
    runner.invoke(cli, ["card", "--name", "bob", "--out", card_path])  # no challenge
    r = runner.invoke(
        cli, ["verify-card", card_path, "--challenge", new_pop_challenge()]
    )
    assert r.exit_code == 1
    assert "proof-of-possession : INVALID" in r.output


def test_pop_proof_is_bound_to_the_challenged_did():
    """Cross-card replay: a proof Bob made for HIS card must not validate
    when the same nonce is presented against a different card. The signed
    message embeds the DID (domain-separated), so this follows from the
    construction - this test pins it."""
    bob = generate_identity()
    carol = generate_identity()
    did_bob = did_from_public(bob.public_key)
    did_carol = did_from_public(carol.public_key)
    nonce = new_pop_challenge()
    proof = sign_pop_proof(bob, did_bob, nonce)
    # same nonce, same proof, different card DID -> must fail
    assert verify_pop_proof(did_carol, nonce, proof) is False
    # and the honest use still passes
    assert verify_pop_proof(did_bob, nonce, proof) is True


def test_pop_nonce_reuse_across_cards_does_not_help_mallory():
    """Mallory captures Bob's proof for nonce N, then gets challenged with
    the same nonce N while presenting her own card: still rejected."""
    bob = generate_identity()
    mallory = generate_identity()
    did_bob = did_from_public(bob.public_key)
    did_mallory = did_from_public(mallory.public_key)
    nonce = new_pop_challenge()
    captured = sign_pop_proof(bob, did_bob, nonce)
    assert verify_pop_proof(did_mallory, nonce, captured) is False
