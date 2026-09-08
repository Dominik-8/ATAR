"""Stage A3: proof-of-possession challenge for agent cards (SPEC §11.3).

Without PoP, anyone who copies Bob's agent card can present it as their own -
the card carries Bob's DID and vouches but nothing binds the presenter to the
card's key. These tests pin the challenge-response fix.
"""
import json
import os

from click.testing import CliRunner

from atar.cli import cli
from atar.identity import generate_identity, did_from_public
from atar.atc import (
    make_agent_card,
    new_pop_challenge,
    sign_pop_proof,
    verify_pop_proof,
)


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
    card = make_agent_card(did=did, name="bob", vouches=[])  # what Mallory copies
    nonce = new_pop_challenge()  # recipient's fresh challenge
    # Mallory cannot produce a proof - she does not hold Bob's key
    assert verify_pop_proof(card["did"], nonce, card.get("proof")) is False


def _keygen(runner, name):
    r = runner.invoke(cli, ["keygen", "--name", name])
    return [l for l in r.output.splitlines() if l.startswith("did:agent:")][0]


def test_cli_card_challenge_and_verify(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    _keygen(runner, "bob")
    nonce = new_pop_challenge()
    card_path = os.path.join(str(tmp_path), "card.json")
    r = runner.invoke(cli, ["card", "--name", "bob", "--challenge", nonce,
                            "--out", card_path])
    assert r.exit_code == 0, r.output
    card = json.load(open(card_path))
    assert "proof" in card and card["proof"]["nonce"] == nonce
    # the real verifier's nonce passes
    r = runner.invoke(cli, ["verify-card", card_path, "--challenge", nonce])
    assert r.exit_code == 0, r.output
    assert "proof-of-possession : VALID" in r.output
    # any other nonce (replay attempt) fails
    r = runner.invoke(cli, ["verify-card", card_path, "--challenge", new_pop_challenge()])
    assert r.exit_code == 1
    assert "proof-of-possession : INVALID" in r.output


def test_cli_verify_card_challenge_without_proof_fails(tmp_path, monkeypatch):
    """A card presented where PoP is requested must carry a proof."""
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    _keygen(runner, "bob")
    card_path = os.path.join(str(tmp_path), "card.json")
    runner.invoke(cli, ["card", "--name", "bob", "--out", card_path])  # no challenge
    r = runner.invoke(cli, ["verify-card", card_path, "--challenge", new_pop_challenge()])
    assert r.exit_code == 1
    assert "proof-of-possession : INVALID" in r.output
