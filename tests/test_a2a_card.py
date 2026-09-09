"""B3 — A2A-compatible signed agent card (SPEC §11.2).

The card is a standard A2A Agent Card; ATAR trust data (identity, vouch
tokens, optional proof-of-possession) rides in a declared capability
extension, and the whole card is signed (JWS-style EdDSA entry in the card's
"signatures" array). Legacy atar-agent-card/1.0 cards stay verifiable.
"""

import json

import pytest
from click.testing import CliRunner

from atar.atc import (
    ATAR_TRUST_EXT_URI,
    _trust_params,
    card_identity,
    make_agent_card,
    new_pop_challenge,
    sign_agent_card,
    sign_pop_proof,
    verify_agent_card,
    verify_card_signature,
)
from atar.identity import did_from_public, generate_identity
from atar.vouch import create_vouch

A2A_REQUIRED_FIELDS = [
    "name",
    "description",
    "url",
    "version",
    "capabilities",
    "defaultInputModes",
    "defaultOutputModes",
    "skills",
]


def _card(signer=None):
    bob = signer or generate_identity()
    alice = generate_identity()
    v = create_vouch(alice, bob.public_key, score=0.9, scope="coding")
    card = make_agent_card(did=did_from_public(bob.public_key), name="bob", vouches=[v])
    return bob, card


def test_card_has_a2a_required_fields():
    _, card = _card()
    for field in A2A_REQUIRED_FIELDS:
        assert field in card, f"missing A2A field: {field}"
    ext = card["capabilities"]["extensions"][0]
    assert ext["uri"] == ATAR_TRUST_EXT_URI
    assert card_identity(card).startswith("did:key:")


def test_no_standalone_schema_field():
    _, card = _card()
    assert "schema" not in card  # the standalone atar-agent-card/1.0 is gone


def test_signed_card_verifies():
    bob, card = _card()
    signed = sign_agent_card(card, bob)
    assert verify_card_signature(signed)
    report = verify_agent_card(signed)
    assert report["signature_valid"] is True
    assert len(report["valid_vouches"]) == 1


def test_tampered_card_fails_signature():
    bob, card = _card()
    signed = sign_agent_card(card, bob)
    signed["name"] = "mallory"
    assert not verify_card_signature(signed)
    assert verify_agent_card(signed)["signature_valid"] is False


def test_signature_kid_must_match_presented_identity():
    """Mallory cannot sign Bob's card with her own key."""
    bob, card = _card()
    mallory = generate_identity()
    with pytest.raises(ValueError):
        sign_agent_card(card, mallory)
    # and a card whose kid points elsewhere does not verify
    signed = sign_agent_card(card, bob)
    other = generate_identity()
    other_did = did_from_public(other.public_key)
    header = json.loads(
        __import__("base64").urlsafe_b64decode(
            signed["signatures"][0]["protected"] + "=="
        )
    )
    header["kid"] = other_did + "#" + other_did.split(":")[2]
    import base64

    signed["signatures"][0]["protected"] = (
        base64.urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=").decode()
    )
    assert not verify_card_signature(signed)


def test_unsigned_card_reports_signature_absent():
    _, card = _card()
    assert verify_agent_card(card)["signature_valid"] is False


def test_legacy_card_still_verifiable():
    alice = generate_identity()
    bob = generate_identity()
    v = create_vouch(alice, bob.public_key, score=0.9, scope="coding")
    from atar.atc import vouch_to_token

    legacy = {
        "schema": "atar-agent-card/1.0",
        "did": did_from_public(bob.public_key),
        "name": "bob",
        "atar": {"vouches": [vouch_to_token(v)]},
    }
    report = verify_agent_card(legacy)
    assert report["did"] == legacy["did"]
    assert len(report["valid_vouches"]) == 1
    assert report["signature_valid"] is None  # unsigned legacy card


def test_pop_proof_lives_in_extension(tmp_path, monkeypatch):
    from atar.cli import cli

    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "bob"])
    nonce = new_pop_challenge()
    card_path = str(tmp_path / "card.json")
    r = runner.invoke(
        cli, ["card", "--name", "bob", "--challenge", nonce, "--out", card_path]
    )
    assert r.exit_code == 0, r.output
    card = json.load(open(card_path))
    assert _trust_params(card)["proof"]["nonce"] == nonce
    assert verify_card_signature(card)  # signed after the proof was embedded
    r = runner.invoke(cli, ["verify-card", card_path, "--challenge", nonce])
    assert r.exit_code == 0 and "VALID" in r.output
