"""Interoperability test vectors.

Golden vectors under ``tests/vectors/`` pin the exact wire formats a
third-party implementation must reproduce to interoperate with ATAR:
``did:key`` derivation, JCS canonicalization, the native vouch format +
content address, the revocation entry format, and the W3C VC export.

These tests guard both directions: the implementation must keep matching
the published vectors (no silent format drift), and every signed vector
must verify with the public verification paths.
"""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from atar.atc import (
    make_agent_card,
    sign_agent_card,
    verify_agent_card,
    verify_card_signature,
    verify_token,
    vouch_from_token,
    vouch_to_token,
)
from atar.identity import (
    Identity,
    did_key_from_public,
    legacy_did_agent_from_public,
    normalize_did,
    public_key_from_did,
)
from atar.jcs import canonicalize
from atar.revocation import verify_revocation_entry
from atar.rotation import RotationStatement, verify_rotation
from atar.transparency import canonical_vouch_id
from atar.vc import (
    credential_to_vouch_payload,
    verify_credential,
    vouch_to_credential,
)
from atar.vouch import create_vouch, verify_vouch

VECTORS = Path(__file__).parent / "vectors"


def _load(name: str) -> dict:
    return json.loads((VECTORS / name).read_text(encoding="utf-8"))


def test_identity_derivation_matches_vectors():
    data = _load("identity.json")
    for vec in data["vectors"]:
        priv = Ed25519PrivateKey.from_private_bytes(
            bytes.fromhex(vec["private_key_seed_hex"])
        )
        pub = priv.public_key()
        assert pub.public_bytes_raw().hex() == vec["public_key_raw_hex"]
        assert did_key_from_public(pub) == vec["did_key"]
        assert legacy_did_agent_from_public(pub) == vec["legacy_did_agent"]
        # round-trips and aliasing
        assert (
            public_key_from_did(vec["did_key"]).public_bytes_raw()
            == pub.public_bytes_raw()
        )
        assert (
            public_key_from_did(vec["legacy_did_agent"]).public_bytes_raw()
            == pub.public_bytes_raw()
        )
        assert normalize_did(vec["legacy_did_agent"]) == vec["did_key"]


def test_jcs_canonicalization_matches_vectors():
    data = _load("jcs.json")
    for vec in data["vectors"]:
        assert canonicalize(vec["input"]).decode("utf-8") == vec["canonical"], vec[
            "note"
        ]


def test_vouch_vector_matches_and_verifies():
    data = _load("native-vouch.json")
    vouch = data["vouch"]
    # the pinned vouch verifies through the public path
    assert verify_vouch(vouch)
    assert canonical_vouch_id(vouch) == data["canonical_vouch_id"]
    assert vouch["payload"]["issuer"] == data["issuer_did"]
    assert vouch["payload"]["subject"] == data["subject_did"]
    # and the implementation still produces byte-identical vouches
    identity_vec = {v["name"]: v for v in _load("identity.json")["vectors"]}
    issuer_priv = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(identity_vec["issuer"]["private_key_seed_hex"])
    )
    issuer = Identity(private_key=issuer_priv, public_key=issuer_priv.public_key())
    subject_pub = public_key_from_did(data["subject_did"])
    reproduced = create_vouch(
        issuer,
        subject_pub,
        score=vouch["payload"]["score"],
        scope=vouch["payload"]["scope"],
        claim=vouch["payload"]["claim"],
        evidence=vouch["payload"].get("evidence"),
        ts=vouch["payload"]["ts"],
    )
    assert reproduced == vouch  # Ed25519 is deterministic


def test_revocation_vector_verifies():
    data = _load("revocation.json")
    assert verify_revocation_entry(data["entry"])
    # the entry revokes the pinned vouch from native-vouch.json
    vouch = _load("native-vouch.json")["vouch"]
    assert data["entry"]["vid"] == canonical_vouch_id(vouch)
    assert data["entry"]["revoked_by"] == vouch["payload"]["issuer"]


def test_atc_token_vector_roundtrips_and_verifies():
    data = _load("atc-token.json")
    vouch = data["vouch"]
    assert vouch_to_token(vouch) == data["token"]  # deterministic encoding
    assert vouch_from_token(data["token"]) == vouch
    assert verify_token(data["token"])


def test_agent_card_vector_matches_and_verifies():
    data = _load("agent-card.json")
    vouch = _load("native-vouch.json")["vouch"]
    subject_vec = {v["name"]: v for v in _load("identity.json")["vectors"]}["subject"]
    subject_priv = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(subject_vec["private_key_seed_hex"])
    )
    subject = Identity(private_key=subject_priv, public_key=subject_priv.public_key())

    card = data["unsigned_card"]
    reproduced = make_agent_card(
        subject_vec["did_key"],
        "subject-agent",
        [vouch],
        url="https://agent.example.org/a2a",
        description="Test subject agent",
    )
    assert reproduced == card  # card construction is deterministic
    signed = sign_agent_card(card, subject)
    assert signed == data["signed_card"]  # Ed25519 is deterministic
    assert verify_card_signature(data["signed_card"])
    report = verify_agent_card(data["signed_card"])
    assert report["signature_valid"] is True
    assert report["did"] == subject_vec["did_key"]
    assert len(report["valid_vouches"]) == 1 and not report["invalid_vouches"]


def test_rotation_vector_verifies():
    data = _load("rotation.json")
    stmt = RotationStatement.from_dict(data["statement"])
    assert verify_rotation(stmt)
    identity_vec = {v["name"]: v for v in _load("identity.json")["vectors"]}
    assert stmt.old_did == identity_vec["issuer"]["did_key"]


def test_vc_export_vector_matches_and_verifies():
    data = _load("vc-export.json")
    vouch = _load("native-vouch.json")["vouch"]
    # unsigned export is fully deterministic
    assert vouch_to_credential(vouch) == data["unsigned_credential"]
    # the pinned signed credential verifies offline through the public path
    assert verify_credential(data["signed_credential"])
    # and still carries the same claim content as the native vouch
    payload = credential_to_vouch_payload(data["signed_credential"])
    assert payload["issuer"] == vouch["payload"]["issuer"]
    assert payload["subject"] == vouch["payload"]["subject"]
    assert payload["score"] == vouch["payload"]["score"]
    assert payload["scope"] == vouch["payload"]["scope"]
    assert payload["ts"] == vouch["payload"]["ts"]
