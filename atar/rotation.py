"""Key rotation — recover from a key leak without losing the trust graph.

Revocation (Phase 16) kills trust. Freshness (Phase 24) lets it expire. But
neither lets an agent *come back* after a key leak without starting from zero:
every vouch it issued becomes unverifiable (the old key is gone) and every
vouch it received points at a dead DID.

Rotation fixes that:
  • ``rotate_identity(old, new)`` produces a signed RotationStatement binding
    the new DID to the old one (old key signs "I am now <newdid>").
  • ``reissue_vouch(old_issuer, new_issuer, vouch, ...)`` re-signs an
    out-going vouch under the new key, preserving score/scope and stamping a
    fresh ts (uses the ts= override from Phase 24).
  • ``verify_rotation`` lets verifiers confirm the new DID is controlled by the
    same agent that owned the old one — continuity, not a fresh start.

The old key may then be revoked; the new key + re-issued vouches carry the
trust graph forward. No servers, no cost.
"""

from __future__ import annotations

import time
from dataclasses import dataclass

from cryptography.exceptions import InvalidSignature

from .identity import did_from_public
from .vouch import _canonical, create_vouch


@dataclass
class RotationStatement:
    old_did: str
    new_did: str
    ts: int
    signature: str  # old key signs the canonical rotation payload

    def to_dict(self) -> dict:
        return {
            "type": "rotation",
            "old_did": self.old_did,
            "new_did": self.new_did,
            "ts": self.ts,
            "signature": self.signature,
        }

    @classmethod
    def from_dict(cls, d: dict) -> RotationStatement:
        return cls(
            old_did=d["old_did"],
            new_did=d["new_did"],
            ts=d["ts"],
            signature=d["signature"],
        )


def rotate_identity(old, new) -> RotationStatement:
    """Bind a new identity to an old one (old key signs the rotation).

    Accepts ``Ed25519PrivateKey`` objects (as returned by the CLI loader) or
    ``Identity`` objects interchangeably.
    """
    old_pub = (
        old.public_key()
        if hasattr(old, "public_key") and callable(old.public_key)
        else old.public_key
    )
    new_pub = (
        new.public_key()
        if hasattr(new, "public_key") and callable(new.public_key)
        else new.public_key
    )
    payload = {
        "type": "rotation",
        "old_did": did_from_public(old_pub),
        "new_did": did_from_public(new_pub),
        "ts": int(time.time()),
    }
    sig = old.sign(_canonical(payload))
    return RotationStatement(
        old_did=payload["old_did"],
        new_did=payload["new_did"],
        ts=payload["ts"],
        signature=sig.hex(),
    )


def verify_rotation(stmt: RotationStatement) -> bool:
    """True iff the rotation is genuinely signed by the OLD key."""
    try:
        from .identity import public_key_from_did

        pub = public_key_from_did(stmt.old_did)
        payload = {
            "type": "rotation",
            "old_did": stmt.old_did,
            "new_did": stmt.new_did,
            "ts": stmt.ts,
        }
        pub.verify(bytes.fromhex(stmt.signature), _canonical(payload))
        return True
    except (InvalidSignature, ValueError, KeyError, AttributeError):
        return False


def reissue_vouch(
    old_issuer,
    new_issuer,
    vouch: dict,
    *,
    scope: str | None = None,
    score: float | None = None,
) -> dict:
    """Re-sign an out-going vouch under the NEW key, fresh ts (Phase 24).

    Preserves subject/score/scope/claim/evidence; only the issuer key +
    timestamp change.
    Accepts Ed25519PrivateKey objects (CLI) or Identity objects.
    Returns a new, validly-signed vouch blob attributable to the new DID.
    """
    p = vouch["payload"]
    subject_did = p["subject"]
    # recover the subject public key from its DID (did:key or legacy)
    from .identity import public_key_from_did

    subj_pub = public_key_from_did(subject_did)
    return create_vouch(
        new_issuer,
        subj_pub,
        score=float(score if score is not None else p["score"]),
        scope=scope if scope is not None else p["scope"],
        claim=p.get("claim"),
        evidence=p.get("evidence"),
    )
