"""Signed vouch (attestation) blobs for the ATAR trust layer.

A *vouch* is a signed statement by one agent ("issuer") that endorses another
agent ("subject") for a given scope with a score. Vouches are content the
subject can present to prove reputation, and anyone can verify them offline
for $0 with the issuer's public key.

Wire format (JSON, canonical):
    {
      "payload": {
        "type": "vouch",
        "issuer": "did:agent:...",
        "subject": "did:agent:...",
        "score": 0.9,
        "scope": "coding",
        "claim": null,            # optional free-text for self-vouches
        "ts": 1690000000
      },
      "signature": "<hex ed25519 signature over canonical payload bytes>"
    }
"""

from __future__ import annotations

import json
import time

from cryptography.exceptions import InvalidSignature

from .identity import did_from_public


def _canonical(payload: dict) -> bytes:
    """Deterministic JSON serialization so signing/verifying match."""
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def create_vouch(issuer, subject_public_key, *, score: float, scope: str,
                 claim: str | None = None, ts: int | None = None) -> dict:
    """Create a signed vouch from ``issuer`` for ``subject_public_key``.

    ``issuer`` may be an ``Identity`` or a bare ``Ed25519PrivateKey`` (as used
    by the CLI / key-rotation paths). ``subject_public_key`` is the subject's
    Ed25519 public key. ``ts`` lets callers backdate the timestamp (used for
    tests and for re-issuing a vouch with a fresh validity window during key
    rotation).
    """
    issuer_pub = issuer.public_key() if hasattr(issuer, "public_key") and callable(getattr(issuer, "public_key")) else issuer.public_key
    payload = {
        "type": "vouch",
        "issuer": did_from_public(issuer_pub),
        "subject": did_from_public(subject_public_key),
        "score": float(score),
        "scope": scope,
        "claim": claim,
        "ts": int(ts if ts is not None else time.time()),
    }
    body = _canonical(payload)
    sig = issuer.sign(body)
    return {"payload": payload, "signature": sig.hex()}


def vouch_from_self(agent, *, claim: str, scope: str) -> dict:
    """A self-issued claim (not a third-party endorsement)."""
    return create_vouch(agent, agent.public_key, score=1.0, scope=scope, claim=claim)


def verify_vouch(vouch: dict) -> bool:
    """Return True iff the vouch signature is valid for its issuer DID.

    Accepts issuers identified by ``did:key`` or legacy ``did:agent:`` — both
    embed the raw Ed25519 key, so pre-realignment vouches stay verifiable
    unchanged (SPEC §2).
    """
    try:
        if not isinstance(vouch, dict):
            return False
        payload = vouch["payload"]
        sig_hex = vouch["signature"]
        # Recover the issuer public key from its DID (did:key or did:agent:).
        from .identity import public_key_from_did
        pub = public_key_from_did(payload["issuer"])
        pub.verify(bytes.fromhex(sig_hex), _canonical(payload))
        return True
    except (InvalidSignature, KeyError, ValueError, TypeError, AttributeError):
        # InvalidSignature: bad signature. KeyError/ValueError/TypeError/
        # AttributeError: malformed vouch (wrong field types).
        return False
