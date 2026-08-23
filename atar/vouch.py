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
                 claim: str | None = None) -> dict:
    """Create a signed vouch from ``issuer`` (Identity) for ``subject_public_key``."""
    payload = {
        "type": "vouch",
        "issuer": did_from_public(issuer.public_key),
        "subject": did_from_public(subject_public_key),
        "score": float(score),
        "scope": scope,
        "claim": claim,
        "ts": int(time.time()),
    }
    body = _canonical(payload)
    sig = issuer.sign(body)
    return {"payload": payload, "signature": sig.hex()}


def vouch_from_self(agent, *, claim: str, scope: str) -> dict:
    """A self-issued claim (not a third-party endorsement)."""
    return create_vouch(agent, agent.public_key, score=1.0, scope=scope, claim=claim)


def verify_vouch(vouch: dict) -> bool:
    """Return True iff the vouch signature is valid for its issuer DID."""
    try:
        payload = vouch["payload"]
        sig_hex = vouch["signature"]
        # Recover the issuer public key from its did:agent: (raw ed25519 bytes).
        from base58 import b58decode
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        did = payload["issuer"]
        if not did.startswith("did:agent:"):
            return False
        raw = b58decode(did[len("did:agent:"):])
        pub = Ed25519PublicKey.from_public_bytes(raw)
        pub.verify(bytes.fromhex(sig_hex), _canonical(payload))
        return True
    except (InvalidSignature, KeyError, ValueError, Exception):
        return False
