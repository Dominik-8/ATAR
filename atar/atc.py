"""ATC — Agent Trust Carrier.

The wire format that lets an agent present its verifiable identity + vouches
*inline* on first contact, over any existing transport (HTTP header,
A2A extension, MCP metadata). ATAR does not replace MCP/A2A — it rides on
top of them as a carrier.

Two primitives:
  * ``vouch_to_token`` / ``vouch_from_token`` — a vouch blob encoded as a
    header-safe string (base64url of canonical JSON).
  * ``make_agent_card`` / ``verify_agent_card`` — a self-describing JSON
    "business card" an agent sends: its DID, a name, and the vouches it
    wants to present. The receiver verifies each vouch offline.
"""

from __future__ import annotations

import base64
import json
import secrets

import base58
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .vouch import verify_vouch


def _public_key_from_did(did: str) -> Ed25519PublicKey:
    """Reconstruct the Ed25519 public key embedded in a ``did:agent:`` DID."""
    if not isinstance(did, str) or not did.startswith("did:agent:"):
        raise ValueError(f"not a did:agent: DID: {did!r}")
    raw = base58.b58decode(did[len("did:agent:"):])
    return Ed25519PublicKey.from_public_bytes(raw)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def vouch_to_token(vouch: dict) -> str:
    """Encode a vouch blob as a header-safe token string."""
    raw = json.dumps(vouch, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64url_encode(raw)


def vouch_from_token(token: str) -> dict:
    """Decode a token back into a vouch blob (dict)."""
    return json.loads(_b64url_decode(token))


def verify_token(token: str) -> bool:
    """Verify a vouch token's signature. Returns True/False."""
    try:
        return verify_vouch(vouch_from_token(token))
    except (ValueError, KeyError):
        return False


def make_agent_card(did: str, name: str, vouches: list[dict], *, extra: dict | None = None) -> dict:
    """Build an agent card carrying the agent's DID, name and vouch tokens.

    ``vouches`` is a list of vouch *blobs* (dicts); they are encoded to tokens
    here so the card is transport-ready.
    """
    card = {
        "schema": "atar-agent-card/1.0",
        "did": did,
        "name": name,
        "atar": {
            "vouches": [vouch_to_token(v) for v in vouches],
        },
    }
    if extra:
        card.update(extra)
    return card


def verify_agent_card(card: dict) -> dict:
    """Verify every vouch in an agent card offline.

    Returns a report:
        {
          "did": <card did>,
          "name": <card name>,
          "valid_vouches": [list of decoded vouch blobs that verified],
          "invalid_vouches": [list of tokens that failed],
        }
    """
    valid, invalid = [], []
    for tok in card.get("atar", {}).get("vouches", []):
        if verify_token(tok):
            valid.append(vouch_from_token(tok))
        else:
            invalid.append(tok)
    return {
        "did": card.get("did"),
        "name": card.get("name"),
        "valid_vouches": valid,
        "invalid_vouches": invalid,
    }


# --- Proof of possession (SPEC §11.3) ---------------------------------------
#
# A card proves only that *someone* holds Bob's vouches - copied bytes present
# identically. The challenge-response below proves the presenter controls the
# private key behind the card's DID: the recipient sends a fresh nonce, the
# presenter signs it, the recipient verifies against the DID's key.

POP_CONTEXT = "atar-pop/1"


def new_pop_challenge() -> str:
    """Fresh 128-bit random nonce for a proof-of-possession challenge (hex)."""
    return secrets.token_hex(16)


def pop_message(did: str, nonce: str) -> bytes:
    """The exact bytes a PoP proof signs (domain-separated, DID-bound)."""
    return f"{POP_CONTEXT}|{did}|{nonce}".encode("utf-8")


def sign_pop_proof(identity, did: str, nonce: str) -> dict:
    """Presenter side: sign the recipient's challenge nonce with the card key.

    ``identity`` may be an ``Identity`` or a bare ``Ed25519PrivateKey`` (CLI).
    """
    return {"nonce": nonce, "signature": identity.sign(pop_message(did, nonce)).hex()}


def verify_pop_proof(did: str, nonce: str, proof: dict | None) -> bool:
    """Recipient side: True iff ``proof`` signs THIS nonce with the DID's key.

    False for a missing proof, a nonce mismatch (replay of a captured proof),
    a signature by any other key, or any malformed input.
    """
    try:
        if not proof or proof.get("nonce") != nonce:
            return False
        pub = _public_key_from_did(did)
        pub.verify(bytes.fromhex(proof["signature"]), pop_message(did, nonce))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError):
        return False
