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

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

from .vouch import verify_vouch


def _public_key_from_did(did: str) -> Ed25519PublicKey:
    """Reconstruct the Ed25519 public key embedded in a DID (did:key or legacy)."""
    from .identity import public_key_from_did

    return public_key_from_did(did)


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


# --- A2A-compatible signed agent card (SPEC §11.2) ---------------------------
#
# The card is a standard A2A Agent Card; ATAR's trust data (identity, vouch
# tokens, optional proof-of-possession) rides in a declared extension, and the
# whole card is signed with a JWS-style EdDSA signature in the card's
# "signatures" array. Any A2A-speaking system can read the card; ATAR-aware
# verifiers additionally check the trust extension and the signature.

ATAR_TRUST_EXT_URI = "https://github.com/Dominik-8/ATAR/ext/atar-trust/1.0"
LEGACY_CARD_SCHEMA = "atar-agent-card/1.0"


def _trust_params(card: dict) -> dict:
    """The ATAR trust extension params of a card ({} when absent).

    Also reads the pre-realignment standalone layout (``schema``/
    ``did``/``atar.vouches``) so legacy cards stay verifiable.
    """
    if card.get("schema") == LEGACY_CARD_SCHEMA:
        legacy = dict(card.get("atar", {}))
        legacy.setdefault("identity", card.get("did"))
        return legacy
    for ext in card.get("capabilities", {}).get("extensions", []):
        if ext.get("uri") == ATAR_TRUST_EXT_URI:
            return ext.get("params", {}) or {}
    return {}


def card_identity(card: dict) -> str | None:
    """The DID this card presents (from the ATAR trust extension)."""
    did = _trust_params(card).get("identity")
    return did if isinstance(did, str) else None


def make_agent_card(
    did: str,
    name: str,
    vouches: list[dict],
    *,
    url: str | None = None,
    description: str | None = None,
    extra: dict | None = None,
) -> dict:
    """Build an A2A-compatible agent card carrying ATAR trust data.

    ``vouches`` is a list of vouch *blobs* (dicts); they are encoded to tokens
    (§11.1) inside the ATAR trust extension. ``url`` is the agent's A2A
    endpoint when it has one; offline agents default to a ``urn:atar:agent:``
    identifier URI.
    """
    card = {
        "name": name,
        "description": description
        or (
            f"ATAR agent '{name}' - identity and vouches carried in the ATAR "
            f"trust extension ({ATAR_TRUST_EXT_URI})"
        ),
        "url": url or f"urn:atar:agent:{did}",
        "version": "1.0.0",
        "capabilities": {
            "extensions": [
                {
                    "uri": ATAR_TRUST_EXT_URI,
                    "description": "ATAR trust data: presented identity, vouch "
                    "tokens (SPEC §11.1) and an optional "
                    "proof-of-possession (§11.3)",
                    "required": False,
                    "params": {
                        "identity": did,
                        "vouches": [vouch_to_token(v) for v in vouches],
                    },
                }
            ],
        },
        "defaultInputModes": ["application/json"],
        "defaultOutputModes": ["application/json"],
        "skills": [],
    }
    if extra:
        card.update(extra)
    return card


def sign_agent_card(card: dict, identity) -> dict:
    """Sign a card (A2A Agent Card signature): a JWS-style flattened entry in
    the card's ``signatures`` array, EdDSA over the card without that array.

    The signing input is ``b64u(protected) || "." || b64u(payload)`` (JWS
    convention) where the payload is the canonical JSON (§4) of the card
    minus ``signatures``. ``kid`` binds the signature to the card's presented
    identity DID (alias-aware, §2.1).
    """
    from .identity import did_from_public, normalize_did

    pub = (
        identity.public_key()
        if callable(getattr(identity, "public_key", None))
        else identity.public_key
    )
    did = did_from_public(pub)
    presented = card_identity(card)
    if presented is None:
        raise ValueError("card carries no ATAR identity to sign for")
    if normalize_did(presented) != did:
        raise ValueError("signing key does not match the card's presented identity")
    protected = _b64url_encode(
        json.dumps(
            {"alg": "EdDSA", "kid": did + "#" + did.split(":")[2], "typ": "JWS"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
    )
    payload = json.dumps(
        {k: v for k, v in card.items() if k != "signatures"},
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signing_input = (protected + "." + _b64url_encode(payload)).encode("ascii")
    entry = {
        "protected": protected,
        "signature": _b64url_encode(identity.sign(signing_input)),
    }
    out = dict(card)
    out["signatures"] = list(card.get("signatures", [])) + [entry]
    return out


def verify_card_signature(card: dict) -> bool:
    """True iff some signature in the card's ``signatures`` array verifies
    against the card's presented identity (kid must match it, alias-aware)."""
    try:
        from .identity import normalize_did

        presented = card_identity(card)
        if presented is None:
            return False
        entries = card.get("signatures") or []
        if not entries:
            return False
        payload = json.dumps(
            {k: v for k, v in card.items() if k != "signatures"},
            sort_keys=True,
            separators=(",", ":"),
        ).encode("utf-8")
        for entry in entries:
            header = json.loads(_b64url_decode(entry["protected"]))
            if header.get("alg") != "EdDSA":
                continue
            kid = header.get("kid", "")
            kid_did = kid.split("#")[0]
            if normalize_did(kid_did) != normalize_did(presented):
                continue
            pub = _public_key_from_did(kid_did)
            signing_input = (entry["protected"] + "." + _b64url_encode(payload)).encode(
                "ascii"
            )
            pub.verify(_b64url_decode(entry["signature"]), signing_input)
            return True
        return False
    except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError):
        return False


def verify_agent_card(card: dict) -> dict:
    """Verify an agent card offline: every vouch token, plus the card
    signature when present.

    Returns a report:
        {
          "did": <presented identity DID>,
          "name": <card name>,
          "valid_vouches": [decoded vouch blobs that verified],
          "invalid_vouches": [tokens that failed],
          "signature_valid": True/False/None (None = unsigned, e.g. legacy card),
        }
    """
    params = _trust_params(card)
    valid, invalid = [], []
    for tok in params.get("vouches", []):
        if verify_token(tok):
            valid.append(vouch_from_token(tok))
        else:
            invalid.append(tok)
    legacy = card.get("schema") == LEGACY_CARD_SCHEMA
    return {
        "did": card_identity(card),
        "name": card.get("name"),
        "valid_vouches": valid,
        "invalid_vouches": invalid,
        "signature_valid": (
            None if legacy and "signatures" not in card else verify_card_signature(card)
        ),
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
