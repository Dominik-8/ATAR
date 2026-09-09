"""Ed25519 agent identity for the ATAR protocol.

An identity is an Ed25519 key pair plus a ``did:key`` identifier derived
solely from the public key (W3C ``did:key`` method: multicodec
``ed25519-pub`` + multibase base58btc). No registration, no servers, no
blockchain, no cost.

Legacy ``did:agent:`` identifiers (ATAR protocol versions before the 2026-09
standards realignment) remain fully decodable and alias to the ``did:key`` of
the *same* Ed25519 key: both encodings embed the identical 32 raw public-key
bytes, so old vouches, revocations, and rotation statements stay verifiable
with no data loss and no hard cut.
"""

from dataclasses import dataclass

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)

# multicodec code for ed25519-pub (0xed), varint-encoded -> b"\xed\x01"
ED25519_MULTICODEC_PREFIX = b"\xed\x01"

DID_KEY_PREFIX = "did:key:"
LEGACY_DID_AGENT_PREFIX = "did:agent:"


@dataclass
class Identity:
    private_key: Ed25519PrivateKey
    public_key: Ed25519PublicKey

    def sign(self, msg: bytes) -> bytes:
        return self.private_key.sign(msg)


def generate_identity() -> Identity:
    private_key = Ed25519PrivateKey.generate()
    public_key = private_key.public_key()
    return Identity(private_key=private_key, public_key=public_key)


def did_key_from_public(public_key: Ed25519PublicKey) -> str:
    """Derive the W3C ``did:key`` identifier for an Ed25519 public key.

    Layout: ``did:key:`` + multibase base58btc (``z``) of
    multicodec(``ed25519-pub`` = 0xed 0x01) || raw 32-byte public key.
    """
    raw = public_key.public_bytes_raw()
    return (
        DID_KEY_PREFIX
        + "z"
        + base58.b58encode(ED25519_MULTICODEC_PREFIX + raw).decode()
    )


def legacy_did_agent_from_public(public_key: Ed25519PublicKey) -> str:
    """The pre-realignment ``did:agent:`` identifier (base58 of raw key only).

    Still produced only for migration tooling; new identities use ``did:key``.
    """
    raw = public_key.public_bytes_raw()
    return LEGACY_DID_AGENT_PREFIX + base58.b58encode(raw).decode()


def did_from_public(public_key: Ed25519PublicKey) -> str:
    """Canonical DID for a public key — the ``did:key`` form (SPEC §2)."""
    return did_key_from_public(public_key)


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """Reconstruct the Ed25519 public key embedded in an ATAR-supported DID.

    Accepts ``did:key:z…`` (multibase base58btc, multicodec ed25519-pub) and
    legacy ``did:agent:…`` (raw base58). Raises ValueError for malformed DIDs
    (unknown prefix/method, wrong multibase, wrong multicodec, bad base58,
    wrong key length) — callers decide whether to reject or skip.
    """
    if not isinstance(did, str):
        raise ValueError(f"not a DID string: {did!r}")
    if did.startswith(DID_KEY_PREFIX):
        multibase_value = did[len(DID_KEY_PREFIX) :]
        if not multibase_value.startswith("z"):
            raise ValueError(
                f"did:key with unsupported multibase (need 'z'/base58btc): {did!r}"
            )
        data = base58.b58decode(multibase_value[1:])
        if not data.startswith(ED25519_MULTICODEC_PREFIX):
            raise ValueError(
                f"did:key with unsupported multicodec (need ed25519-pub): {did!r}"
            )
        raw = data[len(ED25519_MULTICODEC_PREFIX) :]
    elif did.startswith(LEGACY_DID_AGENT_PREFIX):
        raw = base58.b58decode(did[len(LEGACY_DID_AGENT_PREFIX) :])
    else:
        raise ValueError(
            f"unsupported DID method (need did:key or legacy did:agent): {did!r}"
        )
    if len(raw) != 32:
        raise ValueError(
            f"DID embeds a non-Ed25519 key length ({len(raw)} bytes): {did!r}"
        )
    return Ed25519PublicKey.from_public_bytes(raw)


def is_supported_did(did: str) -> bool:
    """True iff ``did`` decodes to an Ed25519 key under a supported method."""
    try:
        public_key_from_did(did)
        return True
    except ValueError:
        return False


def normalize_did(did: str) -> str:
    """Canonical alias of any supported DID: its ``did:key`` form.

    A legacy ``did:agent:`` DID and the ``did:key`` DID of the same key
    normalize to the same string, so trust-graph, revocation, and store
    comparisons treat them as one identity.
    """
    return did_key_from_public(public_key_from_did(did))


def did_aliases(did: str) -> tuple[str, str]:
    """Both spellings of one key: (canonical ``did:key``, legacy ``did:agent:``)."""
    pub = public_key_from_did(did)
    return did_key_from_public(pub), legacy_did_agent_from_public(pub)
