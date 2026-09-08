"""Ed25519 agent identity for the ATAR protocol.

An identity is an Ed25519 key pair plus a ``did:agent:`` identifier derived
from the public key. No servers, no blockchain, no cost.
"""

from dataclasses import dataclass

import base58
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


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


def did_from_public(public_key: Ed25519PublicKey) -> str:
    raw = public_key.public_bytes_raw()
    return "did:agent:" + base58.b58encode(raw).decode()


def public_key_from_did(did: str) -> Ed25519PublicKey:
    """Reconstruct the Ed25519 public key embedded in a ``did:agent:`` DID.

    Raises ValueError for malformed DIDs (wrong prefix, bad base58, wrong
    length) — callers decide whether to reject or skip.
    """
    if not isinstance(did, str) or not did.startswith("did:agent:"):
        raise ValueError(f"not a did:agent: DID: {did!r}")
    raw = base58.b58decode(did[len("did:agent:"):])
    return Ed25519PublicKey.from_public_bytes(raw)
