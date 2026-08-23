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
