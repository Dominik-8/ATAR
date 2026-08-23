"""Revocation — the missing security primitive for a trust protocol.

A signed vouch is valid forever unless it can be *revoked*. Without revocation,
a leaked or malicious agent key would let an attacker keep deriving trust
indefinitely. This module provides a local, decentralized revocation list:

  * Each revocation is signed by the vouch's issuer (or a designated revoker).
  * ``verify_vouch_revocation_aware`` rejects a vouch whose ID is on the list.
  * The list is content-addressed + deduplicated, so it gossip-ready (sync it
    between agents like vouches).

No server, no cost. Modeled on CRL/OCSP but local and P2P.

Wire format (one entry):
    {
      "vid": "<canonical vouch id>",
      "revoked_by": "<did:agent: of issuer/revoker>",
      "ts": 1690000000,
      "signature": "<base64 Ed25519 over (vid|revoked_by|ts)>"
    }
"""

from __future__ import annotations

import json
import os
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.exceptions import InvalidSignature
from .identity import Identity, did_from_public
from .transparency import canonical_vouch_id
from .vouch import verify_vouch


def revoke_payload_id(vouch: dict) -> str:
    """Canonical ID of the vouch to revoke (same as used by transparency/store)."""
    return canonical_vouch_id(vouch)


def _sign_revocation(issuer: Identity, vid: str, revoked_by: str, ts: int) -> str:
    from base64 import b64encode
    msg = f"{vid}|{revoked_by}|{ts}".encode("utf-8")
    sig = issuer.private_key.sign(msg)
    return b64encode(sig).decode("ascii")


def revoke_vouch(rlist: "RevocationList", issuer: Identity, vid: str) -> bool:
    """Add a revocation signed by the vouch's issuer. Returns False if dup/invalid."""
    revoked_by = did_from_public(issuer.public_key)
    ts = int(time.time())
    sig = _sign_revocation(issuer, vid, revoked_by, ts)
    return rlist.add(revoked_by, vid, ts, sig, verify_key=issuer.public_key)


class RevocationList:
    """A signed, deduplicated list of revoked vouch IDs (local/P2P)."""

    def __init__(self) -> None:
        # vid -> entry dict
        self.entries: dict[str, dict] = {}

    def add(self, revoked_by: str, vid: str, ts: int, signature: str,
            verify_key=None) -> bool:
        """Add a revocation entry. If verify_key given, the signature is checked."""
        if vid in self.entries:
            return False
        if verify_key is not None:
            from base64 import b64decode
            msg = f"{vid}|{revoked_by}|{ts}".encode("utf-8")
            try:
                verify_key.verify(b64decode(signature), msg)
            except (InvalidSignature, ValueError, KeyError):
                # InvalidSignature: bad signature. ValueError/KeyError: malformed.
                return False
        self.entries[vid] = {
            "vid": vid,
            "revoked_by": revoked_by,
            "ts": ts,
            "signature": signature,
        }
        return True

    def is_revoked(self, vid: str) -> bool:
        return vid in self.entries

    def all(self) -> list[dict]:
        return list(self.entries.values())

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"revocations": self.all()}, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "RevocationList":
        r = cls()
        if not os.path.exists(path):
            return r
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for e in data.get("revocations", []):
            r.entries[e["vid"]] = e
        return r


def is_revoked(vid: str, rlist: RevocationList) -> bool:
    return rlist.is_revoked(vid)


def verify_vouch_revocation_aware(vouch: dict, rlist: RevocationList) -> bool:
    """Like verify_vouch, but False if the vouch ID is on the revocation list."""
    if not verify_vouch(vouch):
        return False
    vid = revoke_payload_id(vouch)
    return not rlist.is_revoked(vid)
