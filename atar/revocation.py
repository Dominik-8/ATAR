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
from .identity import Identity, did_from_public, public_key_from_did
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


def verify_revocation_entry(entry: dict, verify_key=None) -> bool:
    """True iff the entry's signature verifies against the ``revoked_by`` key.

    When ``verify_key`` is not given, the public key is reconstructed from the
    ``revoked_by`` DID (a ``did:agent:`` embeds the raw Ed25519 key), so an
    entry can always be checked standalone — no trusted source needed.
    """
    from base64 import b64decode
    try:
        vid = entry["vid"]
        revoked_by = entry["revoked_by"]
        ts = entry["ts"]
        signature = entry["signature"]
        key = verify_key if verify_key is not None else public_key_from_did(revoked_by)
        msg = f"{vid}|{revoked_by}|{ts}".encode("utf-8")
        key.verify(b64decode(signature), msg)
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        # InvalidSignature: bad signature. ValueError: malformed DID/base64/
        # key bytes. KeyError/TypeError: missing or wrongly-typed fields.
        return False


class RevocationList:
    """A signed, deduplicated list of revoked vouch IDs (local/P2P)."""

    def __init__(self) -> None:
        # vid -> entry dict
        self.entries: dict[str, dict] = {}

    def add(self, revoked_by: str, vid: str, ts: int, signature: str,
            verify_key=None, vouch: dict | None = None) -> bool:
        """Add a revocation entry. The signature is ALWAYS verified against
        the ``revoked_by`` key (reconstructed from the DID when ``verify_key``
        is not given) — an unverifiable entry never enters the list.

        If ``vouch`` (the revoked vouch, when known) is given, ``revoked_by``
        must equal the vouch's issuer (SPEC §6); otherwise the entry is
        rejected at intake instead of merely ignored at evaluation.
        """
        if vid in self.entries:
            return False
        if vouch is not None and vouch.get("payload", {}).get("issuer") != revoked_by:
            return False
        entry = {
            "vid": vid,
            "revoked_by": revoked_by,
            "ts": ts,
            "signature": signature,
        }
        if not verify_revocation_entry(entry, verify_key=verify_key):
            return False
        self.entries[vid] = entry
        return True

    def is_revoked(self, vid: str) -> bool:
        return vid in self.entries

    def is_revoked_for(self, vouch: dict) -> bool:
        """True iff a revocation exists for this vouch AND was made by the
        vouch's issuer (SPEC §6). An entry signed by anyone else verifies
        fine against its own ``revoked_by`` key but never applies here."""
        entry = self.entries.get(revoke_payload_id(vouch))
        return entry is not None and entry.get("revoked_by") == vouch.get("payload", {}).get("issuer")

    def all(self) -> list[dict]:
        return list(self.entries.values())

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"revocations": self.all()}, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "RevocationList":
        """Load from disk, verifying every entry (SPEC §6): entries whose
        signature does not verify against ``revoked_by`` are dropped, so a
        forged or tampered revocations.json cannot kill vouches."""
        r = cls()
        if not os.path.exists(path):
            return r
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            return r  # corrupt file — start clean rather than crash
        for e in data.get("revocations", []):
            try:
                r.add(e["revoked_by"], e["vid"], e["ts"], e["signature"])
            except (KeyError, TypeError):
                continue  # malformed entry — dropped
        return r


def is_revoked(vid: str, rlist: RevocationList) -> bool:
    return rlist.is_revoked(vid)


def verify_vouch_revocation_aware(vouch: dict, rlist: RevocationList) -> bool:
    """Like verify_vouch, but False if the vouch was revoked by its issuer."""
    if not verify_vouch(vouch):
        return False
    return not rlist.is_revoked_for(vouch)
