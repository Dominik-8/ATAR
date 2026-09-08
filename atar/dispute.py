"""Signed disputes — negative signals next to positive vouches (Stage C3).

A vouch says "I trust this agent for this scope." Until now the protocol had
no way to say the opposite about someone *else's* vouch: revocation is
issuer-only (SPEC §6), so a third party that observes fraud, drift, or a
broken promise had no voice. A **dispute** is that voice: a signed statement
by any agent, against a foreign vouch, carrying a reason.

A dispute never *invalidates* a vouch — only the issuer's revocation does
that (§6). A dispute is an advisory negative signal: verifiers surface it,
and transitive trust computation discounts a vouch when the disputer is
itself trusted (§8.2). Disputes are content-addressed by their own bytes,
signature-verified at every intake path, and gossip-synced like vouches and
revocations — so a warning made by one peer reaches all.

Wire format (one entry):
    {
      "vid": "<canonical vouch id>",
      "disputed_by": "did:key:... (or legacy did:agent:)",
      "reason": "<free text>",
      "ts": 1690000000,
      "signature": "<base64 Ed25519 over \"vid|disputed_by|reason|ts\">"
    }
"""

from __future__ import annotations

import json
import os
import time
from base64 import b64decode, b64encode

from cryptography.exceptions import InvalidSignature

from .identity import Identity, did_from_public, public_key_from_did, normalize_did
from .transparency import canonical_vouch_id

# Disputer trust at or above this level makes a dispute "count" in trust
# computation (SPEC §8.2). Below it, the dispute is stored and shown but
# does not move scores — otherwise any Sybil could zero out honest vouches.
DISPUTE_TRUST_THRESHOLD = 0.5


def _same_did(a: str, b: str) -> bool:
    if a == b:
        return True
    try:
        return normalize_did(a) == normalize_did(b)
    except ValueError:
        return False


def _signing_message(vid: str, disputed_by: str, reason: str, ts: int) -> bytes:
    return f"{vid}|{disputed_by}|{reason}|{ts}".encode("utf-8")


def create_dispute(disputer: Identity, vouch: dict, *, reason: str,
                   ts: int | None = None) -> dict:
    """Create a signed dispute against ``vouch``. The disputer MUST NOT be the
    vouch's issuer — the issuer's negative signal is revocation (§6)."""
    issuer = vouch.get("payload", {}).get("issuer")
    disputed_by = did_from_public(disputer.public_key)
    if issuer is not None and _same_did(issuer, disputed_by):
        raise ValueError("issuers revoke (§6); disputes are for foreign vouches")
    ts = int(ts if ts is not None else time.time())
    vid = canonical_vouch_id(vouch)
    sig = disputer.sign(_signing_message(vid, disputed_by, reason, ts))
    return {
        "vid": vid,
        "disputed_by": disputed_by,
        "reason": reason,
        "ts": ts,
        "signature": b64encode(sig).decode("ascii"),
    }


def verify_dispute_entry(entry: dict) -> bool:
    """True iff the entry's signature verifies against the ``disputed_by``
    key (reconstructed from the DID — both spellings embed the raw key)."""
    try:
        vid = entry["vid"]
        disputed_by = entry["disputed_by"]
        reason = entry["reason"]
        ts = entry["ts"]
        key = public_key_from_did(disputed_by)
        key.verify(b64decode(entry["signature"]),
                   _signing_message(vid, disputed_by, reason, ts))
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError):
        return False


def _entry_id(entry: dict) -> str:
    """Content address for dedup: the signed statement, excluding ts+signature."""
    return f"{entry['vid']}|{entry['disputed_by']}|{entry['reason']}"


class DisputeList:
    """A signed, deduplicated list of disputes (local/P2P)."""

    def __init__(self) -> None:
        self.entries: dict[str, dict] = {}

    def add(self, entry: dict, *, vouch: dict | None = None) -> bool:
        """Add a dispute. The signature is ALWAYS verified; when the disputed
        vouch is known, a dispute by the vouch's own issuer is rejected at
        intake (issuers revoke instead)."""
        try:
            eid = _entry_id(entry)
        except (KeyError, TypeError):
            return False
        if eid in self.entries:
            return False
        if vouch is not None and _same_did(
                vouch.get("payload", {}).get("issuer"), entry.get("disputed_by")):
            return False
        if not verify_dispute_entry(entry):
            return False
        self.entries[eid] = entry
        return True

    def disputes_for(self, vouch: dict) -> list[dict]:
        vid = canonical_vouch_id(vouch)
        return [e for e in self.entries.values() if e["vid"] == vid]

    def is_disputed(self, vouch: dict) -> bool:
        return bool(self.disputes_for(vouch))

    def all(self) -> list[dict]:
        return list(self.entries.values())

    def save(self, path: str) -> None:
        with open(path, "w", encoding="utf-8") as f:
            json.dump({"disputes": self.all()}, f, indent=2)

    @classmethod
    def load(cls, path: str) -> "DisputeList":
        """Load from disk, verifying every entry — a forged or tampered
        disputes.json cannot smear honest vouches."""
        d = cls()
        if not os.path.exists(path):
            return d
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except json.JSONDecodeError:
            return d
        for e in data.get("disputes", []):
            d.add(e)
        return d
