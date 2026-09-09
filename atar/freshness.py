"""Freshness — time-bounded trust (the missing half of revocation).

Revocation (Phase 16) lets a trust edge be *actively* killed. Freshness makes
trust *expire* if it is not periodically renewed — like TLS certs. Without it,
a vouch from 3 years ago is still "valid" just because nobody objected. With a
TTL, agents must re-vouch on a cadence, so the graph stays alive and stale
trust decays instead of accumulating forever.

Combined check (trust_valid):
    valid signature  AND  not revoked  AND  not expired (ts within TTL)
"""

from __future__ import annotations

import time

from .revocation import RevocationList
from .vouch import verify_vouch

# Default trust lifetime: 180 days. Re-vouch before it lapses.
VOUCH_TTL_DEFAULT = 180 * 24 * 3600


def is_fresh(
    vouch: dict, *, ttl: int = VOUCH_TTL_DEFAULT, now: int | None = None
) -> bool:
    """True if the vouch's timestamp is within `ttl` seconds of `now`."""
    now = now if now is not None else int(time.time())
    ts = vouch.get("payload", {}).get("ts")
    if not isinstance(ts, int):
        return False
    return (now - ts) <= ttl


def trust_valid(
    vouch: dict,
    *,
    revocation_list: RevocationList | None = None,
    ttl: int = VOUCH_TTL_DEFAULT,
    now: int | None = None,
) -> bool:
    """Full trust check: valid signature + not revoked + not expired."""
    if not verify_vouch(vouch):
        return False
    if revocation_list is not None and revocation_list.is_revoked_for(vouch):
        return False
    return is_fresh(vouch, ttl=ttl, now=now)
