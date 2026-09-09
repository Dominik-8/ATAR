"""ATAR Transparency Log — a decentralized, serverless trust graph.

Vouches are content-addressed (deterministic ID from their bytes) so they can
be shared over any gossip/mirror layer without an operator. Each agent keeps a
local copy of vouches it has seen and computes *transitive trust* from a seed
of trusted roots (e.g. its own identity, or a personhood root).

This is the reputation layer of ATAR: no central server, no ledger, no cost.
Trust emerges from who vouches for whom — exactly the Web-of-Trust model.

Honest constraint: free + serverless identity means Sybil agents can mint
themselves. Transitive trust only flows through *valid* vouches (cryptographically
verified), so a Sybil still needs real agents to vouch for it to gain trust.
"""

from __future__ import annotations

import hashlib
import json

from .vouch import verify_vouch


def canonical_vouch_id(vouch: dict) -> str:
    """Content-addressed ID: sha256 of the canonical vouch bytes (hex).

    Excludes ``ts`` and ``signature`` — a vouch is identified by its *claim*
    (issuer -> subject, scope, score, claim), not by when it was made or how
    it was signed. This makes dedup work across re-issues / re-bootstrap:
    two vouches with the same claim but different timestamps collapse to one.
    """
    payload = dict(vouch["payload"])
    payload.pop("ts", None)
    body = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return "vouch:" + hashlib.sha256(body).hexdigest()


class TrustGraph:
    """A local store of vouches + transitive trust computation."""

    def __init__(self) -> None:
        # vouch_id -> vouch blob (only valid vouches are stored)
        self._vouches: dict[str, dict] = {}

    def add(self, vouch: dict) -> bool:
        """Add a vouch if its signature verifies. Returns True if stored."""
        if not verify_vouch(vouch):
            return False
        vid = canonical_vouch_id(vouch)
        self._vouches[vid] = vouch
        return True

    def all_vouches(self) -> list[dict]:
        return list(self._vouches.values())

    @staticmethod
    def _alias(did: str) -> str:
        """Canonical alias of a DID (SPEC §2): legacy did:agent: maps to the
        did:key of the same key, so pre-realignment vouches keep carrying
        trust to the same identity. Unparseable DIDs pass through unchanged
        (they can never verify, so they never enter the graph anyway)."""
        try:
            from .identity import normalize_did

            return normalize_did(did)
        except ValueError:
            return did

    def compute_trust(
        self,
        *,
        seed_did: str,
        scope: str,
        decay: float = 1.0,
        disputes=None,
        revocations=None,
        ttl: int | None = None,
        now: int | None = None,
    ) -> dict[str, float]:
        """Compute transitive trust scores from a trusted seed DID.

        Score of a node = sum over incoming valid vouches of
        (issuer_trust * vouch_score), only counting edges within ``scope``.
        Seed node starts at 1.0. Decay < 1.0 weakens longer paths.

        Propagation semantics (SPEC §8.1): the score is a fixed point over
        *all* paths up to the depth bound, not a first-visit traversal —
        level ``k`` accumulates the summed contribution of every length-``k``
        path from the seed. The result therefore depends only on the set of
        valid edges: it is independent of vouch insertion order, and adding
        a vouch can never lower a score (it only adds non-negative terms).
        Contributions are summed in a canonical (sorted) edge order so the
        floating-point result is bit-identical for identical edge sets.

        Revocation + freshness (SPEC §8.1): only *valid, unrevoked,
        unexpired* vouches carry trust. When ``revocations`` (a
        RevocationList) is given, issuer-revoked vouches are excluded; when
        ``ttl`` (seconds, see freshness.VOUCH_TTL_DEFAULT) is given, expired
        vouches are excluded. Both checks mirror ``freshness.trust_valid``.

        Disputes (SPEC §8.2): when ``disputes`` (a DisputeList) is given, the
        computation runs in two passes. Pass 1 ignores disputes and
        establishes who is trusted. Pass 2 excludes vouches that carry a
        valid dispute from a disputer whose pass-1 trust is at or above
        DISPUTE_TRUST_THRESHOLD (0.5) — a warning counts only when it comes
        from inside the trusted graph, so Sybil disputers cannot zero out
        honest vouches. A dispute never removes the vouch from the store; it
        only discounts its contribution here.
        """
        excluded: set[str] = set()
        if revocations is not None or ttl is not None:
            from .freshness import is_fresh

            for vid, v in self._vouches.items():
                if (revocations is not None and revocations.is_revoked_for(v)) or (
                    ttl is not None and not is_fresh(v, ttl=ttl, now=now)
                ):
                    excluded.add(vid)

        discounted: set[str] = set()
        if disputes is not None:
            from .dispute import DISPUTE_TRUST_THRESHOLD

            baseline = self.compute_trust(
                seed_did=seed_did,
                scope=scope,
                decay=decay,
                revocations=revocations,
                ttl=ttl,
                now=now,
            )
            for v in self._vouches.values():
                if v["payload"].get("scope") != scope:
                    continue
                if canonical_vouch_id(v) in excluded:
                    continue
                for e in disputes.disputes_for(v):
                    disputer = self._alias(e["disputed_by"])
                    if baseline.get(disputer, 0.0) >= DISPUTE_TRUST_THRESHOLD:
                        discounted.add(canonical_vouch_id(v))
                        break

        # build adjacency: issuer_did -> list of (subject_did, score)
        # (outgoing edges: who does this issuer vouch for)
        edges: dict[str, list[tuple[str, float]]] = {}
        for v in self._vouches.values():
            p = v["payload"]
            if p.get("scope") != scope:
                continue
            vid = canonical_vouch_id(v)
            if vid in excluded or vid in discounted:
                continue
            issuer = self._alias(p["issuer"])
            subject = self._alias(p["subject"])
            if issuer == subject:
                # self-vouches are claims, not endorsements (SPEC §13): they
                # must not add transitive trust — otherwise a self-endorsement
                # would inflate the issuer's own score.
                continue
            edges.setdefault(issuer, []).append((subject, float(p["score"])))

        seed_did = self._alias(seed_did)
        trust: dict[str, float] = {seed_did: 1.0}
        # Bounded fixed-point propagation (SPEC §8.1). ``level`` holds the
        # summed contribution of all paths of exactly the current length;
        # each step extends every path by one edge with one more decay
        # factor. Bounded by depth 8 and the 1e-9 contribution floor.
        # Iterating edges in canonical (sorted) order keeps floating-point
        # summation order — and thus the exact scores — independent of the
        # order vouches were inserted into the store.
        canonical = {issuer: sorted(out) for issuer, out in sorted(edges.items())}
        level: dict[str, float] = {seed_did: 1.0}
        for _depth in range(1, 9):
            nxt: dict[str, float] = {}
            for issuer in sorted(level):
                issuer_contrib = level[issuer]
                for subj, v_score in canonical.get(issuer, []):
                    contrib = issuer_contrib * v_score * decay
                    if contrib <= 0:
                        continue
                    nxt[subj] = nxt.get(subj, 0.0) + contrib
            if not nxt or max(nxt.values()) < 1e-9:
                break
            for subj, contrib in nxt.items():
                trust[subj] = trust.get(subj, 0.0) + contrib
            level = nxt
        return trust


def add_vouch(graph: TrustGraph, vouch: dict) -> bool:
    return graph.add(vouch)


def graph_from_vouches(vouches: list[dict]) -> TrustGraph:
    g = TrustGraph()
    for v in vouches:
        g.add(v)
    return g
