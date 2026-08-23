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

    def compute_trust(self, *, seed_did: str, scope: str, decay: float = 1.0) -> dict[str, float]:
        """Compute transitive trust scores from a trusted seed DID.

        Score of a node = sum over incoming valid vouches of
        (issuer_trust * vouch_score), only counting edges within ``scope``.
        Seed node starts at 1.0. Decay < 1.0 weakens longer paths.
        """
        # build adjacency: issuer_did -> list of (subject_did, score)
        # (outgoing edges: who does this issuer vouch for)
        edges: dict[str, list[tuple[str, float]]] = {}
        for v in self._vouches.values():
            p = v["payload"]
            if p.get("scope") != scope:
                continue
            issuer = p["issuer"]
            edges.setdefault(issuer, []).append((p["subject"], float(p["score"])))

        trust: dict[str, float] = {seed_did: 1.0}
        # bounded propagation (BFS by trust contribution)
        frontier = [seed_did]
        visited = {seed_did}
        depth = 0
        while frontier:
            depth += 1
            factor = decay ** depth
            if factor < 1e-9:
                break
            nxt = []
            for issuer in frontier:
                issuer_score = trust[issuer]
                for subj, v_score in edges.get(issuer, []):
                    contrib = issuer_score * v_score * factor
                    if contrib <= 0:
                        continue
                    new_score = trust.get(subj, 0.0) + contrib
                    if new_score > trust.get(subj, 0.0) or subj not in visited:
                        trust[subj] = max(trust.get(subj, 0.0), new_score)
                        if subj not in visited:
                            visited.add(subj)
                            nxt.append(subj)
                    elif contrib > 0:
                        # allow re-propagation if it improves, but cap depth
                        if depth <= 8:
                            nxt.append(subj)
            frontier = nxt
        return trust


def add_vouch(graph: TrustGraph, vouch: dict) -> bool:
    return graph.add(vouch)


def graph_from_vouches(vouches: list[dict]) -> TrustGraph:
    g = TrustGraph()
    for v in vouches:
        g.add(v)
    return g
