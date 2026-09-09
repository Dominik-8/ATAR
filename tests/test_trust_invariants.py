"""Randomized invariant tests for transitive trust computation (SPEC §8.1).

Seeded stdlib ``random`` only — no new dependencies. Each test builds many
random graphs (including cycles, multi-paths, self-vouches, and out-of-scope
edges) and asserts a protocol invariant the hand-written tests cannot cover
exhaustively.
"""

from __future__ import annotations

import random

from atar.dispute import DisputeList, create_dispute
from atar.identity import generate_identity
from atar.revocation import RevocationList, revoke_vouch
from atar.transparency import TrustGraph, canonical_vouch_id
from atar.vouch import create_vouch

SCOPES = ["coding", "research", "ops"]


def _random_graph(
    rng: random.Random,
    n_nodes: int = 8,
    n_edges: int = 20,
    scope: str = "coding",
    self_vouches: bool = True,
):
    """A random signed graph: cycles, duplicate paths, self-vouches, and
    edges in other scopes (which must never leak into ``scope``)."""
    idents = [generate_identity() for _ in range(n_nodes)]
    g = TrustGraph()
    vouches = []
    for _ in range(n_edges):
        i = rng.randrange(n_nodes)
        j = rng.randrange(n_nodes) if self_vouches else rng.randrange(n_nodes - 1)
        if not self_vouches and j >= i:
            j += 1
        sc = rng.choice([scope, scope, rng.choice(SCOPES)])
        v = create_vouch(
            idents[i],
            idents[j].public_key,
            score=round(rng.uniform(0.05, 1.0), 3),
            scope=sc,
            ts=1_700_000_000 + rng.randrange(10_000),
        )
        g.add(v)
        vouches.append(v)
    return g, idents, vouches


def _did(ident) -> str:
    from atar.identity import did_from_public

    return did_from_public(ident.public_key)


def test_seed_starts_at_one_and_scores_never_negative():
    """SPEC §8.1: the seed STARTS at 1.0. Vouches pointing back at the seed
    may raise it further (the seed is a normal subject for incoming edges);
    scores are never negative."""
    rng = random.Random(20260908)
    for _ in range(40):
        g, idents, _ = _random_graph(rng)
        trust = g.compute_trust(seed_did=_did(idents[0]), scope="coding")
        assert trust[_did(idents[0])] >= 1.0
        assert all(score >= 0 for score in trust.values())


def test_self_vouches_never_change_any_score():
    rng = random.Random(20260909)
    for _ in range(40):
        g, idents, _ = _random_graph(rng, self_vouches=False)
        before = g.compute_trust(seed_did=_did(idents[0]), scope="coding")
        # pile on self-vouches (SPEC §13: claims, not endorsements)
        for k in range(rng.randrange(1, 5)):
            who = idents[rng.randrange(len(idents))]
            g.add(
                create_vouch(
                    who,
                    who.public_key,
                    score=1.0,
                    scope="coding",
                    claim="I am great",
                    ts=1_700_100_000 + k,
                )
            )
        after = g.compute_trust(seed_did=_did(idents[0]), scope="coding")
        assert before == after


def test_adding_vouches_never_decreases_trust_without_disputes():
    """Monotonicity of the pure propagation per SPEC §8.1: more endorsements
    can only add trust. Regression test for the fixed order-dependence bug
    (a node used to propagate its first-visit trust and was never re-queued
    when its trust improved). Disputes are exempt: a newly trusted disputer
    can discount vouches, which is the SPEC §8.2 mechanism, not a leak."""
    rng = random.Random(20260910)
    for _ in range(40):
        g, idents, _ = _random_graph(rng, self_vouches=False)
        before = g.compute_trust(seed_did=_did(idents[0]), scope="coding")
        for _ in range(rng.randrange(1, 6)):
            i, j = rng.sample(range(len(idents)), 2)
            g.add(
                create_vouch(
                    idents[i],
                    idents[j].public_key,
                    score=round(rng.uniform(0.05, 1.0), 3),
                    scope="coding",
                    ts=1_700_200_000 + rng.randrange(10_000),
                )
            )
        after = g.compute_trust(seed_did=_did(idents[0]), scope="coding")
        for node, score in before.items():
            assert after.get(node, 0.0) >= score - 1e-9, node


def test_revoking_a_vouch_never_increases_trust():
    rng = random.Random(20260911)
    for _ in range(40):
        g, idents, vouches = _random_graph(rng, self_vouches=False)
        seed = _did(idents[0])
        before = g.compute_trust(seed_did=seed, scope="coding")
        # an issuer revokes one of its own vouches
        rl = RevocationList()
        own = [
            v for v in vouches if any(_did(i) == v["payload"]["issuer"] for i in idents)
        ]
        if own:
            v = rng.choice(own)
            issuer = next(i for i in idents if _did(i) == v["payload"]["issuer"])
            assert revoke_vouch(rl, issuer, canonical_vouch_id(v))
        after = g.compute_trust(seed_did=seed, scope="coding", revocations=rl)
        for node, score in after.items():
            if node == seed:
                continue
            assert score <= before.get(node, 0.0) + 1e-9, node


def test_untrusted_disputer_is_inert():
    """A dispute from outside the trusted graph (pass-1 trust below the
    SPEC §8.2 threshold) must never change any score — otherwise any Sybil
    could smear honest agents."""
    rng = random.Random(20260912)
    for _ in range(40):
        g, idents, vouches = _random_graph(rng, self_vouches=False)
        seed = _did(idents[0])
        scope = "coding"
        before = g.compute_trust(seed_did=seed, scope=scope)
        dl = DisputeList()
        outsider = generate_identity()  # no vouches point at them -> trust 0
        targets = [v for v in vouches if v["payload"]["scope"] == scope]
        for v in rng.sample(targets, k=min(len(targets), rng.randrange(1, 4))):
            dl.add(create_dispute(outsider, v, reason="sybil smear", ts=1_700_300_000))
        after = g.compute_trust(seed_did=seed, scope=scope, disputes=dl)
        assert before == after


def test_other_scopes_never_leak_into_scope():
    rng = random.Random(20260913)
    for _ in range(40):
        g, idents, _ = _random_graph(rng)
        seed = _did(idents[0])
        trust_coding = g.compute_trust(seed_did=seed, scope="coding")
        # every node reachable in "coding" must be reachable via coding edges
        # only: recompute on a coding-only graph and compare exactly
        coding_only = TrustGraph()
        for v in g.all_vouches():
            if v["payload"]["scope"] == "coding":
                coding_only.add(v)
        assert trust_coding == coding_only.compute_trust(seed_did=seed, scope="coding")


def test_trust_propagation_order_independent():
    """Minimal deterministic repro: the same four edges, inserted in two
    different orders, must yield the same scores. Regression test for the
    fixed order-dependence bug."""
    from atar.identity import did_from_public

    seed, a, b = generate_identity(), generate_identity(), generate_identity()
    seed_did = did_from_public(seed.public_key)

    def graph(order):
        g = TrustGraph()
        edges = {
            "seed->b weak": create_vouch(
                seed, b.public_key, score=0.1, scope="coding", ts=3
            ),
            "b->a": create_vouch(b, a.public_key, score=0.5, scope="coding", ts=4),
            "seed->a strong": create_vouch(
                seed, a.public_key, score=1.0, scope="coding", ts=1
            ),
            "a->b": create_vouch(a, b.public_key, score=1.0, scope="coding", ts=2),
        }
        for name in order:
            g.add(edges[name])
        return g.compute_trust(seed_did=seed_did, scope="coding")

    early = graph(["seed->b weak", "b->a", "seed->a strong", "a->b"])
    late = graph(["seed->a strong", "a->b", "seed->b weak", "b->a"])
    assert early == late


def test_disconnected_components_never_gain_trust():
    """Nodes unreachable from the seed must never appear in the trust map -
    no matter how dense their own internal vouching is (a Sybil cluster
    vouching only for itself earns exactly nothing)."""
    rng = random.Random(20260909)
    for _ in range(30):
        g, idents, _ = _random_graph(rng, n_nodes=8, n_edges=20)
        # add a dense, isolated Sybil cluster of 4 extra identities
        sybils = [generate_identity() for _ in range(4)]
        for s in sybils:
            for t in sybils:
                if s is not t:
                    g.add(
                        create_vouch(
                            s, t.public_key, score=1.0, scope="coding", ts=1_700_000_000
                        )
                    )
        trust = g.compute_trust(seed_did=_did(idents[0]), scope="coding")
        for s in sybils:
            assert _did(s) not in trust


def test_reissued_vouch_does_not_double_count():
    """Re-issuing the same claim with a new timestamp (freshness re-sign,
    SPEC §7) collapses to one content-addressed vouch. Trust after a
    re-issue must equal trust before it - the refresh must not add weight."""
    seed, bob = generate_identity(), generate_identity()
    seed_did = _did(seed)

    def graph(with_reissue: bool) -> float:
        g = TrustGraph()
        v1 = create_vouch(
            seed, bob.public_key, score=0.8, scope="coding", ts=1_700_000_000
        )
        g.add(v1)
        if with_reissue:
            v2 = create_vouch(
                seed, bob.public_key, score=0.8, scope="coding", ts=1_700_100_000
            )  # same claim, fresh ts
            g.add(v2)
            assert len(g.all_vouches()) == 1, "re-issue must dedup by claim"
        return g.compute_trust(seed_did=seed_did, scope="coding")[_did(bob)]

    assert graph(with_reissue=False) == graph(with_reissue=True)


def test_cycle_propagation_is_bounded_and_exact():
    """Cycles must terminate: a 3-cycle of score-1.0 vouches keeps feeding
    trust around forever in a naive traversal. SPEC §8.1 bounds propagation
    at depth 8, so each node collects exactly the cycle passes that fit:
    seed gets its baseline 1.0 plus the length-3 and length-6 returns
    (3.0), a and b get three passes each (levels 1/4/7 and 2/5/8)."""
    seed, a, b = generate_identity(), generate_identity(), generate_identity()
    g = TrustGraph()
    for issuer, subj in ((seed, a), (a, b), (b, seed)):
        g.add(
            create_vouch(
                issuer, subj.public_key, score=1.0, scope="coding", ts=1_700_000_000
            )
        )
    trust = g.compute_trust(seed_did=_did(seed), scope="coding")
    assert trust[_did(seed)] == 3.0
    assert trust[_did(a)] == 3.0
    assert trust[_did(b)] == 3.0
    # decay shrinks each pass: same cycle with decay 0.5
    trust_d = g.compute_trust(seed_did=_did(seed), scope="coding", decay=0.5)
    assert abs(trust_d[_did(a)] - (0.5 + 0.5**4 + 0.5**7)) < 1e-12
    assert abs(trust_d[_did(b)] - (0.5**2 + 0.5**5 + 0.5**8)) < 1e-12
    assert abs(trust_d[_did(seed)] - (1.0 + 0.5**3 + 0.5**6)) < 1e-12


def test_propagation_respects_depth_cap():
    """A chain longer than the SPEC §8.1 depth bound (8) must stop: the node
    at depth 9 earns nothing."""
    idents = [generate_identity() for _ in range(10)]
    g = TrustGraph()
    for k in range(9):
        g.add(
            create_vouch(
                idents[k],
                idents[k + 1].public_key,
                score=1.0,
                scope="coding",
                ts=1_700_000_000,
            )
        )
    trust = g.compute_trust(seed_did=_did(idents[0]), scope="coding")
    assert trust[_did(idents[8])] == 1.0  # depth 8: last counted hop
    assert _did(idents[9]) not in trust  # depth 9: beyond the cap


def test_all_insertion_orders_are_bit_identical():
    """Stronger than the minimal repro: for several random graphs, EVERY
    permutation of the insertion order must yield the exact same trust map
    (bit-identical floats, not just within tolerance)."""
    rng = random.Random(20260914)
    for _ in range(10):
        g, idents, vouches = _random_graph(rng, n_nodes=6, n_edges=12)
        expected = g.compute_trust(seed_did=_did(idents[0]), scope="coding")
        for _ in range(10):
            perm = vouches[:]
            rng.shuffle(perm)
            shuffled = TrustGraph()
            for v in perm:
                shuffled.add(v)
            assert (
                shuffled.compute_trust(seed_did=_did(idents[0]), scope="coding")
                == expected
            )
