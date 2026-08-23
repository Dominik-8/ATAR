from atar.identity import generate_identity, did_from_public
from atar.vouch import create_vouch
from atar.transparency import TrustGraph, canonical_vouch_id, add_vouch, graph_from_vouches


def _make_vouch(issuer, subject_pub, score, scope):
    return create_vouch(issuer, subject_pub, score=score, scope=scope)


def test_canonical_vouch_id_is_content_addressed():
    a = generate_identity()
    b = generate_identity()
    v = _make_vouch(a, b.public_key, 0.9, "coding")
    vid = canonical_vouch_id(v)
    assert isinstance(vid, str) and len(vid) > 0
    # same content -> same id (deterministic)
    assert canonical_vouch_id(v) == vid
    # different content -> different id
    v2 = _make_vouch(a, b.public_key, 0.5, "coding")
    assert canonical_vouch_id(v2) != vid


def test_graph_computes_transitive_trust():
    # alice (trust root, weight 1.0) vouches bob 0.9, bob vouches carol 0.8
    alice = generate_identity()
    bob = generate_identity()
    carol = generate_identity()
    v_ab = _make_vouch(alice, bob.public_key, 0.9, "coding")
    v_bc = _make_vouch(bob, carol.public_key, 0.8, "coding")
    g = graph_from_vouches([v_ab, v_bc])
    # alice is the seed of trust
    trust = g.compute_trust(seed_did=did_from_public(alice.public_key), scope="coding")
    # bob should be trusted transitively via alice
    assert did_from_public(bob.public_key) in trust
    assert trust[did_from_public(bob.public_key)] > 0
    # carol trusted transitively two hops
    assert did_from_public(carol.public_key) in trust
    assert trust[did_from_public(carol.public_key)] > 0
    # transitive score should be product (0.9 * 0.8 = 0.72)
    assert abs(trust[did_from_public(carol.public_key)] - 0.72) < 1e-6


def test_graph_ignores_unrelated_agents():
    alice = generate_identity()
    bob = generate_identity()
    carol = generate_identity()
    dave = generate_identity()
    v_ab = _make_vouch(alice, bob.public_key, 0.9, "coding")
    g = graph_from_vouches([v_ab])
    trust = g.compute_trust(seed_did=did_from_public(alice.public_key), scope="coding")
    # dave and carol are not in the graph at all
    assert did_from_public(carol.public_key) not in trust
    assert did_from_public(dave.public_key) not in trust


def test_invalid_vouch_excluded_from_graph():
    alice = generate_identity()
    bob = generate_identity()
    carol = generate_identity()
    v_ab = _make_vouch(alice, bob.public_key, 0.9, "coding")
    # a forged vouch claiming alice vouched for carol (wrong signature)
    forged = _make_vouch(bob, carol.public_key, 1.0, "coding")  # signed by bob, not alice
    forged["payload"]["issuer"] = did_from_public(alice.public_key)
    g = graph_from_vouches([v_ab, forged])
    trust = g.compute_trust(seed_did=did_from_public(alice.public_key), scope="coding")
    # carol must NOT be trusted because the vouch for her is invalid
    assert did_from_public(carol.public_key) not in trust
