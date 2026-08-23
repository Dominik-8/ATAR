from atar.identity import generate_identity, did_from_public
from atar.vouch import create_vouch
from atar.transparency import graph_from_vouches, TrustGraph
from atar.examples.network import build_demo_network, demo_trust_report


def test_demo_network_transitive_trust():
    net = build_demo_network()
    # net has 4 agents + cross vouches
    assert len(net["agents"]) == 4
    # graph should compute transitive trust from the seed (seed_agent root)
    g = graph_from_vouches(net["vouches"])
    seed = net["seed_did"]
    trust = g.compute_trust(seed_did=seed, scope="intelligence")
    # all 4 agents reachable through the web of trust
    assert len(trust) == 4
    # every non-seed agent has positive trust
    for did in net["agents"].values():
        assert trust.get(did, 0.0) > 0.0


def test_demo_report_runs_and_ranks():
    net = build_demo_network()
    report = demo_trust_report(net, scope="intelligence")
    assert "trust ranking" in report
    # seed appears first (highest trust = 1.0)
    lines = report.splitlines()
    assert any("1.000" in ln and "(seed)" in ln for ln in lines)
