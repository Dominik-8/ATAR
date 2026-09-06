from atar.examples.network import build_demo_network
from atar.dashboard import render_dashboard_html, dashboard_data


def test_dashboard_data_ranks_agents():
    net = build_demo_network()
    data = dashboard_data(net, scope="intelligence")
    assert "seed_did" in data
    assert len(data["agents"]) == 5
    # agents sorted by trust descending
    trusts = [a["trust"] for a in data["agents"]]
    assert trusts == sorted(trusts, reverse=True)
    # seed has trust 1.0
    seed = next(a for a in data["agents"] if a["did"] == data["seed_did"])
    assert abs(seed["trust"] - 1.0) < 1e-9


def test_dashboard_html_uses_seed_agent_design():
    net = build_demo_network()
    html = render_dashboard_html(net, scope="intelligence")
    # seed_agent design tokens must appear
    assert "#0a0a0b" in html          # near-black bg
    assert "#39ff14" in html          # gift-green accent
    assert "Segoe UI" in html         # system font stack
    assert "Know Your Agent" in html  # title
    # every agent DID rendered
    for did in net["agents"].values():
        assert did in html
    # trust scores rendered as numbers
    assert "trust=" in html
