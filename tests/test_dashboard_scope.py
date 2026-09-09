import os

from atar.agent_bootstrap import AgentRegistry, seed_trust_root
from atar.dashboard import (
    dashboard_data,
    render_multi_scope_html,
)


def _build_multi_scope(home):
    os.makedirs(home, exist_ok=True)
    os.environ["ATAR_HOME"] = home
    reg = AgentRegistry()
    seed_trust_root("seed_agent")
    reg = AgentRegistry()
    reg.register("research")
    reg.register("market")
    # research trusted in BOTH scopes, market only in intelligence
    reg.vouch("seed_agent", "research", score=0.9, scope="intelligence")
    reg.vouch("seed_agent", "research", score=0.8, scope="coding")
    reg.vouch("seed_agent", "market", score=0.8, scope="intelligence")
    # market has NO coding vouch -> unreachable in coding scope
    return reg


def test_dashboard_filters_by_scope(tmp_path):
    reg = _build_multi_scope(str(tmp_path))
    # intelligence: both research + market reachable
    net_i = reg.build_network(scope="intelligence")
    data_i = dashboard_data(net_i, scope="intelligence")
    names_i = {a["name"] for a in data_i["agents"]}
    assert "research" in names_i and "market" in names_i
    # coding: only research (market has no coding vouch)
    net_c = reg.build_network(scope="coding")
    data_c = dashboard_data(net_c, scope="coding")
    names_c = {a["name"] for a in data_c["agents"]}
    assert "research" in names_c
    assert "market" not in names_c  # no coding vouch -> not reachable


def test_multi_scope_html_has_both_sections(tmp_path):
    reg = _build_multi_scope(str(tmp_path))
    html = render_multi_scope_html(
        reg.build_network(scope="intelligence"), scopes=["intelligence", "coding"]
    )
    assert "intelligence" in html
    assert "coding" in html
    assert "scope-sec" in html  # sections rendered
