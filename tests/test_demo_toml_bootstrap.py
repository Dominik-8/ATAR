"""Verify the demo network config actually bootstraps a real trust graph.

The demo.toml exists to SHOW how a multi-agent trust graph looks. If it
doesn't bootstrap cleanly (or produces a broken graph), it's theater — the
exact thing we removed from agents.toml. This test proves demo.toml works.
"""

import os

from click.testing import CliRunner

from atar.cli import cli


_CFG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "demo.toml"
)


def test_demo_toml_bootstraps_multi_agent_graph(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    r = runner.invoke(cli, ["bootstrap", "--config", _CFG])
    assert r.exit_code == 0, r.output

    # 5 agents seeded, edges vouched
    from atar.agent_bootstrap import AgentRegistry

    reg = AgentRegistry()
    names = set(reg._agents.keys()) - {"_seed"}
    assert {
        "seed_agent",
        "reporting_agent",
        "research",
        "market",
        "founder_intel",
    } <= names, f"missing agents: {names}"

    from atar.store import VouchStore
    from atar.cli import _home

    store = VouchStore(os.path.join(_home(), "vouches.json"))
    assert len(store.all()) >= 5, "demo should produce multiple vouches"

    # verify passes on the demo graph (audit the store)
    rv = runner.invoke(cli, ["audit"])
    assert rv.exit_code == 0, rv.output

    # dashboard renders without crashing
    rd = runner.invoke(cli, ["dashboard", "--out", str(tmp_path / "d.html")])
    assert rd.exit_code == 0, rd.output
    html = open(tmp_path / "d.html", encoding="utf-8").read()
    for n in ("seed_agent", "research", "market", "founder_intel", "reporting_agent"):
        assert n in html, f"agent {n} missing from dashboard"
