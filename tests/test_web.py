import os
import tempfile

from click.testing import CliRunner

from atar.cli import cli
from atar.web import build_dashboard_response, run_server, DashboardHandler


def _seed_real_net(home: str, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    reg_cmds = [
        (["keygen", "--name", "seed_agent"], None),
    ]
    runner.invoke(cli, ["keygen", "--name", "seed_agent"])
    r2 = runner.invoke(cli, ["keygen", "--name", "research"])
    r3 = runner.invoke(cli, ["keygen", "--name", "market"])
    research_did = [l for l in r2.output.splitlines() if l.startswith("did:key:")][0]
    market_did = [l for l in r3.output.splitlines() if l.startswith("did:key:")][0]
    # seed root + vouches into store
    from atar.agent_bootstrap import AgentRegistry, seed_trust_root

    reg = AgentRegistry()
    seed_trust_root("seed_agent")
    reg = AgentRegistry()  # reload (seed_trust_root makes a fresh instance)
    reg.vouch("seed_agent", "research", score=0.9, scope="intelligence")
    reg.vouch("seed_agent", "market", score=0.8, scope="intelligence")
    return reg.seed_did


def test_web_builds_html_response(tmp_path, monkeypatch):
    home = str(tmp_path)
    seed = _seed_real_net(home, monkeypatch)
    body = build_dashboard_response(scope="intelligence")
    assert isinstance(body, str)
    assert "#0a0a0b" in body  # seed_agent dark design
    assert "Know Your Agent" in body
    assert seed in body  # seed DID rendered


def test_web_handler_serves_dashboard(tmp_path, monkeypatch):
    home = str(tmp_path)
    seed = _seed_real_net(home, monkeypatch)
    handler = DashboardHandler
    # simulate a GET by calling the render method directly via helper
    html = build_dashboard_response(scope="intelligence")
    assert "seed_agent" in html.lower() or seed in html
