import os
import tempfile

from click.testing import CliRunner

from atar.cli import cli
from atar.agent_bootstrap import AgentRegistry, seed_trust_root


def test_real_agents_bootstrap_from_config(tmp_path, monkeypatch):
    """Your actual agents (seed_agent + daily-brief cron) seed into the network."""
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    cfg = tmp_path / "real_agents.toml"
    cfg.write_text(
        """
[[agents]]
name = "seed_agent"
seed = true

[[agents]]
name = "reporting_agent"

[[vouches]]
issuer = "seed_agent"
subject = "reporting_agent"
score = 0.95
scope = "intelligence"
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    r = runner.invoke(cli, ["bootstrap", "--config", str(cfg)])
    assert r.exit_code == 0
    reg = AgentRegistry()
    assert reg.did_of("seed_agent") is not None
    assert reg.did_of("reporting_agent") is not None
    # the real network has 2 agents + 1 vouch
    from atar.store import VouchStore

    assert VouchStore(os.path.join(tmp_path, "vouches.json")).count() == 1


def test_real_agents_appear_in_dashboard(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    cfg = tmp_path / "real_agents.toml"
    cfg.write_text(
        """
[[agents]]
name = "seed_agent"
seed = true

[[agents]]
name = "reporting_agent"

[[vouches]]
issuer = "seed_agent"
subject = "reporting_agent"
score = 0.95
scope = "intelligence"
""",
        encoding="utf-8",
    )
    runner = CliRunner()
    runner.invoke(cli, ["bootstrap", "--config", str(cfg)])
    from atar.dashboard import dashboard_data
    from atar.agent_bootstrap import AgentRegistry

    reg = AgentRegistry()
    net = reg.build_network(scope="intelligence")
    data = dashboard_data(net, scope="intelligence")
    names = {a["name"] for a in data["agents"]}
    assert "seed_agent" in names
    assert "reporting_agent" in names
