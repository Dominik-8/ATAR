import os
import tempfile

from click.testing import CliRunner

from atar.cli import cli
from atar.agent_bootstrap import AgentRegistry, seed_trust_root


def _seed_multi_scope(home, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    reg = AgentRegistry()
    seed_trust_root("seed_agent")
    reg = AgentRegistry()
    reg.register("research")
    reg.register("market")
    reg.vouch("seed_agent", "research", score=0.9, scope="intelligence")
    reg.vouch("seed_agent", "research", score=0.8, scope="coding")
    reg.vouch("seed_agent", "market", score=0.8, scope="intelligence")
    return reg


def test_scopes_cli_lists_scopes_and_counts(tmp_path, monkeypatch):
    _seed_multi_scope(str(tmp_path), monkeypatch)
    runner = CliRunner()
    r = runner.invoke(cli, ["scopes"])
    assert r.exit_code == 0
    assert "intelligence" in r.output
    assert "coding" in r.output
    # intelligence has seed_agent+research+market (3), coding has seed_agent+research (2)
    assert "3" in r.output  # agent count for intelligence
    assert "2" in r.output  # agent count for coding


def test_scopes_cli_empty_store(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    r = runner.invoke(cli, ["scopes"])
    assert r.exit_code == 0
    assert "no scopes" in r.output.lower() or "empty" in r.output.lower()
