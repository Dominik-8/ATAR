import os

from click.testing import CliRunner

from atar.cli import cli

_CFG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                    "agents.toml")


def test_dashboard_without_seed_uses_registry_seed(tmp_path, monkeypatch):
    """If --seed is omitted, dashboard should use the seeded agent from the
    registry instead of erroring. (UX fix: bootstrap -> dashboard should work.)"""
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["bootstrap", "--config", _CFG])
    out = tmp_path / "dash.html"
    r = runner.invoke(cli, ["dashboard", "--out", str(out)])
    assert r.exit_code == 0, r.output
    assert out.exists()
    assert out.stat().st_size > 0


def test_graph_without_seed_uses_registry_seed(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["bootstrap", "--config", _CFG])
    r = runner.invoke(cli, ["graph"])
    assert r.exit_code == 0, r.output
    assert "intelligence" in r.output
