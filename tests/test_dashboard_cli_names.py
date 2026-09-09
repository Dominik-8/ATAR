from pathlib import Path

from click.testing import CliRunner

from atar.cli import cli


def test_dashboard_cli_resolves_agent_names_from_registry(tmp_path, monkeypatch):
    """Regression: `atar dashboard` must show real agent names (from the
    registry), not '?'. Bug: net['agents'] was hardcoded to {}.
    """
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "seed_agent"])
    # bootstrap the registry (so names + seed exist)
    runner.invoke(cli, ["bootstrap", "--config", "agents.toml"])

    out = str(tmp_path / "dash.html")
    r2 = runner.invoke(cli, ["dashboard", "--out", out])
    assert r2.exit_code == 0, r2.output
    html = Path(out).read_text(encoding="utf-8")
    # registry agents must appear by NAME (not '?')
    assert "seed_agent" in html
    assert "reporting_agent" in html
    assert "<h2>?</h2>" not in html
