"""No-seed dashboard must be an honest empty state, never a bogus score.

Regression: a CLI-only network (keygen + vouch + add, no bootstrap) served
a dashboard whose single card was an anonymous "?" agent with trust=1.000 -
an artifact of seedless computation rendered as if it were a trusted agent.
"""

from __future__ import annotations

from click.testing import CliRunner

from atar.cli import cli


def _cli_only_network(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "a"])
    r2 = runner.invoke(cli, ["keygen", "--name", "b"])
    b_did = r2.output.strip()
    vf = tmp_path / "v.json"
    runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "a",
            "--for",
            b_did,
            "--score",
            "0.9",
            "--scope",
            "coding",
            "--out",
            str(vf),
        ],
    )
    runner.invoke(cli, ["add", str(vf)])


def test_single_scope_no_seed_shows_setup_notice(tmp_path, monkeypatch):
    _cli_only_network(tmp_path, monkeypatch)
    from atar.web import build_dashboard_response

    html = build_dashboard_response(scope="coding")
    assert "No trust seed configured" in html
    assert "atar bootstrap" in html
    assert "trust=1.000" not in html and ">?<" not in html


def test_multi_scope_no_seed_shows_setup_notice(tmp_path, monkeypatch):
    _cli_only_network(tmp_path, monkeypatch)
    from atar.web import build_dashboard_response_multi

    html = build_dashboard_response_multi()
    assert "No trust seed configured" in html
    assert "trust=1.000" not in html and ">?<" not in html


def test_seeded_network_still_renders_normally(tmp_path, monkeypatch):
    import os

    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    cfg = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agents.toml"
    )
    runner = CliRunner()
    assert runner.invoke(cli, ["bootstrap", "--config", cfg]).exit_code == 0
    from atar.web import build_dashboard_response_multi

    html = build_dashboard_response_multi()
    assert "Know Your Agent" in html
    assert "No trust seed configured" not in html
