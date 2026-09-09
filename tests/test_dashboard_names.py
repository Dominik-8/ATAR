"""Dashboard name resolution for CLI-only networks.

Regression: agents created with plain `atar keygen` (no bootstrap registry)
rendered as "?" in the dashboard and the live server, with trust paths
reading "via ?". Names now resolve from keys.json via known_agent_names().
"""

from __future__ import annotations

import json

from click.testing import CliRunner

from atar.cli import cli


def _seed_cli_network(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    dids = {}
    for name in ("seed", "research", "reporting"):
        r = runner.invoke(cli, ["keygen", "--name", name])
        assert r.exit_code == 0
        dids[name] = r.output.strip()
    for frm, to, score in (
        ("seed", "research", "0.9"),
        ("seed", "reporting", "0.75"),
        ("research", "reporting", "0.95"),
    ):
        vf = tmp_path / f"{frm}-{to}.json"
        assert (
            runner.invoke(
                cli,
                [
                    "vouch",
                    "--from",
                    frm,
                    "--for",
                    dids[to],
                    "--score",
                    score,
                    "--scope",
                    "coding",
                    "--out",
                    str(vf),
                ],
            ).exit_code
            == 0
        )
        assert runner.invoke(cli, ["add", str(vf)]).exit_code == 0
    return runner, dids


def test_dashboard_cli_resolves_keygen_names(tmp_path, monkeypatch):
    runner, dids = _seed_cli_network(tmp_path, monkeypatch)
    out = tmp_path / "dash.html"
    r = runner.invoke(
        cli,
        ["dashboard", "--seed", dids["seed"], "--scope", "coding", "--out", str(out)],
    )
    assert r.exit_code == 0
    html = out.read_text()
    assert ">seed<" in html and ">research<" in html and ">reporting<" in html
    assert "via research" in html  # trust path names the intermediate
    assert "<h2>?</h2>" not in html and 'class="a-name">?<' not in html


def test_known_agent_names_merges_keys_and_registry(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "solo"])
    from atar.agent_bootstrap import known_agent_names

    names = known_agent_names()
    assert names["solo"].startswith("did:key:")


def test_live_server_resolves_keygen_names(tmp_path, monkeypatch):
    """web._build_net must pick up keygen-only identities too."""
    runner, dids = _seed_cli_network(tmp_path, monkeypatch)
    from atar.web import _build_net

    net = _build_net()
    from atar.identity import normalize_did

    got = {normalize_did(v) for v in net["agents"].values()}
    for d in dids.values():
        assert normalize_did(d) in got
