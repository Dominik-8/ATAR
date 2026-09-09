import os
import json

from click.testing import CliRunner

from atar.cli import cli
from atar.examples.network import build_demo_network


def test_dashboard_cli_writes_html(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    # build demo network and add its vouches into the persistent store
    net = build_demo_network()
    for v in net["vouches"]:
        fn = tmp_path / "v.json"
        with open(fn, "w", encoding="utf-8") as f:
            json.dump(v, f)
        runner.invoke(cli, ["add", str(fn)])
    out = tmp_path / "dash.html"
    r = runner.invoke(
        cli,
        [
            "dashboard",
            "--seed",
            net["seed_did"],
            "--scope",
            "intelligence",
            "--out",
            str(out),
        ],
    )
    assert r.exit_code == 0
    assert out.exists()
    html = out.read_text(encoding="utf-8")
    assert "#0a0a0b" in html  # seed_agent dark design
    assert "#39ff14" in html  # gift-green accent
    assert "Know Your Agent" in html
    # every agent DID present
    for did in net["agents"].values():
        assert did in html
