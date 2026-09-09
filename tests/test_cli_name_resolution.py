"""CLI name resolution: anywhere the docs tell users to paste a DID,
a local identity name works too (vouch/issue --for, graph/dashboard --seed).

Born from a fresh-user quickstart walk: step 2 said
`atar vouch --from alice --for "did:key:..."` - copy-pasting a DID the
tool already knows by name.
"""

from __future__ import annotations

import json
import os

from click.testing import CliRunner

from atar.cli import cli


def _env(home):
    return {"ATAR_HOME": str(home)}


def _setup(tmp_path):
    home = tmp_path / "home"
    home.mkdir()
    env = _env(home)
    runner = CliRunner()
    for name in ("alice", "bob"):
        r = runner.invoke(cli, ["keygen", "--name", name], env=env)
        assert r.exit_code == 0, r.output
    keys = json.load(open(home / "keys.json"))
    return runner, env, home, keys


def test_vouch_for_accepts_local_name(tmp_path):
    runner, env, home, keys = _setup(tmp_path)
    out = str(home / "v.json")
    r = runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "alice",
            "--for",
            "bob",
            "--score",
            "0.9",
            "--scope",
            "coding",
            "--out",
            out,
        ],
        env=env,
    )
    assert r.exit_code == 0, r.output
    blob = json.load(open(out))
    assert blob["payload"]["subject"] == keys["bob"]["did"]


def test_vouch_for_unknown_name_errors_clearly(tmp_path):
    runner, env, home, _ = _setup(tmp_path)
    r = runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "alice",
            "--for",
            "nobody",
            "--score",
            "0.9",
            "--scope",
            "coding",
        ],
        env=env,
    )
    assert r.exit_code == 2
    assert "no local identity" in r.output


def test_vouch_for_still_accepts_raw_did(tmp_path):
    runner, env, home, keys = _setup(tmp_path)
    out = str(home / "v.json")
    r = runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "alice",
            "--for",
            keys["bob"]["did"],
            "--score",
            "0.9",
            "--scope",
            "coding",
            "--out",
            out,
        ],
        env=env,
    )
    assert r.exit_code == 0, r.output
    assert json.load(open(out))["payload"]["subject"] == keys["bob"]["did"]


def test_issue_for_accepts_local_name(tmp_path):
    runner, env, home, keys = _setup(tmp_path)
    out = str(home / "c.json")
    r = runner.invoke(
        cli,
        [
            "issue",
            "--from",
            "alice",
            "--for",
            "bob",
            "--scope",
            "coding",
            "--score",
            "0.8",
            "--out",
            out,
        ],
        env=env,
    )
    assert r.exit_code == 0, r.output
    assert json.load(open(out))["payload"]["subject"] == keys["bob"]["did"]


def test_graph_seed_accepts_local_name(tmp_path):
    runner, env, home, keys = _setup(tmp_path)
    v = str(home / "v.json")
    runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "alice",
            "--for",
            "bob",
            "--score",
            "0.9",
            "--scope",
            "coding",
            "--out",
            v,
        ],
        env=env,
    )
    runner.invoke(cli, ["add", v], env=env)
    r = runner.invoke(cli, ["graph", "--seed", "alice", "--scope", "coding"], env=env)
    assert r.exit_code == 0, r.output
    assert f"seed  : {keys['alice']['did']}" in r.output
    assert "bob" in r.output  # ranking shows bob by name, not '?'


def test_dashboard_seed_accepts_local_name(tmp_path):
    runner, env, home, keys = _setup(tmp_path)
    v = str(home / "v.json")
    runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "alice",
            "--for",
            "bob",
            "--score",
            "0.9",
            "--scope",
            "coding",
            "--out",
            v,
        ],
        env=env,
    )
    runner.invoke(cli, ["add", v], env=env)
    out = str(home / "dash.html")
    r = runner.invoke(
        cli,
        ["dashboard", "--seed", "alice", "--scope", "coding", "--out", out],
        env=env,
    )
    assert r.exit_code == 0, r.output
    assert os.path.exists(out)


def test_graph_seed_unknown_name_errors_clearly(tmp_path):
    runner, env, home, _ = _setup(tmp_path)
    r = runner.invoke(cli, ["graph", "--seed", "ghost"], env=env)
    assert r.exit_code != 0
    assert "no local identity" in (r.output or str(r.exception))
