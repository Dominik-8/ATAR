"""Export/import round-trip: the bundle must carry the WHOLE trust graph -
vouches, revocations, disputes, and agent names - not just vouches.

Before this test: export dropped disputes (silent loss of negative
signals, SPEC 8.2) and recorded agent names that import never restored,
so a migrated network rendered every agent as "?" in dashboard/graph.
"""

from __future__ import annotations

import json
import os

from click.testing import CliRunner

from atar.cli import cli
from atar.dispute import DisputeList
from atar.identity import generate_identity
from atar.vouch import create_vouch


def _run(runner, args, env):
    r = runner.invoke(cli, args, env=env)
    assert r.exit_code == 0, f"atar {' '.join(args)} failed: {r.output}"
    return r


def _build_home_a(tmp_path):
    home_a = str(tmp_path / "a")
    os.makedirs(home_a)
    env = {"ATAR_HOME": home_a}
    runner = CliRunner()
    _run(runner, ["keygen", "--name", "alice"], env)
    _run(runner, ["keygen", "--name", "bob"], env)
    keys = json.load(open(os.path.join(home_a, "keys.json")))
    bob = keys["bob"]["did"]
    _run(runner, ["vouch", "--from", "alice", "--for", bob, "--score", "0.9",
                  "--scope", "coding", "--out", os.path.join(home_a, "v.json")], env)
    _run(runner, ["add", os.path.join(home_a, "v.json")], env)
    # a foreign vouch (issuer not in keys.json) that alice disputes
    carol = generate_identity()
    dave = generate_identity()
    foreign = create_vouch(carol, dave.public_key, score=0.4, scope="coding",
                           ts=1_700_000_000)
    fpath = os.path.join(home_a, "foreign.json")
    json.dump(foreign, open(fpath, "w"))
    _run(runner, ["add", fpath], env)
    _run(runner, ["dispute", fpath, "--from", "alice", "--reason",
                  "score looks inflated"], env)
    return home_a, env


def test_roundtrip_carries_disputes_and_names(tmp_path):
    home_a, env_a = _build_home_a(tmp_path)
    runner = CliRunner()
    bundle = os.path.join(home_a, "net.atpkg")
    _run(runner, ["export", "--out", bundle], env_a)

    data = json.load(open(bundle))
    assert len(data["vouches"]) == 2
    assert len(data["disputes"]) == 1, "export must include disputes"
    assert data["agents"]["alice"] and data["agents"]["bob"], \
        "export must record keys.json names too, not only the registry"

    home_b = str(tmp_path / "b")
    os.makedirs(home_b)
    env_b = {"ATAR_HOME": home_b}
    r = _run(runner, ["import", bundle], env_b)
    assert "1 dispute(s)" in r.output, r.output
    assert "2 agent name(s)" in r.output, r.output

    dl = DisputeList.load(os.path.join(home_b, "disputes.json"))
    assert len(dl.all()) == 1

    from atar.agent_bootstrap import known_agent_names
    os.environ["ATAR_HOME"] = home_b
    try:
        names = known_agent_names()
    finally:
        os.environ["ATAR_HOME"] = home_a
    assert names.get("alice") and names.get("bob")

    # names land in the keyless file, never in keys.json (no private keys
    # exist for them on this machine)
    assert os.path.exists(os.path.join(home_b, "known-agents.json"))
    assert not os.path.exists(os.path.join(home_b, "keys.json"))


def test_import_names_never_clobber_local_identity(tmp_path):
    home_a, env_a = _build_home_a(tmp_path)
    runner = CliRunner()
    bundle = os.path.join(home_a, "net.atpkg")
    _run(runner, ["export", "--out", bundle], env_a)

    home_b = str(tmp_path / "b")
    os.makedirs(home_b)
    env_b = {"ATAR_HOME": home_b}
    # home B already has its own "alice" - a DIFFERENT key
    _run(runner, ["keygen", "--name", "alice"], env_b)
    b_alice = json.load(open(os.path.join(home_b, "keys.json")))["alice"]["did"]
    _run(runner, ["import", bundle], env_b)

    from atar.agent_bootstrap import known_agent_names
    os.environ["ATAR_HOME"] = home_b
    try:
        names = known_agent_names()
    finally:
        os.environ["ATAR_HOME"] = home_a
    assert names["alice"] == b_alice, "local identity must win over the bundle"
