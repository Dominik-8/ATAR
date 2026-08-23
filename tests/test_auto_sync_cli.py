import os
import json
import tempfile

from click.testing import CliRunner

from atar.cli import cli
from atar.store import VouchStore


def _seed_seed_agent_home(home, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    # create a vouch so there is something to gossip
    from atar.agent_bootstrap import AgentRegistry, seed_trust_root
    seed_trust_root("seed_agent")
    reg = AgentRegistry()
    # a peer DID to vouch for (stand-in for a real peer)
    peer_did = "did:agent:PEERx" + "0" * 40
    reg._agents[peer_did] = {"did": peer_did, "private": "00" * 32}
    reg._save()
    reg.vouch("seed_agent", peer_did, score=0.9, scope="intelligence")
    return peer_did


def test_auto_sync_hook_reads_peer_list(tmp_path, monkeypatch):
    seed_agent_home = str(tmp_path / "seed_agent")
    peer_home = str(tmp_path / "peer")
    os.makedirs(seed_agent_home)
    os.makedirs(peer_home)
    monkeypatch.setenv("ATAR_HOME", seed_agent_home)
    _seed_seed_agent_home(seed_agent_home, monkeypatch)

    # peer list declares the peer home
    peers_file = os.path.join(seed_agent_home, "atar_peers.json")
    json.dump({"peers": [peer_home]}, open(peers_file, "w"))

    runner = CliRunner()
    r = runner.invoke(cli, ["auto-sync"])
    assert r.exit_code == 0
    assert "synced" in r.output.lower() or "sync" in r.output.lower()
    # peer now has seed_agent's vouch
    peer_store = VouchStore(os.path.join(peer_home, "vouches.json"))
    assert peer_store.count() == 1


def test_auto_sync_hook_no_peers_is_safe(tmp_path, monkeypatch):
    seed_agent_home = str(tmp_path / "seed_agent")
    os.makedirs(seed_agent_home)
    monkeypatch.setenv("ATAR_HOME", seed_agent_home)
    _seed_seed_agent_home(seed_agent_home, monkeypatch)
    # no peers file -> should exit cleanly, not error
    runner = CliRunner()
    r = runner.invoke(cli, ["auto-sync"])
    assert r.exit_code == 0
    assert "no peers" in r.output.lower()


def test_auto_sync_hook_missing_peer_dir_is_skipped(tmp_path, monkeypatch):
    seed_agent_home = str(tmp_path / "seed_agent")
    os.makedirs(seed_agent_home)
    monkeypatch.setenv("ATAR_HOME", seed_agent_home)
    _seed_seed_agent_home(seed_agent_home, monkeypatch)
    peers_file = os.path.join(seed_agent_home, "atar_peers.json")
    json.dump({"peers": [str(tmp_path / "does_not_exist")]}, open(peers_file, "w"))
    runner = CliRunner()
    r = runner.invoke(cli, ["auto-sync"])
    assert r.exit_code == 0  # missing peer dir is skipped, not fatal
