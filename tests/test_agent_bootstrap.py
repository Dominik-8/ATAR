import os
import json
import tempfile

from atar.agent_bootstrap import (
    AgentRegistry,
    seed_trust_root,
)


def test_register_agent_persists_did(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    reg = AgentRegistry()
    did = reg.register("seed_agent")
    assert did.startswith("did:key:z6Mk")
    # reload -> same DID (stable)
    reg2 = AgentRegistry()
    assert reg2.did_of("seed_agent") == did


def test_vouch_for_writes_to_persistent_store(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    reg = AgentRegistry()
    a = reg.register("seed_agent")
    b = reg.register("research")
    # seed_agent vouches for research
    ok = reg.vouch("seed_agent", "research", score=0.9, scope="intelligence")
    assert ok is True
    # store on disk has the vouch
    store_path = os.path.join(tmp_path, "vouches.json")
    data = json.load(open(store_path))
    assert len(data["vouches"]) == 1
    p = data["vouches"][0]["payload"]
    assert p["issuer"] == a and p["subject"] == b


def test_seed_trust_root_makes_agent_trusted(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    reg = AgentRegistry()
    reg.register("seed_agent")
    seed_trust_root("seed_agent")
    # the registry knows the seed (reload to simulate fresh process)
    reg2 = AgentRegistry()
    assert reg2.seed_did == reg2.did_of("seed_agent")


def test_network_visible_in_dashboard(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    reg = AgentRegistry()
    reg.register("seed_agent")
    reg.register("research")
    reg.register("market")
    seed_trust_root("seed_agent")
    reg.vouch("seed_agent", "research", score=0.9, scope="intelligence")
    reg.vouch("seed_agent", "market", score=0.8, scope="intelligence")
    reg.vouch("research", "market", score=0.6, scope="intelligence")
    # reload registry fresh (new process simulation)
    reg2 = AgentRegistry()
    net = reg2.build_network(scope="intelligence")
    assert len(net["agents"]) == 3
    from atar.dashboard import dashboard_data
    data = dashboard_data(net, scope="intelligence")
    # all 3 reachable from seed
    assert len(data["agents"]) == 3
    # market reachable transitively via research too
    market = next(a for a in data["agents"] if a["name"] == "market")
    assert market["trust"] > 0
