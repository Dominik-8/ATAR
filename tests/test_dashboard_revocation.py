import os
import json
import tempfile

from atar.dashboard import dashboard_data, render_dashboard_html
from atar.agent_bootstrap import AgentRegistry, seed_trust_root
from atar.store import VouchStore
from atar.revocation import RevocationList, revoke_vouch, revoke_payload_id
from atar.identity import generate_identity, did_from_public


def _build_net_with_revocation(home, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    reg = AgentRegistry()
    seed_trust_root("seed_agent")
    reg = AgentRegistry()  # reload (seed_trust_root makes a fresh instance)
    reg.register("research")
    reg.register("market")
    reg.vouch("seed_agent", "research", score=0.9, scope="intelligence")
    reg.vouch("seed_agent", "market", score=0.8, scope="intelligence")
    # revoke the market vouch
    v = VouchStore(os.path.join(home, "vouches.json")).all()[0]  # market vouch
    # find market vouch specifically
    for vv in VouchStore(os.path.join(home, "vouches.json")).all():
        if vv["payload"]["subject"] == reg.did_of("market"):
            v = vv
    break_outer = True
    # sign revocation with seed_agent's key
    vid = revoke_payload_id(v)
    rl = RevocationList()
    ident = reg.identity_of("seed_agent")
    assert revoke_vouch(rl, ident, vid) is True
    rl.save(os.path.join(home, "revocations.json"))
    return reg, vid


def test_revoked_agent_shows_in_dashboard(tmp_path, monkeypatch):
    reg, vid = _build_net_with_revocation(str(tmp_path), monkeypatch)
    net = reg.build_network(scope="intelligence")
    data = dashboard_data(net, scope="intelligence")
    market_entry = next(a for a in data["agents"] if a["name"] == "market")
    assert market_entry["revoked"] is True
    assert "seed_agent" in market_entry["revoked_by"]


def test_revoked_agent_has_zero_trust(tmp_path, monkeypatch):
    reg, vid = _build_net_with_revocation(str(tmp_path), monkeypatch)
    net = reg.build_network(scope="intelligence")
    data = dashboard_data(net, scope="intelligence")
    market_entry = next(a for a in data["agents"] if a["name"] == "market")
    assert market_entry["trust"] == 0.0


def test_revoked_renders_red_in_html(tmp_path, monkeypatch):
    reg, vid = _build_net_with_revocation(str(tmp_path), monkeypatch)
    net = reg.build_network(scope="intelligence")
    html = render_dashboard_html(net, scope="intelligence")
    assert "REVOKED" in html
    # red marker class present
    assert "revoked" in html.lower()


def test_non_revoked_agent_not_flagged(tmp_path, monkeypatch):
    reg, vid = _build_net_with_revocation(str(tmp_path), monkeypatch)
    net = reg.build_network(scope="intelligence")
    data = dashboard_data(net, scope="intelligence")
    research = next(a for a in data["agents"] if a["name"] == "research")
    assert research["revoked"] is False
