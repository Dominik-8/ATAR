"""Stage C2: CrewAI framework plugin (duck-typed; no crewai dependency)."""

import os

from click.testing import CliRunner

from atar.atc import verify_agent_card, verify_card_signature
from atar.cli import cli
from atar.integrations.crewai import AtarCrewTrust
from atar.store import VouchStore


class FakeAgent:
    def __init__(self, role):
        self.role = role


class FakeCrew:
    def __init__(self, agents):
        self.agents = agents


class FakeTaskOutput:
    raw = "task result text"


def _trust(tmp_path, monkeypatch, **kw):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    return AtarCrewTrust(**kw)


def test_register_crew_gives_every_agent_an_identity(tmp_path, monkeypatch):
    trust = _trust(tmp_path, monkeypatch)
    crew = FakeCrew([FakeAgent("researcher"), FakeAgent("writer")])
    mapping = trust.register_crew(crew)
    assert set(mapping) == {"researcher", "writer"}
    assert all(d.startswith("did:key:") for d in mapping.values())
    assert mapping["researcher"] != mapping["writer"]
    # stable across instances/restarts
    trust2 = _trust(tmp_path, monkeypatch)
    assert trust2.did_of("researcher") == mapping["researcher"]


def test_successful_task_earns_a_vouch(tmp_path, monkeypatch):
    trust = _trust(tmp_path, monkeypatch, scope="research")
    trust.register("researcher")
    cb = trust.task_callback_for("researcher")
    cb(FakeTaskOutput())  # CrewAI calls this only on successful completion
    store = VouchStore(os.path.join(str(tmp_path), "vouches.json"))
    assert store.count() == 1
    v = store.all()[0]["payload"]
    assert v["subject"] == trust.did_of("researcher")
    assert v["issuer"] == trust.did_of("crew_operator")
    assert v["scope"] == "research"
    assert 0.0 < v["score"] <= 1.0


def test_callback_scope_override(tmp_path, monkeypatch):
    trust = _trust(tmp_path, monkeypatch, scope="general")
    cb = trust.task_callback_for("writer", scope="summarization")
    cb(FakeTaskOutput())
    v = VouchStore(os.path.join(str(tmp_path), "vouches.json")).all()[0]["payload"]
    assert v["scope"] == "summarization"


def test_card_is_signed_and_verifies(tmp_path, monkeypatch):
    trust = _trust(tmp_path, monkeypatch)
    trust.register("researcher")
    trust.task_callback_for("researcher")(FakeTaskOutput())
    card = trust.card("researcher")
    assert verify_card_signature(card)
    report = verify_agent_card(card)
    assert report["signature_valid"] is True
    assert report["did"] == trust.did_of("researcher")
    assert len(report["valid_vouches"]) == 1
    assert not report["invalid_vouches"]


def test_card_of_unknown_agent_still_works(tmp_path, monkeypatch):
    trust = _trust(tmp_path, monkeypatch)
    card = trust.card("newcomer")  # auto-registers, zero vouches
    assert verify_card_signature(card)
    assert verify_agent_card(card)["valid_vouches"] == []


def test_vouch_survives_gossip(tmp_path, monkeypatch):
    # a plugin-earned vouch behaves like any other: it syncs to a peer
    trust = _trust(tmp_path / "a", monkeypatch)
    trust.task_callback_for("researcher")(FakeTaskOutput())
    peer_home = str(tmp_path / "b")
    os.makedirs(peer_home)
    runner = CliRunner()
    r = runner.invoke(cli, ["sync", "--with", peer_home])
    assert r.exit_code == 0, r.output
    assert VouchStore(os.path.join(peer_home, "vouches.json")).count() == 1


def test_score_bounds_enforced(tmp_path, monkeypatch):
    import pytest

    with pytest.raises(ValueError):
        _trust(tmp_path, monkeypatch, score=1.5)
