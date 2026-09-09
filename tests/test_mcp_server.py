"""The MCP server exposes ATAR's read/verify surface to any MCP host.

Tests run the real MCP protocol in-memory (mcp.client.Client against the
MCPServer object) - no stdio subprocesses, no network. They pin both the
tool surface (names) and the trust semantics (the same computation as
`atar graph`, the same verification as `atar verify`).
"""

import asyncio
import json

import pytest

mcp = pytest.importorskip("mcp", reason="MCP extra not installed")

from mcp.client import Client  # noqa: E402

from atar.atc import make_agent_card, sign_agent_card, vouch_to_token  # noqa: E402
from atar.identity import did_from_public, generate_identity  # noqa: E402
from atar.integrations.mcp_server import create_server  # noqa: E402
from atar.store import VouchStore  # noqa: E402
from atar.vouch import create_vouch  # noqa: E402

EXPECTED_TOOLS = {
    "verify_vouch",
    "verify_vouch_token",
    "verify_agent_card",
    "trust_scores",
    "vouches_for",
    "list_known_agents",
}


def _call(server, tool: str, args: dict, tmp_path):
    """Call one tool and return its JSON payload (fails the test on MCP errors)."""

    async def run():
        async with Client(server) as client:
            result = await client.call_tool(tool, args)
            assert not result.is_error, f"tool {tool} returned an MCP error: {result}"
            (text,) = [c.text for c in result.content if c.type == "text"]
            return json.loads(text)

    return asyncio.run(run())


@pytest.fixture()
def store_env(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    return tmp_path


@pytest.fixture()
def seeded(store_env):
    """root --0.9/intelligence--> alice --0.8/intelligence--> bob, persisted."""
    root, alice, bob = generate_identity(), generate_identity(), generate_identity()
    store = VouchStore(str(store_env / "vouches.json"))
    v_root_alice = create_vouch(root, alice.public_key, score=0.9, scope="intelligence")
    v_alice_bob = create_vouch(alice, bob.public_key, score=0.8, scope="intelligence")
    assert store.add(v_root_alice)
    assert store.add(v_alice_bob)
    return {
        "root": root,
        "alice": alice,
        "bob": bob,
        "root_did": did_from_public(root.public_key),
        "alice_did": did_from_public(alice.public_key),
        "bob_did": did_from_public(bob.public_key),
        "v_root_alice": v_root_alice,
        "v_alice_bob": v_alice_bob,
    }


def test_tool_surface(store_env):
    server = create_server()

    async def run():
        async with Client(server) as client:
            result = await client.list_tools()
            return {t.name for t in result.tools}

    assert asyncio.run(run()) == EXPECTED_TOOLS


def test_verify_vouch_valid_and_summary(store_env, seeded):
    out = _call(
        create_server(), "verify_vouch", {"vouch": seeded["v_root_alice"]}, store_env
    )
    assert out["valid"] is True
    assert out["vouch"]["issuer"] == seeded["root_did"]
    assert out["vouch"]["subject"] == seeded["alice_did"]
    assert out["vouch"]["scope"] == "intelligence"
    assert out["vouch"]["score"] == 0.9
    assert out["vouch"]["vouch_id"].startswith("vouch:")


def test_verify_vouch_rejects_garbage(store_env):
    out = _call(
        create_server(),
        "verify_vouch",
        {"vouch": {"payload": {}, "signature": "00"}},
        store_env,
    )
    assert out["valid"] is False


def test_verify_vouch_token_roundtrip(store_env, seeded):
    token = vouch_to_token(seeded["v_root_alice"])
    out = _call(create_server(), "verify_vouch_token", {"token": token}, store_env)
    assert out["valid"] is True
    assert out["vouch"]["issuer"] == seeded["root_did"]


def test_verify_vouch_token_rejects_garbage(store_env):
    out = _call(
        create_server(), "verify_vouch_token", {"token": "not-a-token"}, store_env
    )
    assert out["valid"] is False


def test_verify_agent_card(store_env, seeded):
    card = make_agent_card(
        seeded["alice_did"],
        "alice",
        [seeded["v_root_alice"]],
        url="https://alice.example.org/a2a",
        description="test agent",
    )
    signed = sign_agent_card(card, seeded["alice"])
    out = _call(create_server(), "verify_agent_card", {"card": signed}, store_env)
    assert out["did"] == seeded["alice_did"]
    assert out["signature_valid"] is True
    assert len(out["valid_vouches"]) == 1


def test_verify_agent_card_never_crashes(store_env):
    out = _call(
        create_server(),
        "verify_agent_card",
        {"card": {"capabilities": None}},
        store_env,
    )
    assert out["signature_valid"] is False
    assert out["valid_vouches"] == []


def test_trust_scores_transitive(store_env, seeded):
    out = _call(
        create_server(),
        "trust_scores",
        {"seed": seeded["root_did"], "scope": "intelligence"},
        store_env,
    )
    assert out["ok"] is True
    assert out["seed"] == seeded["root_did"]
    # same transitive computation as `atar graph`: 0.9 * 0.8 for the 2-hop node
    assert out["scores"][seeded["alice_did"]] == pytest.approx(0.9)
    assert out["scores"][seeded["bob_did"]] == pytest.approx(0.72)
    # the ranking includes the seed itself (fixed at 1.0) plus reachable agents
    assert out["scores"][seeded["root_did"]] == pytest.approx(1.0)
    assert out["reachable_agents"] == 3


def test_trust_scores_rejects_unknown_seed(store_env):
    out = _call(
        create_server(), "trust_scores", {"seed": "nobody", "scope": "x"}, store_env
    )
    assert out["ok"] is False
    assert "seed" in out["error"]


def test_vouches_for(store_env, seeded):
    out = _call(create_server(), "vouches_for", {"did": seeded["alice_did"]}, store_env)
    assert out["ok"] is True
    assert [v["subject"] for v in out["received"]] == [seeded["alice_did"]]
    assert [v["subject"] for v in out["issued"]] == [seeded["bob_did"]]


def test_vouches_for_rejects_unknown(store_env):
    out = _call(
        create_server(), "vouches_for", {"did": "did:web:example.org"}, store_env
    )
    assert out["ok"] is False


def test_list_known_agents(store_env, seeded):
    out = _call(create_server(), "list_known_agents", {}, store_env)
    assert out["ok"] is True
    assert out["vouches_in_store"] == 2
    assert out["agents"] == []  # no registered names in a fresh home
