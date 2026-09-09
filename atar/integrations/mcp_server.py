"""MCP server: ATAR trust verification and lookup for any MCP host.

Exposes ATAR's read/verify surface over the Model Context Protocol, so MCP
hosts (Claude, ChatGPT, Cursor, Copilot, ...) can answer "is this vouch
genuine?", "is this agent card correctly signed?" and "what does my local
trust graph say about this DID?" without shelling out to the CLI.

Read-only by design: the server verifies and reports, it never signs.
Reputation is minted by the operator through the CLI after human judgment -
a connected MCP client must never be able to mint trust. (SPEC §8.1: trust
flows from a trusted seed; issuance is an operator decision.)

Runs over stdio (the standard MCP transport):

    atar mcp            # or: python -m atar.integrations.mcp_server

Requires the optional extra: pip install "atar-trust[mcp]".
The module imports fine without it - only create_server() needs the SDK.
"""

from __future__ import annotations

import os
from typing import Any

from ..atc import verify_agent_card, verify_token, vouch_from_token
from ..transparency import canonical_vouch_id
from ..vouch import verify_vouch

SERVER_NAME = "atar-trust"
SERVER_INSTRUCTIONS = (
    "ATAR (Agent Trust & Attribution Root) trust-graph tools. All tools are "
    "read-only verifiers and reports over the operator's LOCAL trust store; "
    "nothing here signs or issues vouches. DIDs are did:key identifiers; "
    "local identity names also resolve. A vouch token is the base64url ATC "
    "form from 'atar vouch --token' / agent cards."
)


def _home() -> str:
    return os.environ.get("ATAR_HOME", os.path.join(os.path.expanduser("~"), ".atar"))


def _store_vouches() -> list[dict]:
    from ..store import VouchStore

    return VouchStore(os.path.join(_home(), "vouches.json")).all()


def _vouch_summary(vouch: dict) -> dict[str, Any]:
    payload = vouch.get("payload", {})
    return {
        "vouch_id": canonical_vouch_id(vouch),
        "issuer": payload.get("issuer"),
        "subject": payload.get("subject"),
        "scope": payload.get("scope"),
        "score": payload.get("score"),
        "claim": payload.get("claim"),
        "ts": payload.get("ts"),
        "evidence": payload.get("evidence"),
    }


def create_server():
    """Build the ATAR MCP server. Imports the MCP SDK lazily so the core
    package never depends on it."""
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError as exc:  # pragma: no cover - exercised via CLI test
        raise SystemExit(
            "the MCP integration needs the optional extra: "
            'pip install "atar-trust[mcp]"'
        ) from exc

    server = MCPServer(
        name=SERVER_NAME,
        instructions=SERVER_INSTRUCTIONS,
        version=_package_version(),
    )

    @server.tool(
        name="verify_vouch",
        description=(
            "Verify a native ATAR vouch blob ({payload, signature}) against "
            "the issuer's did:key. Fully offline; returns valid=true/false "
            "plus the vouch summary when parseable."
        ),
    )
    def tool_verify_vouch(vouch: dict) -> dict:
        valid = verify_vouch(vouch)
        out: dict[str, Any] = {"valid": valid}
        if isinstance(vouch, dict) and isinstance(vouch.get("payload"), dict):
            out["vouch"] = _vouch_summary(vouch)
        return out

    @server.tool(
        name="verify_vouch_token",
        description=(
            "Verify an ATC vouch token (base64url, header-safe; SPEC §11.1) "
            "and return validity plus the decoded vouch."
        ),
    )
    def tool_verify_vouch_token(token: str) -> dict:
        valid = verify_token(token)
        out: dict[str, Any] = {"valid": valid}
        if valid:
            out["vouch"] = _vouch_summary(vouch_from_token(token))
        return out

    @server.tool(
        name="verify_agent_card",
        description=(
            "Verify an A2A agent card carrying the ATAR trust extension "
            "(SPEC §11.2): every vouch token plus the card signature. "
            "Returns the full report (did, name, valid/invalid vouches, "
            "signature_valid)."
        ),
    )
    def tool_verify_agent_card(card: dict) -> dict:
        return verify_agent_card(card)

    @server.tool(
        name="trust_scores",
        description=(
            "Compute transitive trust over the operator's local store from a "
            "seed DID (or local identity name) for a capability scope. Only "
            "valid, unrevoked, unexpired vouches count; disputes from "
            "trusted disputers discount their targets (SPEC §8)."
        ),
    )
    def tool_trust_scores(seed: str | None = None, scope: str = "general") -> dict:
        from ..dispute import DisputeList
        from ..freshness import VOUCH_TTL_DEFAULT
        from ..revocation import RevocationList
        from ..transparency import TrustGraph

        seed_did = _resolve_seed(seed)
        if seed_did is None:
            return {
                "ok": False,
                "error": (
                    "no usable seed: pass a did:key DID or a local identity "
                    "name, or seed a default agent first (atar bootstrap)"
                ),
            }
        graph = TrustGraph()
        for v in _store_vouches():
            graph.add(v)
        scores = graph.compute_trust(
            seed_did=seed_did,
            scope=scope,
            revocations=RevocationList.load(os.path.join(_home(), "revocations.json")),
            disputes=DisputeList.load(os.path.join(_home(), "disputes.json")),
            ttl=VOUCH_TTL_DEFAULT,
        )
        ranked = sorted(scores.items(), key=lambda kv: kv[1], reverse=True)
        return {
            "ok": True,
            "seed": seed_did,
            "scope": scope,
            "vouches_in_store": len(graph.all_vouches()),
            "reachable_agents": len(ranked),
            "scores": {did: round(score, 6) for did, score in ranked},
        }

    @server.tool(
        name="vouches_for",
        description=(
            "List vouches in the operator's local store that a DID (or local "
            "identity name) issued or received, with revocation state."
        ),
    )
    def tool_vouches_for(did: str) -> dict:
        resolved = _resolve_did(did)
        if resolved is None:
            return {"ok": False, "error": f"not a supported DID or known name: {did!r}"}
        from ..identity import normalize_did

        target = normalize_did(resolved)
        issued, received = [], []
        for v in _store_vouches():
            payload = v.get("payload", {})
            try:
                issuer = normalize_did(payload.get("issuer", ""))
                subject = normalize_did(payload.get("subject", ""))
            except ValueError:
                continue
            summary = _vouch_summary(v)
            if issuer == target:
                issued.append(summary)
            if subject == target:
                received.append(summary)
        return {"ok": True, "did": resolved, "issued": issued, "received": received}

    @server.tool(
        name="list_known_agents",
        description=(
            "List the operator's known agents: local identity names mapped to "
            "DIDs, plus vouch-store size."
        ),
    )
    def tool_list_known_agents() -> dict:
        from ..agent_bootstrap import known_agent_names

        names = known_agent_names()
        return {
            "ok": True,
            "agents": [{"name": n, "did": d} for n, d in sorted(names.items())],
            "vouches_in_store": len(_store_vouches()),
        }

    return server


def _package_version() -> str:
    try:
        from importlib.metadata import version

        return version("atar-trust")
    except Exception:  # noqa: BLE001 - metadata missing in dev checkouts
        return ""


def _resolve_did(value: str) -> str | None:
    """DID or local identity name -> DID (same rule as the CLI)."""
    from ..agent_bootstrap import known_agent_names
    from ..identity import is_supported_did

    value = value.strip()
    if is_supported_did(value):
        return value
    return known_agent_names().get(value)


def _resolve_seed(seed: str | None) -> str | None:
    if seed:
        return _resolve_did(seed)
    try:
        from ..agent_bootstrap import AgentRegistry

        return AgentRegistry().seed_did or None
    except Exception:  # noqa: BLE001 - no readable registry means "no seed"
        return None


def main() -> None:
    """Run the server over stdio (the standard MCP transport)."""
    create_server().run("stdio")


if __name__ == "__main__":
    main()
