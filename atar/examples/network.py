"""Demo trust network for ATAR — a self-contained, local, private example.

Builds a small web of agents (seed, reporting, research, market, founder_intel)
that vouch for one another, so the transitive-trust graph is demonstrable
*without* any external service. Used to (a) test the graph end-to-end and
(b) give you a live network to render in the Know-Your-Agent view (Phase 6).

This is a local fixture, not a published artifact. Keep it private.
"""

from __future__ import annotations

from atar.identity import generate_identity, did_from_public
from atar.vouch import create_vouch
from atar.transparency import graph_from_vouches


def build_demo_network() -> dict:
    """Create 5 agents and a set of cross-vouches forming a web of trust.

    Structure (scope="intelligence"):
        seed          ──0.95──> reporting
        seed          ──0.9──> research
        seed          ──0.8──> market
        research      ──0.7──> founder_intel
        market        ──0.6──> founder_intel
        reporting     ──0.75──> research  (mutual reinforcement)

    So founder_intel is reachable transitively two ways, research is directly
    trusted by seed, etc. Demonstrates multi-path transitive trust.
    """
    seed = generate_identity()  # primary agent (the trusted root)
    reporting = generate_identity()
    research = generate_identity()
    market = generate_identity()
    founder = generate_identity()

    agents = {
        "seed": did_from_public(seed.public_key),
        "reporting": did_from_public(reporting.public_key),
        "research": did_from_public(research.public_key),
        "market": did_from_public(market.public_key),
        "founder": did_from_public(founder.public_key),
    }

    vouches = [
        create_vouch(seed, reporting.public_key, score=0.95, scope="intelligence"),
        create_vouch(seed, research.public_key, score=0.9, scope="intelligence"),
        create_vouch(seed, market.public_key, score=0.8, scope="intelligence"),
        create_vouch(research, founder.public_key, score=0.7, scope="intelligence"),
        create_vouch(market, founder.public_key, score=0.6, scope="intelligence"),
        create_vouch(reporting, research.public_key, score=0.75, scope="intelligence"),
    ]

    return {
        "agents": agents,
        "seed_did": agents["seed"],
        "vouches": vouches,
    }


def demo_trust_report(net: dict, *, scope: str) -> str:
    """Render a human-readable transitive-trust report for the demo net."""
    g = graph_from_vouches(net["vouches"])
    trust = g.compute_trust(seed_did=net["seed_did"], scope=scope)
    # map DIDs back to friendly names
    name_by_did = {v: k for k, v in net["agents"].items()}
    ranked = sorted(trust.items(), key=lambda kv: kv[1], reverse=True)
    lines = [
        "ATAR demo trust report",
        f"seed : {net['seed_did']} (seed)",
        f"scope: {scope}",
        "--- trust ranking ---",
    ]
    for did, score in ranked:
        name = name_by_did.get(did, "?")
        marker = " (seed)" if did == net["seed_did"] else ""
        lines.append(f"  {name:12s} {did}  trust={score:.3f}{marker}")
    return "\n".join(lines)
