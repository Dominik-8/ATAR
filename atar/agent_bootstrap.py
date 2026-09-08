"""Agent bootstrap — seed real agents into the ATAR trust network.

This is the glue that turns ATAR from a demo into *your* system. Each of
your agents (a primary agent, a reporting cron, a research agent, ...) gets
a persistent ``did:key`` and can vouch for others. Vouches land in the
persistent store (Phase 7), so the Know-Your-Agent dashboard reflects a real,
durable network.

No server, no cost. Each agent's key lives under $ATAR_HOME/agents/<name>.json.
The trust root (seed) is whichever agent you designate (typically your primary).

Usage:
    reg = AgentRegistry()
    reg.register("seed_agent")
    seed_trust_root("seed_agent")
    reg.register("reporting_agent")
    reg.vouch("seed_agent", "reporting_agent", score=0.95, scope="intelligence")
"""

from __future__ import annotations

import json
import os

from .identity import generate_identity, did_from_public, Identity
from .vouch import create_vouch
from .store import VouchStore
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _home() -> str:
    return os.environ.get("ATAR_HOME", os.path.join(os.path.expanduser("~"), ".atar"))


def _agents_dir() -> str:
    d = os.path.join(_home(), "agents")
    os.makedirs(d, exist_ok=True)
    return d


def _store_path() -> str:
    return os.path.join(_home(), "vouches.json")


def _identity_from_private_hex(hex_str: str) -> Identity:
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(hex_str))
    return Identity(private_key=priv, public_key=priv.public_key())


def known_agent_names() -> dict[str, str]:
    """name -> DID for every locally known agent.

    Merges the bootstrap registry (agents/registry.json) with the plain CLI
    identities in keys.json, so dashboards and the live server can name
    agents created with a bare `atar keygen` too — before this, a CLI-only
    network rendered every agent as "?". The registry wins on name conflicts
    (it is the curated bootstrap source). Never raises: dashboards degrade
    to "?" instead of failing.
    """
    names: dict[str, str] = {}
    keys_path = os.path.join(_home(), "keys.json")
    try:
        if os.path.exists(keys_path):
            with open(keys_path, "r", encoding="utf-8") as f:
                for n, rec in json.load(f).items():
                    if isinstance(rec, dict) and isinstance(rec.get("did"), str):
                        names[n] = rec["did"]
    except (json.JSONDecodeError, OSError):
        pass
    try:
        reg = AgentRegistry()
        for n, d in reg._agents.items():
            if n != "_seed" and isinstance(d, dict) and isinstance(d.get("did"), str):
                names[n] = d["did"]
    except Exception:
        pass
    return names


class AgentRegistry:
    """Manage persistent agent identities + vouches for your local network."""

    def __init__(self) -> None:
        self._agents_file = os.path.join(_agents_dir(), "registry.json")
        self._agents: dict[str, dict] = self._load()
        self._store = VouchStore(_store_path())
        self.seed_did = self._agents.get("_seed")

    # --- identity management ------------------------------------------------
    def _load(self) -> dict:
        if os.path.exists(self._agents_file):
            with open(self._agents_file, "r", encoding="utf-8") as f:
                return json.load(f)
        return {}

    def _save(self) -> None:
        from .store import atomic_save_json
        atomic_save_json(self._agents, self._agents_file)
        # the registry holds private keys: owner-read/write only
        os.chmod(self._agents_file, 0o600)

    def register(self, name: str) -> str:
        """Create + persist an agent identity; return its DID (stable).

        Reloads under the store's cross-process lock before writing, so two
        concurrent registrations (or a registration racing another registry
        writer) never lose each other's private keys.
        """
        from .store import file_lock
        with file_lock(self._agents_file):
            self._agents = self._load()
            self.seed_did = self._agents.get("_seed")
            if name in self._agents and "did" in self._agents[name]:
                return self._agents[name]["did"]
            ident = generate_identity()
            self._agents[name] = {
                "did": did_from_public(ident.public_key),
                "private": ident.private_key.private_bytes_raw().hex(),
            }
            self._save()
            return self._agents[name]["did"]

    def did_of(self, name: str) -> str | None:
        return self._agents.get(name, {}).get("did")

    def identity_of(self, name: str) -> Identity:
        if name not in self._agents:
            raise KeyError(f"agent '{name}' not registered")
        return _identity_from_private_hex(self._agents[name]["private"])

    # --- trust --------------------------------------------------------------
    def vouch(self, issuer: str, subject: str, *, score: float, scope: str) -> bool:
        """Issuer agent vouches for subject agent; stored persistently."""
        iss = self.identity_of(issuer)
        subj_did = self.did_of(subject)
        if subj_did is None:
            return False
        subj_pub = _identity_from_private_hex(
            self._agents[subject]["private"]
        ).public_key
        v = create_vouch(iss, subj_pub, score=score, scope=scope)
        return self._store.add(v)

    def build_network(self, *, scope: str) -> dict:
        """Assemble a network dict usable by dashboard_data / graph."""
        return {
            "agents": {n: d["did"] for n, d in self._agents.items() if n != "_seed"},
            "seed_did": self.seed_did or "",
            "vouches": self._store.all(),
        }


def seed_trust_root(name: str) -> str:
    """Designate an agent as the trusted seed (root of the web-of-trust)."""
    from .store import file_lock
    reg = AgentRegistry()
    did = reg.register(name)
    with file_lock(reg._agents_file):
        reg._agents = reg._load()
        reg._agents["_seed"] = did
        reg._save()
    reg.seed_did = did
    return did
