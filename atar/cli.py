"""Command-line interface for the ATAR protocol.

Usage:
    atar keygen [--name NAME]          # create an agent identity, print its DID
    atar vouch --from NAME --for DID   # issuer vouches for subject DID
            --score F --scope STR
    atar verify PATH                    # verify a vouch blob file

Keys are stored locally under $ATAR_HOME (default ~/.atar) as keys.json.
"""

from __future__ import annotations

import json
import os
import sys

import click

from .identity import generate_identity, did_from_public
from .vouch import create_vouch, verify_vouch
from .atc import make_agent_card, verify_agent_card, vouch_to_token


def _home() -> str:
    return os.environ.get("ATAR_HOME", os.path.join(os.path.expanduser("~"), ".atar"))


def _keys_path() -> str:
    return os.path.join(_home(), "keys.json")


def _load_keys() -> dict:
    p = _keys_path()
    if not os.path.exists(p):
        return {}
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def _save_keys(keys: dict) -> None:
    os.makedirs(_home(), exist_ok=True)
    with open(_keys_path(), "w", encoding="utf-8") as f:
        json.dump(keys, f, indent=2)


def _identity_from_name(name: str):
    keys = _load_keys()
    if name not in keys:
        click.echo(f"no identity named '{name}'. Create one with: atar keygen --name {name}")
        sys.exit(1)
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys[name]["private"]))
    return priv


@click.group()
def cli():
    """ATAR — Agent Trust & Attribution Root (decentralized agent ID)."""


@cli.command()
@click.option("--name", default="default", help="label for this identity")
def keygen(name: str):
    """Generate a new agent identity and print its DID."""
    ident = generate_identity()
    priv_hex = ident.private_key.private_bytes_raw().hex()
    keys = _load_keys()
    keys[name] = {"private": priv_hex, "did": did_from_public(ident.public_key)}
    _save_keys(keys)
    click.echo(did_from_public(ident.public_key))


@cli.command()
@click.option("--from", "from_name", required=True, help="issuer identity name")
@click.option("--for", "for_did", required=True, help="subject agent DID")
@click.option("--score", type=float, required=True, help="trust score 0..1")
@click.option("--scope", required=True, help="capability scope, e.g. coding")
@click.option("--out", default="vouch.json", help="output file")
def vouch(from_name: str, for_did: str, score: float, scope: str, out: str):
    """Create a signed vouch from one identity for a subject DID."""
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from base58 import b58decode
    keys = _load_keys()
    if from_name not in keys:
        click.echo(f"no identity '{from_name}'"); sys.exit(1)
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys[from_name]["private"]))
    from .identity import Identity, did_from_public
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    issuer = Identity(private_key=priv, public_key=priv.public_key())
    # reconstruct subject public key from DID
    raw = b58decode(for_did[len("did:agent:"):])
    subject_pub = Ed25519PublicKey.from_public_bytes(raw)
    blob = create_vouch(issuer, subject_pub, score=score, scope=scope)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(blob, f, indent=2)
    click.echo(f"vouch written to {out}")


@cli.command()
@click.argument("path")
def verify(path: str):
    """Verify a vouch blob file. Prints VALID or INVALID."""
    with open(path, "r", encoding="utf-8") as f:
        blob = json.load(f)
    if verify_vouch(blob):
        click.echo("VALID")
    else:
        click.echo("INVALID")
        sys.exit(1)


@cli.command()
@click.option("--name", required=True, help="identity name to build the card for")
@click.option("--out", default="agent-card.json", help="output file")
def card(name: str, out: str):
    """Build an agent card (DID + name + all stored vouches for this DID)."""
    keys = _load_keys()
    if name not in keys:
        click.echo(f"no identity '{name}'"); sys.exit(1)
    did = keys[name]["did"]
    # collect vouches stored locally where subject == this DID
    vouches = []
    for fn in os.listdir(_home()):
        if fn.endswith(".json") and fn != "keys.json":
            try:
                with open(os.path.join(_home(), fn), "r", encoding="utf-8") as f:
                    blob = json.load(f)
                if blob.get("payload", {}).get("subject") == did:
                    vouches.append(blob)
            except (json.JSONDecodeError, KeyError):
                continue
    card_doc = make_agent_card(did=did, name=name, vouches=vouches)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(card_doc, f, indent=2)
    click.echo(f"agent card written to {out} ({len(vouches)} vouch(es))")


@cli.command()
@click.argument("path")
def verify_card(path: str):
    """Verify every vouch inside an agent card. Prints a report."""
    with open(path, "r", encoding="utf-8") as f:
        card_doc = json.load(f)
    report = verify_agent_card(card_doc)
    click.echo(f"agent : {report['name']} ({report['did']})")
    click.echo(f"valid vouches   : {len(report['valid_vouches'])}")
    click.echo(f"invalid vouches : {len(report['invalid_vouches'])}")
    if report["invalid_vouches"]:
        sys.exit(1)


def _load_store_vouches() -> list[dict]:
    """Load all vouches from the persistent store (Phase 7)."""
    from .store import VouchStore
    return VouchStore(_store_path()).all()


@cli.command()
@click.option("--seed", required=True, help="trusted seed DID to compute trust from")
@click.option("--scope", required=True, help="capability scope to evaluate")
@click.option("--home", "home", default=None, help="override ATAR_HOME (vouch store)")
def graph(seed: str, scope: str, home: str | None):
    """Compute transitive trust from a seed DID over all locally stored vouches.

    Reads the persistent vouch store ($ATAR_HOME/vouches.json), builds a
    TrustGraph, and prints a ranked report of every reachable agent.
    """
    if home:
        os.environ["ATAR_HOME"] = home
    from .transparency import TrustGraph
    g = TrustGraph()
    for v in _load_store_vouches():
        g.add(v)
    loaded = len(g.all_vouches())
    trust = g.compute_trust(seed_did=seed, scope=scope)
    ranked = sorted(trust.items(), key=lambda kv: kv[1], reverse=True)
    click.echo(f"seed  : {seed}")
    click.echo(f"scope : {scope}")
    click.echo(f"vouches loaded : {loaded}")
    click.echo(f"reachable agents: {len(ranked)}")
    click.echo("--- trust ranking ---")
    for did, score in ranked:
        marker = " (seed)" if did == seed else ""
        click.echo(f"  {did}  trust={score:.3f}{marker}")


@cli.command()
@click.option("--seed", required=True, help="trusted seed DID to compute trust from")
@click.option("--scope", required=True, help="capability scope to evaluate")
@click.option("--out", default="atar-dashboard.html", help="output HTML file")
@click.option("--home", "home", default=None, help="override ATAR_HOME (vouch store)")
def dashboard(seed: str, scope: str, out: str, home: str | None):
    """Render the Know-Your-Agent dashboard (ATAR dark design) from local vouches.

    Reads the persistent vouch store, computes transitive trust from SEED, and
    writes a standalone HTML page (no server needed).
    """
    if home:
        os.environ["ATAR_HOME"] = home
    from .dashboard import render_dashboard_html
    net = {"agents": {}, "seed_did": seed, "vouches": _load_store_vouches()}
    html = render_dashboard_html(net, scope=scope)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    click.echo(f"dashboard written to {out} ({len(net['vouches'])} vouches, scope={scope})")


def _store_path() -> str:
    return os.path.join(_home(), "vouches.json")


@cli.command()
@click.argument("path")
def add(path: str):
    """Add a vouch blob file to the persistent local store (dedup + verify)."""
    from .store import VouchStore
    with open(path, "r", encoding="utf-8") as f:
        blob = json.load(f)
    s = VouchStore(_store_path())
    if s.add(blob):
        click.echo(f"added (store now has {s.count()} vouch(es))")
    else:
        click.echo("rejected (invalid or duplicate vouch)")
        sys.exit(1)


@cli.command()
def list():
    """List all vouches in the persistent local store."""
    from .store import VouchStore
    s = VouchStore(_store_path())
    if not s.all():
        click.echo("store is empty")
        return
    click.echo(f"{s.count()} vouches:")
    for v in s.all():
        p = v["payload"]
        click.echo(f"  {p['issuer']} -> {p['subject']}  "
                    f"score={p['score']} scope={p['scope']}")


@cli.command()
def auto_sync():
    """Gossip with all known peers from atar_peers.json (for cron/agent hooks).

    Reads $ATAR_HOME/atar_peers.json ({"peers": ["/path/to/peer/home", ...]}) and
    runs `sync` against each. Intended to be called automatically after an agent
    produces output (e.g. a ATAR brief), so trust propagates hands-free. Missing
    peer dirs are skipped; an empty/missing peer list is a no-op, not an error.
    """
    from .store import VouchStore
    peers_file = os.path.join(_home(), "atar_peers.json")
    if not os.path.exists(peers_file):
        click.echo("no peers configured (atar_peers.json absent) — nothing to sync")
        return
    try:
        peers = json.load(open(peers_file)).get("peers", [])
    except (json.JSONDecodeError, KeyError):
        click.echo("atar_peers.json malformed — skipped")
        return
    if not peers:
        click.echo("no peers configured — nothing to sync")
        return
    self_store = VouchStore(_store_path())
    before = self_store.count()
    total_new = 0
    for p in peers:
        if not os.path.isdir(p):
            click.echo(f"  (peer {p}: dir missing, skipped)")
            continue
        peer_store = VouchStore(os.path.join(p, "vouches.json"))
        added_self = sum(1 for v in peer_store.all() if self_store.add(v))
        added_peer = sum(1 for v in self_store.all() if peer_store.add(v))
        total_new += added_self
        click.echo(f"  synced {p}: +{added_self} to us, +{added_peer} to peer")
    after = self_store.count()
    click.echo(f"auto-sync done: {before} -> {after} vouches ({total_new} new)")


@cli.command()
@click.option("--with", "peer", required=True, multiple=True,
              help="peer ATAR_HOME directory to exchange vouches with (repeatable)")
def sync(peer):
    """Gossip vouches between local agent stores (decentralized, no server).

    Each agent keeps its own $ATAR_HOME store. `sync` copies any vouch the peer
    has but you don't (and vice versa) into both stores — content-addressed, so
    duplicates are ignored. This is how ATAR stays decentralized: trust spreads
    peer-to-peer without a central operator. Repeatable and idempotent.
    """
    from .store import VouchStore
    self_path = _store_path()
    self_store = VouchStore(self_path)
    before = self_store.count()
    total_in = 0
    for p in peer:
        peer_path = os.path.join(p, "vouches.json")
        # VouchStore creates the file on first add, so a missing peer store is
        # simply empty (not an error) — we just exchange into it.
        peer_store = VouchStore(peer_path)
        # pull: vouches peer has that we lack
        added_to_self = 0
        for v in peer_store.all():
            if self_store.add(v):
                added_to_self += 1
        # push: vouches we have that peer lacks
        added_to_peer = 0
        for v in self_store.all():
            if peer_store.add(v):
                added_to_peer += 1
        total_in += added_to_self
        click.echo(f"  synced {p}: +{added_to_self} to us, +{added_to_peer} to peer")
    after = self_store.count()
    click.echo(f"sync done: {before} -> {after} vouches ({total_in} new)")


@cli.command()
@click.option("--config", required=True, help="TOML file declaring agents + vouches")
def bootstrap(config: str):
    """Build/refresh your agent network from a config file (idempotent).

    The config declares agents (with an optional seed) and vouches between them.
    Re-running is safe: existing identities are kept (DIDs stay stable) and
    vouches are deduplicated. After bootstrap, `atar serve` shows your network.

    Config shape (TOML):
        [[agents]]
        name = "seed_agent"
        seed = true
        [[agents]]
        name = "research"
        [[vouches]]
        issuer = "seed_agent"
        subject = "research"
        score = 0.9
        scope = "intelligence"
    """
    import tomllib
    from .agent_bootstrap import AgentRegistry, seed_trust_root
    with open(config, "rb") as f:
        cfg = tomllib.load(f)
    reg = AgentRegistry()
    seed_name = None
    for a in cfg.get("agents", []):
        reg.register(a["name"])
        if a.get("seed"):
            seed_name = a["name"]
    if seed_name:
        seed_trust_root(seed_name)
        reg = AgentRegistry()  # reload so seed_did is set
    added = 0
    for v in cfg.get("vouches", []):
        if reg.vouch(v["issuer"], v["subject"],
                     score=float(v["score"]), scope=v["scope"]):
            added += 1
    click.echo(f"bootstrap done: {len(reg._agents) - 1} agents, "
               f"{added} new vouch(es) added")
    if seed_name:
        click.echo(f"seed of trust: {reg.did_of(seed_name)}")


@cli.command()
@click.option("--port", default=8765, help="port to serve on (localhost only)")
def serve(port: int):
    """Serve the live Know-Your-Agent dashboard at http://localhost:PORT.

    Local only (binds 127.0.0.1), no external exposure, no cost. Re-renders
    from the persistent store on every request.
    """
    from .web import run_server
    run_server(port=port)


if __name__ == "__main__":
    cli()
