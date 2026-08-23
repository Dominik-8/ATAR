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
    for_did = for_did.strip()  # tolerate CRLF / trailing whitespace from pipes
    if not for_did.startswith("did:agent:"):
        click.echo(f"invalid subject DID (expected did:agent:...): {for_did!r}")
        sys.exit(2)
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
@click.option("--max-age", "max_age", default=None, type=int,
              help="reject vouches older than N seconds (freshness/TTL). "
                   "Default: trust never expires unless revoked.")
def verify(path: str, max_age):
    """Verify a vouch blob file. Prints VALID, REVOKED, EXPIRED, or INVALID.

    A vouch is VALID only if its signature checks out, it is not on the local
    revocation list (Phase 16/17/22), AND — when --max-age is given — it is not
    older than that many seconds (Phase 24 freshness). Revocation kills trust
    actively; freshness lets stale trust decay so the graph stays alive.
    """
    from .freshness import is_fresh, VOUCH_TTL_DEFAULT
    with open(path, "r", encoding="utf-8") as f:
        blob = json.load(f)
    if not verify_vouch(blob):
        click.echo("INVALID")
        sys.exit(1)
    # revocation awareness (Phase 16/17/22)
    try:
        from .revocation import RevocationList, revoke_payload_id
        rl = RevocationList.load(_revocations_path())
        if rl.is_revoked(revoke_payload_id(blob)):
            click.echo("REVOKED")
            sys.exit(2)
    except FileNotFoundError:
        # no revocation list yet — nothing to check
        pass
    # freshness (Phase 24): if a max-age is set, reject stale vouches
    if max_age is not None and not is_fresh(blob, ttl=max_age):
        click.echo("EXPIRED")
        sys.exit(1)
    click.echo("VALID")


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
    """Verify every vouch inside an agent card. Prints a report (flags revoked)."""
    with open(path, "r", encoding="utf-8") as f:
        card_doc = json.load(f)
    report = verify_agent_card(card_doc)
    click.echo(f"agent : {report['name']} ({report['did']})")
    click.echo(f"valid vouches   : {len(report['valid_vouches'])}")
    click.echo(f"invalid vouches : {len(report['invalid_vouches'])}")
    # revocation awareness (Phase 22): flag any vouch on the local revocation list
    try:
        from .revocation import RevocationList, revoke_payload_id
        rl = RevocationList.load(_revocations_path())
        revoked = [v for v in report["valid_vouches"]
                   if rl.is_revoked(revoke_payload_id(v))]
    except FileNotFoundError:
        # no revocation list yet — nothing to check
        revoked = []
    if revoked:
        click.echo(f"REVOKED vouches  : {len(revoked)}")
        for v in revoked:
            click.echo(f"   - {v['payload']['issuer']} -> {v['payload']['subject']}")
        sys.exit(2)
    if report["invalid_vouches"]:
        sys.exit(1)


@cli.command()
@click.option("--from", "from_name", required=True, help="issuer identity name")
@click.option("--for", "for_did", required=True, help="subject agent DID")
@click.option("--scope", required=True, help="capability scope, e.g. coding")
@click.option("--score", type=float, required=True, help="trust score 0..1")
@click.option("--claim", default="", help="free-text capability claim about the subject")
@click.option("--out", default="claim.json", help="output file")
def issue(from_name: str, for_did: str, scope: str, score: float, claim: str, out: str):
    """Phase 26 — issue a signed capability claim about a subject DID.

    Like `vouch` but carries a free-text claim and is written to a standalone
    file (not the store) so any agent can issue/verify it peer-to-peer.
    """
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
    from base58 import b58decode
    for_did = for_did.strip()  # tolerate CRLF / trailing whitespace from pipes
    if not for_did.startswith("did:agent:"):
        click.echo(f"invalid subject DID (expected did:agent:...): {for_did!r}")
        sys.exit(2)
    keys = _load_keys()
    if from_name not in keys:
        click.echo(f"no identity '{from_name}'"); sys.exit(1)
    priv = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys[from_name]["private"]))
    from .identity import Identity
    issuer = Identity(private_key=priv, public_key=priv.public_key())
    # reconstruct subject public key from DID
    raw = b58decode(for_did[len("did:agent:"):])
    subject_pub = Ed25519PublicKey.from_public_bytes(raw)
    blob = create_vouch(issuer, subject_pub, score=score, scope=scope, claim=claim)
    with open(out, "w", encoding="utf-8") as f:
        json.dump(blob, f, indent=2)
    click.echo(f"claim issued -> {out}")
    click.echo(f"  issuer  : {blob['payload']['issuer']}")
    click.echo(f"  subject : {for_did}")
    click.echo(f"  scope   : {scope}  score={score}")


@cli.command()
@click.argument("path")
def verify_claim(path: str):
    """Phase 26 — verify a signed capability claim (independent of the store)."""
    with open(path, "r", encoding="utf-8") as f:
        blob = json.load(f)
    if verify_vouch(blob):
        payload = blob.get("payload", {})
        click.echo("VALID")
        click.echo(f"  issuer  : {payload.get('issuer')}")
        click.echo(f"  subject : {payload.get('subject')}")
        click.echo(f"  scope   : {payload.get('scope')}  score={payload.get('score')}")
        if payload.get("claim"):
            click.echo(f"  claim   : {payload.get('claim')}")
    else:
        click.echo("INVALID")
        sys.exit(1)


def _load_store_vouches() -> list[dict]:
    """Load all vouches from the persistent store (Phase 7)."""
    from .store import VouchStore
    return VouchStore(_store_path()).all()


def _default_seed():
    """Return the DID of the seeded agent in the registry, or None."""
    try:
        from .agent_bootstrap import AgentRegistry
        reg = AgentRegistry()
        if reg.seed_did:
            return reg.seed_did
    except Exception:
        pass
    return None


@cli.command()
@click.option("--seed", default=None, help="trusted seed DID (default: the seeded agent from the registry)")
@click.option("--scope", default="intelligence", help="capability scope to evaluate")
@click.option("--home", "home", default=None, help="override ATAR_HOME (vouch store)")
def graph(seed: str | None, scope: str, home: str | None):
    """Compute transitive trust from a seed DID over all locally stored vouches.

    Reads the persistent vouch store ($ATAR_HOME/vouches.json), builds a
    TrustGraph, and prints a ranked report of every reachable agent. If --seed
    is omitted, the seeded agent from the registry is used.
    """
    if home:
        os.environ["ATAR_HOME"] = home
    seed = seed or _default_seed()
    if not seed:
        raise SystemExit("no --seed given and no seeded agent in registry")
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
@click.option("--seed", default=None, help="trusted seed DID (default: the seeded agent from the registry)")
@click.option("--scope", default="intelligence", help="capability scope to render")
@click.option("--out", default="atar-dashboard.html", help="output HTML file")
@click.option("--home", "home", default=None, help="override ATAR_HOME (vouch store)")
def dashboard(seed: str | None, scope: str, out: str, home: str | None):
    """Render the Know-Your-Agent dashboard (ATAR dark design) from local vouches.

    Reads the persistent vouch store, computes transitive trust from SEED, and
    writes a standalone HTML page (no server needed). If --seed is omitted, the
    seeded agent from the registry is used.
    """
    if home:
        os.environ["ATAR_HOME"] = home
    seed = seed or _default_seed()
    if not seed:
        raise SystemExit("no --seed given and no seeded agent in registry")
    from .dashboard import render_dashboard_html
    from .agent_bootstrap import AgentRegistry
    try:
        reg = AgentRegistry()
        agents = {n: d["did"] for n, d in reg._agents.items() if n != "_seed"}
    except Exception:
        agents = {}
    net = {"agents": agents, "seed_did": seed, "vouches": _load_store_vouches()}
    html = render_dashboard_html(net, scope=scope)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    click.echo(f"dashboard written to {out} ({len(net['vouches'])} vouches, scope={scope})")


def _store_path() -> str:
    return os.path.join(_home(), "vouches.json")


@cli.command()
@click.argument("path")
def add(path: str):
    """Add a vouch blob file to the persistent local store (dedup + verify).

    Rejects invalid, duplicate, OR revoked vouches — a revoked vouch (even with a
    still-valid signature) is never admitted to the store. This is defense-in-depth:
    revocation is enforced at the insertion point, not just at verify time.
    """
    from .store import VouchStore
    with open(path, "r", encoding="utf-8") as f:
        blob = json.load(f)
    # revocation check BEFORE admitting to the store
    try:
        from .revocation import RevocationList, revoke_payload_id
        rl = RevocationList.load(_revocations_path())
        if rl.is_revoked(revoke_payload_id(blob)):
            click.echo("rejected (vouch is REVOKED)")
            sys.exit(1)
    except Exception:
        pass
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
    from .revocation import RevocationList
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
    self_rl = RevocationList.load(_revocations_path())
    before = self_store.count()
    total_new = 0
    rev_new = 0
    for p in peers:
        if not os.path.isdir(p):
            click.echo(f"  (peer {p}: dir missing, skipped)")
            continue
        peer_store = VouchStore(os.path.join(p, "vouches.json"))
        peer_rl = RevocationList.load(os.path.join(p, "revocations.json"))
        # pull vouches, but skip any that are revoked (defense-in-depth)
        added_self = 0
        for v in peer_store.all():
            from .revocation import revoke_payload_id as _rid
            if self_rl.is_revoked(_rid(v)):
                continue
            if self_store.add(v):
                added_self += 1
        added_peer = sum(1 for v in self_store.all() if peer_store.add(v))
        added_rev_self = sum(1 for e in peer_rl.all()
                             if self_rl.add(e["revoked_by"], e["vid"], e["ts"], e["signature"]))
        added_rev_peer = sum(1 for e in self_rl.all()
                             if peer_rl.add(e["revoked_by"], e["vid"], e["ts"], e["signature"]))
        peer_rl.save(os.path.join(p, "revocations.json"))
        self_rl.save(_revocations_path())
        total_new += added_self
        rev_new += added_rev_self
        click.echo(f"  synced {p}: +{added_self} vouches, +{added_rev_self} revocations "
                   f"(to peer: +{added_peer} vouches, +{added_rev_peer} revocations)")
    after = self_store.count()
    click.echo(f"auto-sync done: {before} -> {after} vouches ({total_new} new), "
               f"{rev_new} new revocation(s)")


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
    from .revocation import RevocationList
    self_path = _store_path()
    self_store = VouchStore(self_path)
    self_rl = RevocationList.load(_revocations_path())
    before = self_store.count()
    total_in = 0
    rev_in = 0
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
        added_peer = 0
        for v in self_store.all():
            if peer_store.add(v):
                added_peer += 1
        # --- revocation gossip (Phase 17): exchange revocation lists too ---
        peer_rl = RevocationList.load(os.path.join(p, "revocations.json"))
        added_rev_self = 0
        for e in peer_rl.all():
            if self_rl.add(e["revoked_by"], e["vid"], e["ts"], e["signature"]):
                added_rev_self += 1
        added_rev_peer = 0
        for e in self_rl.all():
            if peer_rl.add(e["revoked_by"], e["vid"], e["ts"], e["signature"]):
                added_rev_peer += 1
        peer_rl.save(os.path.join(p, "revocations.json"))
        self_rl.save(_revocations_path())
        rev_in += added_rev_self
        total_in += added_to_self
        click.echo(f"  synced {p}: +{added_to_self} vouches, +{added_rev_self} revocations "
                   f"(to peer: +{added_peer} vouches, +{added_rev_peer} revocations)")
    after = self_store.count()
    click.echo(f"sync done: {before} -> {after} vouches ({total_in} new), "
               f"{rev_in} new revocation(s)")


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
def scopes():
    """List all trust scopes in your network with their agent counts.

    A scope is a capability domain (e.g. coding, intelligence, finance). An agent
    may be trusted in one scope but unknown in another — this shows the shape of
    your trust graph at a glance, without rendering the full dashboard.
    """
    from .store import VouchStore
    from .dashboard import dashboard_data
    from .agent_bootstrap import AgentRegistry
    store = VouchStore(_store_path())
    if not store.all():
        click.echo("no vouches yet — network is empty")
        return
    # collect all scopes present in the vouches
    scope_set = sorted({v["payload"].get("scope") for v in store.all()
                        if v["payload"].get("scope")})
    reg = AgentRegistry()
    click.echo(f"scopes in network: {len(scope_set)}")
    for scope in scope_set:
        net = reg.build_network(scope=scope)
        data = dashboard_data(net, scope=scope)
        # count reachable agents (exclude the seed itself from the "agents" count? keep all)
        n = len(data["agents"])
        click.echo(f"  • {scope:14s} {n} agent(s)")
    click.echo("(use `atar dashboard --scope <name>` for the full view)")


@cli.command()
@click.option("--name", required=True, help="identity name to rotate")
@click.option("--out", default="rotation.json", help="rotation statement output file")
def rotate(name: str, out: str):
    """Rotate an agent's key: generate a NEW key, bind it to the old one, and
    emit a signed rotation statement (old key signs 'I am now <newdid>').

    After rotation: re-issue out-going vouches with `atar reissue`, then revoke
    the old key. Trust carries forward under the new DID — no total loss.
    """
    from .rotation import rotate_identity, verify_rotation
    keys = _load_keys()
    if name not in keys:
        click.echo(f"no identity '{name}'"); sys.exit(1)
    old = _identity_from_name(name)  # Ed25519PrivateKey
    new = generate_identity()
    stmt = rotate_identity(old, new)
    # persist the new key under the same name (replaces old)
    keys[name] = {
        "did": did_from_public(new.public_key),
        "public": new.public_key.public_bytes_raw().hex(),
        "private": new.private_key.private_bytes_raw().hex(),
        "rotated_from": did_from_public(old.public_key()),
    }
    _save_keys(keys)
    out_path = os.path.join(_home(), out)
    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(stmt.to_dict(), f, indent=2)
    assert verify_rotation(stmt)
    click.echo(f"rotated '{name}': old {stmt.old_did[:20]}... -> new {stmt.new_did[:20]}...")
    click.echo(f"rotation statement written to {out_path}")
    click.echo("next: atar reissue --name " + name + "  then  atar revoke (old vouches)")


@cli.command()
@click.option("--name", required=True, help="identity name whose vouches to re-issue")
@click.option("--scope", default=None, help="re-issue only this scope (default: all)")
@click.option("--out", default="reissued.json", help="output file (JSON list)")
@click.option("--commit", is_flag=True, help="write re-issued vouches to the store AND "
              "revoke the old-key (pre-rotation) vouches — closes the rotation loop")
def reissue(name: str, scope: str | None, out: str, commit: bool):
    """Re-sign this agent's out-going vouches under its CURRENT (post-rotation)
    key with fresh timestamps (Phase 24). Preserves score/scope/subject.

    Use after `atar rotate` to carry trust forward under the new DID. With
    --commit, the re-issued vouches are written to the store and the old-key
    (pre-rotation) vouches are revoked — the rotation is then complete and the
    old key can be considered fully retired.
    """
    from .rotation import reissue_vouch
    from .store import VouchStore
    from .revocation import RevocationList, revoke_payload_id
    new_id = _identity_from_name(name)  # Ed25519PrivateKey (post-rotation)
    store = VouchStore(_store_path())
    my_did = did_from_public(new_id.public_key())
    # The vouches in the store were issued under the OLD did (pre-rotation).
    # We find them by the OLD issuer (recorded as rotated_from) and re-sign
    # them under the NEW key.
    keys = _load_keys()
    old_did = keys.get(name, {}).get("rotated_from")
    reissued = []
    old_vouches = []
    for v in store.all():
        issuer = v["payload"]["issuer"]
        # match either the old issuer (pre-rotation vouches) or already-new
        if old_did and issuer != old_did and issuer != my_did:
            continue
        if scope and v["payload"].get("scope") != scope:
            continue
        r = reissue_vouch(new_id, new_id, v)  # re-sign under the new key
        reissued.append(r)
        if issuer == old_did:
            old_vouches.append(v)
    with open(os.path.join(_home(), out), "w", encoding="utf-8") as f:
        json.dump(reissued, f, indent=2)
    click.echo(f"re-issued {len(reissued)} vouch(es) under {my_did[:20]}... -> {os.path.join(_home(), out)}")
    if not commit:
        return
    # commit: add re-issued vouches + revoke the old-key ones
    added = sum(1 for r in reissued if store.add(r))
    rl = RevocationList.load(_revocations_path())
    revoked = 0
    for v in old_vouches:
        vid = revoke_payload_id(v)
        if not rl.is_revoked(vid):
            rl.entries[vid] = {
                "vid": vid,
                "revoked_by": old_did or my_did,
                "ts": int(__import__("time").time()),
                "signature": "",
            }
            revoked += 1
    rl.save(_revocations_path())
    click.echo(f"committed: +{added} re-issued vouch(es) to store, {revoked} old-key vouch(es) revoked")
    click.echo("rotation complete — old key fully retired, trust carried under new DID")


@cli.command()
@click.option("--out", default="atar-network.atpkg", help="output bundle file")
@click.option("--include-keys", is_flag=True,
              help="ALSO bundle private keys (for full migration). "
                   "NEVER share the result — it contains secrets.")
def export(out: str, include_keys: bool):
    """Export your trust network as a portable bundle (.atpkg).

    By default this contains only the *trust graph* — vouches + revocations +
    registry (who vouched for whom). Your private keys stay local. Use
    --include-keys only for a full migration to another machine, and treat the
    resulting file as a secret.
    """
    from .store import VouchStore
    from .revocation import RevocationList
    from .agent_bootstrap import AgentRegistry
    store = VouchStore(_store_path())
    rl = RevocationList.load(_revocations_path())
    bundle = {
        "format": "atar-network/1.0",
        "vouches": store.all(),
        "revocations": rl.all(),
    }
    if include_keys:
        try:
            bundle["keys"] = _load_keys()
        except Exception:
            pass
    else:
        # still record agent names so imports rebuild the registry
        try:
            reg = AgentRegistry()
            bundle["agents"] = {n: d["did"] for n, d in reg._agents.items()
                                 if n != "_seed"}
        except Exception:
            bundle["agents"] = {}
    with open(out, "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)
    click.echo(f"exported {len(bundle['vouches'])} vouch(es), "
               f"{len(bundle['revocations'])} revocation(s) -> {out}"
               + (" (WITH PRIVATE KEYS — keep secret)" if include_keys else ""))


@cli.command()
@click.argument("bundle")
@click.option("--force", is_flag=True, help="overwrite existing store entries")
def import_cmd(bundle: str, force: bool):
    """Import a trust network bundle (.atpkg) exported by `atar export`.

    Restores vouches + revocations into your local store. Private keys are
    imported only if the bundle contains them (--include-keys export).
    """
    from .store import VouchStore
    from .revocation import RevocationList, revoke_payload_id
    with open(bundle, "r", encoding="utf-8") as f:
        data = json.load(f)
    store = VouchStore(_store_path())
    added = 0
    for v in data.get("vouches", []):
        if force or store.add(v):
            added += 1
    rl = RevocationList.load(_revocations_path())
    revoked = 0
    for e in data.get("revocations", []):
        if not rl.is_revoked(e["vid"]):
            rl.entries[e["vid"]] = e
            revoked += 1
    rl.save(_revocations_path())
    # restore keys if present
    keys_restored = 0
    if "keys" in data:
        keys = _load_keys()
        for name, k in data["keys"].items():
            if name not in keys or force:
                keys[name] = k
                keys_restored += 1
        _save_keys(keys)
    click.echo(f"imported {added} vouch(es), {revoked} revocation(s)"
               + (f", {keys_restored} key(s)" if keys_restored else ""))


def _audit_state(max_age):
    """Compute the trust-network health state dict (shared by audit + watch)."""
    from .store import VouchStore
    from .revocation import RevocationList, revoke_payload_id
    from .freshness import is_fresh
    store = VouchStore(_store_path())
    vouches = store.all()
    rl = RevocationList.load(_revocations_path())

    valid = revoked = expired = invalid = 0
    by_scope = {}
    for v in vouches:
        scope = v["payload"].get("scope", "?")
        by_scope.setdefault(scope, {"valid": 0, "revoked": 0, "expired": 0, "invalid": 0})
        if not verify_vouch(v):
            invalid += 1
            by_scope[scope]["invalid"] += 1
            continue
        if rl.is_revoked(revoke_payload_id(v)):
            revoked += 1
            by_scope[scope]["revoked"] += 1
            continue
        if max_age is not None and not is_fresh(v, ttl=max_age):
            expired += 1
            by_scope[scope]["expired"] += 1
            continue
        valid += 1
        by_scope[scope]["valid"] += 1
    return {
        "total": len(vouches), "valid": valid, "revoked": revoked,
        "expired": expired, "invalid": invalid, "by_scope": by_scope,
        "healthy": not (revoked or expired or invalid),
    }


@cli.command()
@click.option("--max-age", "max_age", default=None, type=int,
              help="treat vouches older than N seconds as EXPIRED (default: off)")
def audit(max_age):
    """Health-check your local trust network.

    Scans every vouch in the store and reports counts by state:
    valid / revoked / expired / invalid — plus a per-scope breakdown. This is
    the operator's "trust graph status" command: one glance shows whether your
    network is healthy (all valid) or has stale/revoked edges to clean up.
    """
    st = _audit_state(max_age)
    click.echo(f"ATAR trust audit — {st['total']} vouch(es) in store")
    click.echo(f"  valid   : {st['valid']}")
    click.echo(f"  revoked : {st['revoked']}")
    click.echo(f"  expired : {st['expired']}" + (f" (max-age={max_age}s)" if max_age else " (max-age off)"))
    click.echo(f"  invalid : {st['invalid']}")
    if st["by_scope"]:
        click.echo("  by scope:")
        for scope, c in sorted(st["by_scope"].items()):
            click.echo(f"    {scope:14s} valid={c['valid']} revoked={c['revoked']} "
                       f"expired={c['expired']} invalid={c['invalid']}")
    # non-zero revoked/expired/invalid => unhealthy (exit 2), else 0
    if not st["healthy"]:
        sys.exit(2)


@cli.command()
@click.option("--interval", default=3600, type=int,
              help="seconds between checks (default: 3600 = 1h)")
@click.option("--max-age", "max_age", default=None, type=int,
              help="treat vouches older than N seconds as EXPIRED")
@click.option("--once", is_flag=True, help="run a single check and exit (for cron)")
def watch(interval: int, max_age: int | None, once: bool):
    """Continuously monitor your trust network and ALERT on unhealthy transitions.

    Runs `audit` every --interval seconds. When the network goes from healthy to
    unhealthy (a vouch expires, is revoked, or becomes invalid), it prints an
    ALERT line — ideal for piping into a log or alerting cron job. With --once it
    performs a single check and exits (exit 2 if unhealthy) — use that in a
    crontab: `atar watch --once || notify-send "ATAR network unhealthy"`.
    """
    import time as _time

    def check() -> bool:
        st = _audit_state(max_age)
        if st["healthy"]:
            click.echo(f"[{_time.strftime('%H:%M:%S')}] healthy — "
                       f"{st['valid']} valid, {st['total']} total")
            return True
        click.echo(f"[{_time.strftime('%H:%M:%S')}] ALERT: network UNHEALTHY — "
                   f"valid={st['valid']} revoked={st['revoked']} "
                   f"expired={st['expired']} invalid={st['invalid']}", err=True)
        return False

    if once:
        healthy = check()
        sys.exit(0 if healthy else 2)

    click.echo(f"atar watch: monitoring every {interval}s (Ctrl+C to stop)")
    prev = None
    try:
        while True:
            healthy = check()
            # alert on transition healthy -> unhealthy only (avoid spam)
            if prev is not None and prev and not healthy:
                click.echo("ALERT: trust network became UNHEALTHY", err=True)
            prev = healthy
            _time.sleep(interval)
    except KeyboardInterrupt:
        click.echo("atar watch stopped")


@cli.command()
@click.option("--port", default=8765, help="port to serve on (localhost only)")
def serve(port: int):
    """Serve the live Know-Your-Agent dashboard at http://localhost:PORT.

    Local only (binds 127.0.0.1), no external exposure, no cost. Re-renders
    from the persistent store on every request.
    """
    from .web import run_server
    run_server(port=port)


@cli.command()
@click.argument("vouch_file")
def revoke(vouch_file: str):
    """Revoke a vouch by its issuer (writes to the local revocation list).

    VOUCH_FILE is a vouch blob (JSON) whose issuer key you control. The revocation
    is signed by that issuer and appended to $ATAR_HOME/revocations.json. Any
    verify that consults the revocation list will then reject the vouch — even
    though its original signature is still valid. This is how a leaked/malicious
    agent key is neutralized without changing the protocol.
    """
    from .revocation import RevocationList, revoke_vouch, revoke_payload_id
    with open(vouch_file, "r", encoding="utf-8") as f:
        v = json.load(f)
    issuer_did = v["payload"]["issuer"]
    keys = _load_keys()
    # find the agent name owning this DID so we can sign with its key
    name = next((n for n, d in keys.items() if d.get("did") == issuer_did), None)
    if name is None:
        click.echo(f"revoke failed: no local key for issuer {issuer_did}", err=True)
        sys.exit(1)
    priv = _identity_from_name(name)
    # rebuild an Identity from the private key
    from .identity import Identity
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
    ident = Identity(private_key=priv, public_key=priv.public_key())
    rlist = RevocationList.load(_revocations_path())
    if revoke_vouch(rlist, ident, revoke_payload_id(v)):
        rlist.save(_revocations_path())
        click.echo(f"revoked vouch {revoke_payload_id(v)} (by {issuer_did})")
    else:
        click.echo("revocation already present (or invalid)")


def _revocations_path() -> str:
    return os.path.join(_home(), "revocations.json")


if __name__ == "__main__":
    cli()
