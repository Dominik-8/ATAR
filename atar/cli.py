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


@cli.command()
@click.option("--seed", required=True, help="trusted seed DID to compute trust from")
@click.option("--scope", required=True, help="capability scope to evaluate")
@click.option("--home", "home", default=None, help="override ATAR_HOME (vouch store)")
def graph(seed: str, scope: str, home: str | None):
    """Compute transitive trust from a seed DID over all locally stored vouches.

    Loads every *.json vouch in $ATAR_HOME, builds a TrustGraph, and prints a
    ranked report of every reachable agent and its trust score.
    """
    if home:
        os.environ["ATAR_HOME"] = home
    from .transparency import TrustGraph
    g = TrustGraph()
    loaded = 0
    for fn in os.listdir(_home()):
        if not fn.endswith(".json") or fn == "keys.json":
            continue
        try:
            with open(os.path.join(_home(), fn), "r", encoding="utf-8") as f:
                blob = json.load(f)
            if g.add(blob):
                loaded += 1
        except (json.JSONDecodeError, KeyError):
            continue
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

    Builds a TrustGraph from every *.json vouch in $ATAR_HOME, computes transitive
    trust from SEED, and writes a standalone HTML page (no server needed).
    """
    if home:
        os.environ["ATAR_HOME"] = home
    from .transparency import TrustGraph
    from .dashboard import render_dashboard_html

    g = TrustGraph()
    loaded = 0
    for fn in os.listdir(_home()):
        if not fn.endswith(".json") or fn == "keys.json":
            continue
        try:
            with open(os.path.join(_home(), fn), "r", encoding="utf-8") as f:
                blob = json.load(f)
            if g.add(blob):
                loaded += 1
        except (json.JSONDecodeError, KeyError):
            continue
    net = {"agents": {}, "seed_did": seed, "vouches": g.all_vouches()}
    html = render_dashboard_html(net, scope=scope)
    with open(out, "w", encoding="utf-8") as f:
        f.write(html)
    click.echo(f"dashboard written to {out} ({loaded} vouches, scope={scope})")


if __name__ == "__main__":
    cli()
