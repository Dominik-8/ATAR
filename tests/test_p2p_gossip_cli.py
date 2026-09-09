"""End-to-end decentralized gossip: two real ATAR homes exchange vouches via
`atar sync --with <peer>` (no server, no central operator).

This is the core "decentralized" claim of ATAR and was only ever covered by
unit tests on the store, never by running the actual sync CLI between two
independent homes. Here we prove:
  - peer A has a vouch B lacks -> after sync, B has it
  - revocation gossip: A revokes, B sees the revocation
  - idempotent: running sync twice doesn't duplicate
"""

import json
import os
import subprocess
import sys
from pathlib import Path


def _atar():
    return [sys.executable, "-m", "atar.cli"]


def _cli(home, *args):
    """Run an atar command in-process (synchronous, no race)."""
    from click.testing import CliRunner

    from atar.cli import cli

    old = os.environ.get("ATAR_HOME")
    os.environ["ATAR_HOME"] = home
    try:
        r = CliRunner().invoke(cli, list(args), catch_exceptions=False)
        return r.exit_code, r.output
    finally:
        if old is None:
            os.environ.pop("ATAR_HOME", None)
        else:
            os.environ["ATAR_HOME"] = old


def _sync_subprocess(home, peer):
    """Run `atar sync` as a REAL subprocess (the CLI command under test)."""
    env = {**os.environ, "ATAR_HOME": home}
    r = subprocess.run(
        [*_atar(), "sync", "--with", peer],
        capture_output=True,
        text=True,
        env=env,
        check=False,
    )
    return r.returncode, r.stdout + r.stderr


def _did(home, name):
    with open(os.path.join(home, "keys.json")) as _f:
        keys = json.load(_f)
    return keys[name]["did"]


def _count(home):
    p = os.path.join(home, "vouches.json")
    if not os.path.exists(p):
        return 0
    return len(json.loads(Path(p).read_text(encoding="utf-8"))["vouches"])


def test_p2p_gossip_between_two_peers(tmp_path):
    a = str(tmp_path / "peerA")
    b = str(tmp_path / "peerB")
    os.makedirs(a)
    os.makedirs(b)

    # in-process (synchronous) setup — no race
    _cli(a, "keygen", "--name", "alpha")
    _cli(b, "keygen", "--name", "beta")
    b_did = _did(b, "beta")

    # A creates + stores a vouch for B
    _cli(
        a,
        "vouch",
        "--from",
        "alpha",
        "--for",
        b_did,
        "--score",
        "0.8",
        "--scope",
        "core",
        "--out",
        os.path.join(a, "v_a.json"),
    )
    _cli(a, "add", os.path.join(a, "v_a.json"))
    # B creates + stores a self-vouch
    _cli(
        b,
        "vouch",
        "--from",
        "beta",
        "--for",
        b_did,
        "--score",
        "0.5",
        "--scope",
        "core",
        "--out",
        os.path.join(b, "v_b.json"),
    )
    _cli(b, "add", os.path.join(b, "v_b.json"))

    assert _count(a) == 1
    assert _count(b) == 1

    # --- REAL CLI gossip: A syncs with B (subprocess) ---
    rc, o = _sync_subprocess(a, b)
    assert rc == 0, o

    ca = _count(a)
    cb = _count(b)
    assert ca == cb, f"stores diverged after sync: A={ca} B={cb}"
    assert ca == 2, f"expected union of 2 vouches, got {ca}"

    # idempotent: sync again, no duplicates
    rc, o = _sync_subprocess(a, b)
    assert rc == 0, o
    assert _count(a) == 2, "sync duplicated vouches"


def test_p2p_revocation_gossip(tmp_path):
    a = str(tmp_path / "peerA")
    b = str(tmp_path / "peerB")
    os.makedirs(a)
    os.makedirs(b)
    _cli(a, "keygen", "--name", "alpha")
    _cli(b, "keygen", "--name", "beta")
    b_did = _did(b, "beta")

    # A vouches for B, syncs to B
    _cli(
        a,
        "vouch",
        "--from",
        "alpha",
        "--for",
        b_did,
        "--score",
        "0.8",
        "--scope",
        "core",
        "--out",
        os.path.join(a, "v.json"),
    )
    _cli(a, "add", os.path.join(a, "v.json"))
    _sync_subprocess(a, b)

    # A revokes, then gossips the revocation list
    _cli(a, "revoke", os.path.join(a, "v.json"))
    _sync_subprocess(a, b)

    rl = os.path.join(b, "revocations.json")
    assert os.path.exists(rl), "revocation did not gossip to peer B"
    assert len(json.loads(Path(rl).read_text(encoding="utf-8"))) >= 1, (
        "revocation list empty on peer B"
    )
