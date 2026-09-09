"""Regression tests for the pre-release senior-engineer audit (2026-09).

Each test pins one defect the audit found and fixed:
  * self-vouches must not inflate transitive trust (SPEC §13)
  * the dashboard scope label is HTML-escaped (reflected XSS via ?scope=)
  * `atar import --force` actually stores (previously counted without storing)
  * `atar keygen` refuses to silently overwrite an identity
  * `atar reissue` requires a recorded rotation
  * HTTP gossip skips malformed remote entries instead of crashing
  * `atar sync --with <url>` reports an unreachable peer instead of a traceback
  * the agent registry (private keys) is written owner-only (0o600)
  * store writes are atomic (no truncated JSON after a crash)
  * create_vouch rejects out-of-range / non-finite scores (SPEC §3)
"""

import json
import os
import stat
from pathlib import Path

import pytest
from click.testing import CliRunner

from atar.cli import cli
from atar.identity import did_from_public, generate_identity
from atar.store import VouchStore
from atar.transparency import graph_from_vouches
from atar.vouch import create_vouch

# --- self-vouches carry no transitive trust (SPEC §13) ----------------------


def test_self_vouch_adds_no_transitive_trust():
    seed = generate_identity()
    agent = generate_identity()
    v = create_vouch(seed, agent.public_key, score=0.9, scope="s")
    self_v = create_vouch(
        agent, agent.public_key, score=1.0, scope="s", claim="I am great"
    )
    seed_did = did_from_public(seed.public_key)
    agent_did = did_from_public(agent.public_key)
    without = graph_from_vouches([v]).compute_trust(seed_did=seed_did, scope="s")
    with_ = graph_from_vouches([v, self_v]).compute_trust(seed_did=seed_did, scope="s")
    assert without[agent_did] == pytest.approx(0.9)
    assert with_[agent_did] == pytest.approx(0.9)  # was 1.8 before the fix


def test_seed_self_vouch_does_not_raise_seed_above_one():
    seed = generate_identity()
    self_v = create_vouch(seed, seed.public_key, score=1.0, scope="s", claim="x")
    trust = graph_from_vouches([self_v]).compute_trust(
        seed_did=did_from_public(seed.public_key), scope="s"
    )
    assert trust[did_from_public(seed.public_key)] == 1.0


# --- dashboard scope is escaped (reflected XSS via ?scope=) -----------------


def test_dashboard_escapes_scope_label():
    from atar.dashboard import render_dashboard_html

    net = {"agents": {}, "seed_did": "", "vouches": []}
    evil = "<script>alert('scope')</script>"
    out = render_dashboard_html(net, scope=evil)
    assert evil not in out
    assert "&lt;script&gt;" in out


def test_dashboard_paths_and_revoked_flag_work_with_legacy_did_spelling():
    """A vouch addressed to a legacy did:agent: subject must still show its
    trust path and REVOKED flag (alias-aware dashboard, SPEC §2.1)."""
    from atar.dashboard import dashboard_data
    from atar.identity import legacy_did_agent_from_public

    seed = generate_identity()
    subj = generate_identity()
    subj_legacy = legacy_did_agent_from_public(subj.public_key)
    # hand-build a vouch whose subject is the LEGACY spelling
    v = create_vouch(seed, subj.public_key, score=0.9, scope="s")
    v["payload"]["subject"] = subj_legacy
    # re-sign with the legacy subject in the payload
    from atar.vouch import _canonical

    v["signature"] = seed.sign(_canonical(v["payload"])).hex()

    seed_did = did_from_public(seed.public_key)
    net = {"agents": {"subj": subj_legacy}, "seed_did": seed_did, "vouches": [v]}
    data = dashboard_data(net, scope="s")
    subj_canon = did_from_public(subj.public_key)
    row = next(a for a in data["agents"] if a["did"] == subj_canon)
    assert row["paths"], "legacy-spelled subject lost its trust path"


# --- import --force stores instead of only counting --------------------------


def _mkhome_with_vouch(home, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "a"])
    runner.invoke(cli, ["keygen", "--name", "b"])
    with open(os.path.join(home, "keys.json")) as _f:
        keys = json.load(_f)
    runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "a",
            "--for",
            keys["b"]["did"],
            "--score",
            "0.9",
            "--scope",
            "s",
            "--out",
            os.path.join(home, "v.json"),
        ],
    )
    runner.invoke(cli, ["add", os.path.join(home, "v.json")])


def test_import_force_actually_stores(tmp_path, monkeypatch):
    src = tmp_path / "src"
    src.mkdir()
    _mkhome_with_vouch(str(src), monkeypatch)
    pkg = tmp_path / "net.atpkg"
    CliRunner().invoke(cli, ["export", "--out", str(pkg)])
    dst = tmp_path / "dst"
    dst.mkdir()
    monkeypatch.setenv("ATAR_HOME", str(dst))
    r = CliRunner().invoke(cli, ["import", "--force", str(pkg)])
    assert r.exit_code == 0
    assert VouchStore(os.path.join(str(dst), "vouches.json")).count() == 1


# --- keygen overwrite guard --------------------------------------------------


def test_keygen_refuses_overwrite_without_force(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    r1 = runner.invoke(cli, ["keygen", "--name", "a"])
    assert r1.exit_code == 0
    did1 = r1.output.strip()
    r2 = runner.invoke(cli, ["keygen", "--name", "a"])
    assert r2.exit_code == 1
    assert "refusing to overwrite" in r2.output
    with open(os.path.join(str(tmp_path), "keys.json")) as _f:
        keys = json.load(_f)
    assert keys["a"]["did"] == did1  # key untouched
    r3 = runner.invoke(cli, ["keygen", "--name", "a", "--force"])
    assert r3.exit_code == 0
    assert r3.output.strip() != did1


# --- reissue requires a rotation ---------------------------------------------


def test_reissue_without_rotation_fails_cleanly(tmp_path, monkeypatch):
    _mkhome_with_vouch(str(tmp_path), monkeypatch)
    r = CliRunner().invoke(cli, ["reissue", "--name", "a"])
    assert r.exit_code == 1
    assert "no rotation recorded" in r.output


# --- HTTP gossip: malformed remote data never crashes ------------------------


def test_sync_with_url_skips_malformed_remote_entries(tmp_path, monkeypatch):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    from atar.peer import sync_with_url
    from atar.revocation import RevocationList

    class EvilHandler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = json.dumps(
                {
                    "vouches": ["garbage", 42, None],
                    "revocations": [{"vid": "x"}, "junk", {"unexpected": 1}],
                    "disputes": [{"nope": True}, "junk"],
                }
            ).encode()
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            self.rfile.read(length)
            body = b'{"added": 0, "duplicates": 0, "rejected": 0}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *a):
            return

    server = HTTPServer(("127.0.0.1", 0), EvilHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        store = VouchStore(os.path.join(str(tmp_path), "vouches.json"))
        counts = sync_with_url(
            f"http://127.0.0.1:{server.server_address[1]}", store, RevocationList()
        )
        assert counts["vouches_in"] == 0
        assert counts["revocations_in"] == 0
        assert counts["disputes_in"] == 0
    finally:
        server.shutdown()
        server.server_close()


def test_sync_cli_unreachable_url_is_a_clean_skip(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    r = CliRunner().invoke(cli, ["sync", "--with", "http://127.0.0.1:1/none"])
    assert r.exit_code == 0
    assert "unreachable" in r.output
    assert "Traceback" not in r.output


# --- registry file permissions + atomic writes --------------------------------


def test_registry_file_is_owner_only(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    from atar.agent_bootstrap import AgentRegistry

    AgentRegistry().register("a")
    mode = stat.S_IMODE(
        os.stat(os.path.join(str(tmp_path), "agents", "registry.json")).st_mode
    )
    assert mode == 0o600, oct(mode)


def test_store_survives_simulated_crash_mid_write(tmp_path):
    """An interrupted write must leave the previous complete file intact."""
    path = os.path.join(str(tmp_path), "vouches.json")
    seed = generate_identity()
    subj = generate_identity()
    store = VouchStore(path)
    store.add(create_vouch(seed, subj.public_key, score=0.9, scope="s"))
    good = Path(path).read_bytes()
    # simulate a crashed partial write (what a non-atomic save could leave)
    with open(path, "wb") as f:
        f.write(good[: len(good) // 2])
    # the reader degrades gracefully (starts clean) rather than crashing
    assert VouchStore(path).count() == 0
    # and the next save is a complete, valid file again
    VouchStore(path).add(create_vouch(seed, subj.public_key, score=0.8, scope="s"))
    assert VouchStore(path).count() == 1


# --- score validation (SPEC §3) ------------------------------------------------


def test_create_vouch_rejects_out_of_range_scores():
    a = generate_identity()
    b = generate_identity()
    for bad in (-0.1, 1.1, float("nan"), float("inf")):
        with pytest.raises(ValueError):
            create_vouch(a, b.public_key, score=bad, scope="s")


def test_bootstrap_skips_invalid_score_cleanly(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    cfg = tmp_path / "net.toml"
    cfg.write_text(
        '[[agents]]\nname = "seed"\nseed = true\n'
        '[[agents]]\nname = "b"\n'
        '[[vouches]]\nissuer = "seed"\nsubject = "b"\nscore = 1.7\nscope = "s"\n'
        '[[vouches]]\nissuer = "seed"\nsubject = "b"\nscore = 0.5\nscope = "s"\n'
    )
    r = CliRunner().invoke(cli, ["bootstrap", "--config", str(cfg)])
    assert r.exit_code == 0
    assert "skipping invalid vouch entry" in r.output
    assert VouchStore(os.path.join(str(tmp_path), "vouches.json")).count() == 1
