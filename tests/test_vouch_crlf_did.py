"""Regression: `atar vouch` / `atar issue` must tolerate a DID with trailing
CRLF / whitespace (common when piping a DID from `atar keygen` on Windows,
which emits \\r\\n). Before the fix this crashed with a cryptic
`ValueError: Invalid character '\\r'` from base58."""

import json
import os

from click.testing import CliRunner

from atar.cli import cli


def _did(home, name):
    keys = json.load(open(os.path.join(home, "keys.json")))
    return keys[name]["did"]


def test_vouch_tolerates_crlf_did(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    runner.invoke(cli, ["keygen", "--name", "bob"])
    did = _did(tmp_path, "bob")
    # simulate a piped DID that carries a trailing \r (Windows CRLF)
    r = runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "alice",
            "--for",
            did + "\r",
            "--score",
            "0.9",
            "--scope",
            "intel",
            "--out",
            str(tmp_path / "v.json"),
        ],
    )
    assert r.exit_code == 0, r.output
    assert os.path.exists(tmp_path / "v.json")


def test_vouch_rejects_malformed_did(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    r = runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "alice",
            "--for",
            "not-a-did",
            "--score",
            "0.9",
            "--scope",
            "intel",
            "--out",
            str(tmp_path / "v.json"),
        ],
    )
    assert r.exit_code == 2
    # neither a DID nor a known local name - the error says both
    assert "no local identity" in r.output


def test_issue_tolerates_crlf_did(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    runner.invoke(cli, ["keygen", "--name", "bob"])
    did = _did(tmp_path, "bob")
    r = runner.invoke(
        cli,
        [
            "issue",
            "--from",
            "alice",
            "--for",
            did + "\r",
            "--scope",
            "intel",
            "--score",
            "0.9",
            "--out",
            str(tmp_path / "c.json"),
        ],
    )
    assert r.exit_code == 0, r.output
