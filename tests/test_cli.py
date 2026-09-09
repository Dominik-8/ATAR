import os
import json

from click.testing import CliRunner

from atar.cli import cli


def test_keygen_cli_prints_did(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    r = CliRunner().invoke(cli, ["keygen"])
    assert r.exit_code == 0
    assert "did:key:" in r.output
    # a key file was written
    assert (tmp_path / "keys.json").exists()


def test_vouch_and_verify_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    # create issuer
    r1 = runner.invoke(cli, ["keygen", "--name", "issuer"])
    assert r1.exit_code == 0
    # create subject
    r2 = runner.invoke(cli, ["keygen", "--name", "subject"])
    assert r2.exit_code == 0
    subject_did = [l for l in r2.output.splitlines() if l.startswith("did:key:")][0]
    # issuer vouches for subject
    out_file = tmp_path / "vouch.json"
    r3 = runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "issuer",
            "--for",
            subject_did,
            "--score",
            "0.8",
            "--scope",
            "coding",
            "--out",
            str(out_file),
        ],
    )
    assert r3.exit_code == 0
    vouch_file = out_file
    assert vouch_file.exists()
    # verify the vouch file
    r4 = runner.invoke(cli, ["verify", str(vouch_file)])
    assert r4.exit_code == 0
    assert "VALID" in r4.output
