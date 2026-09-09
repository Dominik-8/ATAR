import os

from click.testing import CliRunner

from atar.cli import cli


def _make_vouch_file(home, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    r2 = runner.invoke(cli, ["keygen", "--name", "bob"])
    bob_did = next(
        line for line in r2.output.splitlines() if line.startswith("did:key:")
    )
    out = os.path.join(home, "v.json")
    runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "alice",
            "--for",
            bob_did,
            "--score",
            "0.9",
            "--scope",
            "coding",
            "--out",
            out,
        ],
    )
    runner.invoke(cli, ["add", out])
    return out


def test_verify_reports_valid_when_not_revoked(tmp_path, monkeypatch):
    out = _make_vouch_file(str(tmp_path), monkeypatch)
    r = CliRunner().invoke(cli, ["verify", out])
    assert r.exit_code == 0
    assert "VALID" in r.output


def test_verify_reports_revoked_when_on_list(tmp_path, monkeypatch):
    out = _make_vouch_file(str(tmp_path), monkeypatch)
    # revoke it
    r = CliRunner().invoke(cli, ["revoke", out])
    assert r.exit_code == 0
    # now verify must report REVOKED (not VALID)
    r2 = CliRunner().invoke(cli, ["verify", out])
    assert r2.exit_code != 0
    assert "REVOKED" in r2.output.upper()


def test_verify_card_also_checks_revocation(tmp_path, monkeypatch):
    out = _make_vouch_file(str(tmp_path), monkeypatch)
    # build a card containing this vouch
    CliRunner().invoke(
        cli,
        ["card", "--name", "bob", "--out", os.path.join(str(tmp_path), "card.json")],
    )
    # revoke, then verify_card must flag it
    CliRunner().invoke(cli, ["revoke", out])
    r = CliRunner().invoke(
        cli, ["verify-card", os.path.join(str(tmp_path), "card.json")]
    )
    assert "REVOKED" in r.output.upper()
