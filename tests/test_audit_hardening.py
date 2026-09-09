"""Pre-publication audit nice-to-haves: key-file permissions, --score bounds,
evidence preservation on VC export and rotation re-issue."""

import json
import os
import stat

from click.testing import CliRunner

from atar.cli import cli
from atar.identity import generate_identity
from atar.rotation import reissue_vouch
from atar.vc import vouch_to_credential
from atar.vouch import create_vouch, verify_vouch


def test_keys_file_is_owner_only(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    r = CliRunner().invoke(cli, ["keygen", "--name", "alice"])
    assert r.exit_code == 0
    mode = stat.S_IMODE(os.stat(tmp_path / "keys.json").st_mode)
    assert mode == 0o600, oct(mode)


def test_vouch_rejects_out_of_range_score(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    assert runner.invoke(cli, ["keygen", "--name", "alice"]).exit_code == 0
    did = "did:key:z6MkhaXgBZDvotDkL5257faiztiGiC2QtKLGpbnnEGta2doK"
    for bad in ("1.5", "-0.1"):
        r = runner.invoke(
            cli,
            [
                "vouch",
                "--from",
                "alice",
                "--for",
                did,
                "--score",
                bad,
                "--scope",
                "coding",
            ],
        )
        assert r.exit_code == 2, (bad, r.output)
        assert "score must be within [0, 1]" in r.output
    # boundary values stay legal
    for good in ("0", "1"):
        r = runner.invoke(
            cli,
            [
                "vouch",
                "--from",
                "alice",
                "--for",
                did,
                "--score",
                good,
                "--scope",
                "coding",
                "--out",
                str(tmp_path / f"v{good}.json"),
            ],
        )
        assert r.exit_code == 0, (good, r.output)


def test_vc_export_carries_evidence():
    issuer = generate_identity()
    v = create_vouch(
        issuer,
        issuer.public_key,
        score=0.9,
        scope="coding",
        evidence=["https://ops.example/task/42"],
        ts=1000,
    )
    cred = vouch_to_credential(v)
    assert cred["credentialSubject"]["atar:evidence"] == ["https://ops.example/task/42"]
    # no evidence -> key omitted, not null
    v2 = create_vouch(issuer, issuer.public_key, score=0.9, scope="coding", ts=1000)
    assert "atar:evidence" not in vouch_to_credential(v2)["credentialSubject"]


def test_reissue_preserves_claim_and_evidence():
    old_key, new_key, subject = (generate_identity() for _ in range(3))
    v = create_vouch(
        old_key,
        subject.public_key,
        score=0.9,
        scope="coding",
        claim="reviewed Q3 deliverables",
        evidence=["ticket:ATAR-7"],
        ts=1000,
    )
    out = reissue_vouch(old_key.private_key, new_key.private_key, v)
    assert out["payload"]["claim"] == "reviewed Q3 deliverables"
    assert out["payload"]["evidence"] == ["ticket:ATAR-7"]
    assert verify_vouch(out)
