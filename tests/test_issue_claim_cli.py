import json
import os
from pathlib import Path

from click.testing import CliRunner

from atar.cli import cli


def _id(home, name):
    keys = json.loads(Path(os.path.join(home, "keys.json")).read_text(encoding="utf-8"))
    return keys[name]["did"]


def test_issue_and_verify_claim(tmp_path, monkeypatch):
    """Phase 26 core: an agent can issue a signed claim about another DID and
    the claim verifies cryptographically (independent of the store)."""
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "reporting_agent"])
    runner.invoke(cli, ["keygen", "--name", "seed_agent"])

    # reporting_agent issues a signed claim about seed_agent's capability
    r = runner.invoke(
        cli,
        [
            "issue",
            "--from",
            "reporting_agent",
            "--for",
            _id(str(tmp_path), "seed_agent"),
            "--scope",
            "intelligence",
            "--score",
            "0.85",
            "--claim",
            "operates the morning brief",
            "--out",
            str(tmp_path / "claim.json"),
        ],
    )
    assert r.exit_code == 0, r.output
    assert os.path.exists(str(tmp_path / "claim.json"))

    # verify the issued claim independently
    r2 = runner.invoke(cli, ["verify-claim", str(tmp_path / "claim.json")])
    assert r2.exit_code == 0, r2.output
    assert "VALID" in r2.output

    # tamper with the claim -> verify must fail
    import json

    with open(str(tmp_path / "claim.json")) as _f:
        claim = json.load(_f)
    claim["payload"]["claim"] = "TAMPERED"
    with open(str(tmp_path / "claim.json"), "w") as _f:
        json.dump(claim, _f)
    r3 = runner.invoke(cli, ["verify-claim", str(tmp_path / "claim.json")])
    assert r3.exit_code != 0
    assert "INVALID" in r3.output
