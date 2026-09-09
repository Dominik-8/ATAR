import json
import os
from pathlib import Path

from click.testing import CliRunner

from atar.cli import cli


def _did(home, name):
    keys = json.loads(Path(os.path.join(home, "keys.json")).read_text(encoding="utf-8"))
    return keys[name]["did"]


def test_issue_claim_into_store_and_audit(tmp_path, monkeypatch):
    """Phase 26 integration: issue a claim, verify it, add it to the store,
    and confirm it appears in audit as a valid vouch."""
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "reporting_agent"])
    runner.invoke(cli, ["keygen", "--name", "seed_agent"])
    seed_agent_did = _did(str(tmp_path), "seed_agent")

    # issue a capability claim
    r = runner.invoke(
        cli,
        [
            "issue",
            "--from",
            "reporting_agent",
            "--for",
            seed_agent_did,
            "--scope",
            "intelligence",
            "--score",
            "0.9",
            "--claim",
            "produces the morning brief",
            "--out",
            str(tmp_path / "c.json"),
        ],
    )
    assert r.exit_code == 0, r.output

    # verify the claim independently
    r2 = runner.invoke(cli, ["verify-claim", str(tmp_path / "c.json")])
    assert r2.exit_code == 0 and "VALID" in r2.output

    # add it to the store so it becomes part of the network
    r3 = runner.invoke(cli, ["add", str(tmp_path / "c.json")])
    assert r3.exit_code == 0, r3.output

    # audit should now count it as a valid vouch
    r4 = runner.invoke(cli, ["audit"])
    assert r4.exit_code == 0 and "valid   : 1" in r4.output
