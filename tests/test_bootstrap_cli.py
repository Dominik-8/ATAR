import os
import tempfile

from click.testing import CliRunner

from atar.cli import cli


def test_bootstrap_from_config_idempotent(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    cfg = tmp_path / "agents.toml"
    cfg.write_text(
        '''
[[agents]]
name = "seed_agent"
seed = true

[[agents]]
name = "research"

[[agents]]
name = "market"

[[vouches]]
issuer = "seed_agent"
subject = "research"
score = 0.9
scope = "intelligence"

[[vouches]]
issuer = "seed_agent"
subject = "market"
score = 0.8
scope = "intelligence"
''',
        encoding="utf-8",
    )
    # first run: builds the network
    r1 = runner.invoke(cli, ["bootstrap", "--config", str(cfg)])
    assert r1.exit_code == 0
    assert "3 agents" in r1.output and "2 new vouch" in r1.output
    assert "seed of trust" in r1.output
    # verify store has the vouches
    from atar.store import VouchStore
    store = VouchStore(os.path.join(tmp_path, "vouches.json"))
    assert store.count() == 2
    # second run: idempotent (no duplicates, no errors)
    r2 = runner.invoke(cli, ["bootstrap", "--config", str(cfg)])
    assert r2.exit_code == 0
    store2 = VouchStore(os.path.join(tmp_path, "vouches.json"))
    assert store2.count() == 2  # still 2, not 4


def test_bootstrap_creates_agent_identities(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    cfg = tmp_path / "a.toml"
    cfg.write_text(
        '''
[[agents]]
name = "seed_agent"
seed = true

[[agents]]
name = "scout"
''',
        encoding="utf-8",
    )
    r = runner.invoke(cli, ["bootstrap", "--config", str(cfg)])
    assert r.exit_code == 0
    # identities persisted
    reg_file = os.path.join(tmp_path, "agents", "registry.json")
    import json
    reg = json.load(open(reg_file))
    assert "seed_agent" in reg and "scout" in reg
    assert reg.get("_seed") == reg["seed_agent"]["did"]
