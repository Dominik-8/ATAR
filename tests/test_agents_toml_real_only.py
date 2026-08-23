"""Guard: the REAL network config must contain only real agents.

The whole point of ATAR is a trust layer built on real agents. Shipping demo
agents as if they were real (in the default bootstrap config) is theater, not
infrastructure. This test forbids "(demo)" markers in agents.toml. Demo agents
belong in demo.toml.
"""

import os

import toml  # or fall back to stdlib if toml missing

_CONFIG = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "agents.toml")


def test_agents_toml_has_no_demo_agents():
    with open(_CONFIG, "r", encoding="utf-8") as f:
        data = toml.load(f)
    for agent in data.get("agents", []):
        name = agent.get("name", "")
        note = str(agent.get("note", ""))
        assert "(demo)" not in note, f"agents.toml must not contain demo agents: {name}"
        assert "demo" not in name.lower(), f"agents.toml must not contain demo agents: {name}"


def test_agents_toml_contains_real_agents():
    with open(_CONFIG, "r", encoding="utf-8") as f:
        data = toml.load(f)
    names = {a.get("name") for a in data.get("agents", [])}
    assert "seed_agent" in names, "seed_agent (real seed) must be present"
    assert "daily_brief" in names, "daily_brief (real cron) must be present"
