"""Guard: the REAL network config must contain only real agents.

The whole point of ATAR is a trust layer built on real agents. Shipping demo
agents as if they were real (in the default bootstrap config) is theater, not
infrastructure. This test forbids "(demo)" markers in agents.toml. Demo agents
belong in demo.toml.
"""

import os
import tomllib

_CONFIG = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "agents.toml"
)


def _load():
    with open(_CONFIG, "rb") as f:
        return tomllib.load(f)


def test_agents_toml_has_no_demo_agents():
    data = _load()
    for agent in data.get("agents", []):
        name = agent.get("name", "")
        note = str(agent.get("note", ""))
        assert "(demo)" not in note, f"agents.toml must not contain demo agents: {name}"
        assert "demo" not in name.lower(), (
            f"agents.toml must not contain demo agents: {name}"
        )


def test_agents_toml_contains_real_agents():
    data = _load()
    names = {a.get("name") for a in data.get("agents", [])}
    assert "seed_agent" in names, "seed_agent (real seed) must be present"
    assert "reporting_agent" in names, "reporting_agent (real cron) must be present"
