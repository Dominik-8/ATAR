"""Working example: a CrewAI crew on the ATAR trust graph (Stage C2).

Runs end-to-end WITHOUT a CrewAI install by duck-typing the two framework
touchpoints the plugin uses (``crew.agents[].role`` and the task callback).
With CrewAI installed, swap the fakes for real ``Agent``/``Crew``/``Task``
objects — the plugin calls are identical (see docs/crewai-plugin.md).

Run:  python -m atar.examples.crewai_integration
"""

from __future__ import annotations

import os
import tempfile

from atar.atc import verify_agent_card
from atar.integrations.crewai import AtarCrewTrust


# --- stand-ins for crewai.Agent / crewai.Crew / task output -----------------
class Agent:
    def __init__(self, role):
        self.role = role


class Crew:
    def __init__(self, agents):
        self.agents = agents


def run_task(role: str) -> object:
    """Pretend the crew ran a task and it succeeded."""
    return f"output of {role}'s task"


def main() -> None:
    os.environ.setdefault("ATAR_HOME", tempfile.mkdtemp(prefix="atar-crewai-"))

    trust = AtarCrewTrust(operator="crew_operator", scope="research")

    crew = Crew([Agent("researcher"), Agent("writer")])
    print("identities:", trust.register_crew(crew))

    # CrewAI: Task(..., agent=researcher, callback=trust.task_callback_for("researcher"))
    for role in ("researcher", "writer"):
        output = run_task(role)  # task runs...
        trust.task_callback_for(role)(output)  # ...and on success, vouch

    card = trust.card("researcher")
    report = verify_agent_card(card)
    print(
        "researcher card valid:",
        report["signature_valid"],
        "| vouches presented:",
        len(report["valid_vouches"]),
    )
    print("researcher DID:", report["did"])


if __name__ == "__main__":
    main()
