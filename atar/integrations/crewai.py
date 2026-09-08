"""CrewAI integration — framework agents join the ATAR trust graph (Stage C2).

The plugin gives every CrewAI agent a persistent ATAR identity, vouches for
an agent after each task it completes successfully, and can present a signed
A2A-compatible agent card for any agent. Identities and vouches live in the
normal ATAR store ($ATAR_HOME), so everything the plugin records gossip-syncs,
audits and shows on the dashboard like any other ATAR data.

Trust model: the *operator* identity (the crew owner, by default the named
identity ``crew_operator``) vouches for the agent that executed the task,
under the task's scope. That matches ATAR's model: an already-trusted root
attests to observed performance; agents never mint their own reputation.

Usage with CrewAI installed (``pip install crewai``):

    from crewai import Agent, Crew, Task
    from atar.integrations.crewai import AtarCrewTrust

    trust = AtarCrewTrust(operator="crew_operator", scope="research")
    researcher = Agent(role="researcher", goal="...", backstory="...")
    trust.register_crew(Crew(agents=[researcher], tasks=[]))  # or register("researcher")

    task = Task(description="...", agent=researcher,
                callback=trust.task_callback_for("researcher"))
    # after a successful run:
    card = trust.card("researcher")   # signed A2A-compatible agent card

The module imports fine without CrewAI installed — it only duck-types
(``crew.agents`` with a ``role`` attribute), so the trust layer never forces
a framework dependency on the core package.
"""

from __future__ import annotations

from ..agent_bootstrap import AgentRegistry
from ..atc import make_agent_card, sign_agent_card

# Default score the operator gives for one successfully completed task.
# Deliberately below 1.0: a single task is evidence, not proof (SPEC §7
# freshness still applies; repeated success is meant to be re-vouched).
DEFAULT_TASK_SCORE = 0.8


class AtarCrewTrust:
    """Bridges a CrewAI crew and the ATAR trust graph."""

    def __init__(self, *, operator: str = "crew_operator",
                 scope: str = "general", score: float = DEFAULT_TASK_SCORE) -> None:
        if not 0.0 < score <= 1.0:
            raise ValueError("score must be in (0.0, 1.0]")
        self.operator = operator
        self.scope = scope
        self.score = float(score)
        self._reg = AgentRegistry()
        # The operator is the trust root of this crew: ensure it exists.
        self._reg.register(operator)

    # --- identities ---------------------------------------------------------

    def register(self, role: str) -> str:
        """Ensure the agent with this CrewAI ``role`` has an ATAR identity.

        Idempotent and stable: the same role maps to the same DID across
        process restarts (the key lives in the registry under $ATAR_HOME).
        """
        return self._reg.register(role)

    def register_crew(self, crew) -> dict[str, str]:
        """Register every agent of a CrewAI ``Crew``; returns role -> DID."""
        mapping: dict[str, str] = {}
        for agent in getattr(crew, "agents", []) or []:
            role = getattr(agent, "role", None)
            if role:
                mapping[role] = self.register(role)
        return mapping

    def did_of(self, role: str) -> str:
        return self.register(role)

    # --- vouching -----------------------------------------------------------

    def record_success(self, role: str, *, scope: str | None = None,
                       score: float | None = None) -> bool:
        """Vouch for ``role`` after a successfully completed task.

        The operator identity signs the vouch; it lands in the persistent
        store (content-addressed, so re-recording the same scope+score for the
        same agent is a no-op until the timestamped claim differs — see
        canonical_vouch_id). Returns True when a new vouch was stored.
        """
        self.register(role)
        return self._reg.vouch(self.operator, role,
                               score=score if score is not None else self.score,
                               scope=scope or self.scope)

    def task_callback_for(self, role: str, *, scope: str | None = None):
        """Return a CrewAI task callback: ``Task(..., callback=...)``.

        CrewAI invokes the callback with the task output only when the task
        completes successfully, so the callback itself is the success signal.
        The output object is accepted (and ignored) for API compatibility.
        """
        def _callback(output=None) -> None:
            self.record_success(role, scope=scope)
        return _callback

    # --- presentation -------------------------------------------------------

    def card(self, role: str, *, url: str | None = None,
             description: str | None = None) -> dict:
        """Build + sign an A2A-compatible agent card for ``role`` (SPEC §11.2).

        The card carries the agent's DID and every vouch the local store holds
        for it (as §11.1 tokens), signed by the agent's own key, so any
        A2A-speaking system can read it and any ATAR verifier can check it
        offline (`atar verify-card`).
        """
        did = self.register(role)
        subject_vouches = [
            v for v in self._reg._store.all()
            if v.get("payload", {}).get("subject") == did
        ]
        card = make_agent_card(did, role, subject_vouches,
                               url=url, description=description)
        return sign_agent_card(card, self._reg.identity_of(role))
