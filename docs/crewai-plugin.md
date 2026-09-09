# CrewAI plugin — framework agents on the ATAR trust graph

Stage C2 of the [realignment roadmap](../ROADMAP.md): one visible framework
integration. The plugin lives at `atar.integrations.crewai` and has **no hard
dependency on CrewAI** — it duck-types the two touchpoints it needs, so the
core package stays lean.

## What it does

1. **Every agent gets an identity.** `trust.register_crew(crew)` (or
   `trust.register(role)`) creates a persistent `did:key` identity per CrewAI
   agent role, stored in the normal ATAR registry under `$ATAR_HOME`. The
   mapping is stable across restarts.
2. **Successful tasks earn vouches.** Attach `trust.task_callback_for(role)`
   as a CrewAI task callback. CrewAI fires the callback only when the task
   completes successfully, and the plugin then records a signed vouch from
   the *operator* identity (the crew owner) for the executing agent, under
   the configured scope. The vouch lands in the persistent store — it
   gossip-syncs (`atar sync`), shows up in `atar audit` and on the dashboard
   like any other vouch.
3. **Agents present a card.** `trust.card(role)` builds a signed,
   A2A-compatible agent card (SPEC §11.2) carrying the agent's DID and all
   vouches the store holds for it. Any ATAR verifier checks it offline with
   `atar verify-card`.

## Trust model

The **operator identity** (default name `crew_operator`, created on first
use) is the trust root: it attests to observed task success. Agents never
vouch for themselves — self-attestation contributes nothing to transitive
trust (SPEC §8.1, §13). The default score for one completed task is `0.8`:
evidence, not proof. Repeated success is meant to be re-vouched over time;
TTL (SPEC §7) keeps old vouches from becoming zombie trust.

## Usage

```python
from crewai import Agent, Crew, Task
from atar.integrations.crewai import AtarCrewTrust

trust = AtarCrewTrust(operator="crew_operator", scope="research")

researcher = Agent(role="researcher", goal="Find facts", backstory="...")
writer = Agent(role="writer", goal="Write reports", backstory="...")

crew = Crew(agents=[researcher, writer], tasks=[])
trust.register_crew(crew)  # every agent gets a did:key identity

task = Task(
    description="Research agent trust protocols",
    agent=researcher,
    callback=trust.task_callback_for("researcher"),  # vouch on success
)

# ... run the crew ...

card = trust.card("researcher")  # signed A2A-compatible agent card
```

## Working example

`python -m atar.examples.crewai_integration` runs the whole flow end-to-end
(identity → task success → vouch → signed card → offline verification) with
lightweight stand-ins for the CrewAI objects, so it works without the
framework installed. With CrewAI installed, swap the stand-ins for real
`Agent`/`Crew`/`Task` — the plugin calls are identical.

## Why CrewAI (and not LangGraph)

CrewAI is agent-centric: agents have roles, tasks have per-task success
callbacks — the exact shape of ATAR's "identity per agent, vouch after
observed success" model. LangGraph is state-graph-centric (nodes are
functions, not identities), so the mapping is less natural. The plugin
module is small and the same pattern ports to other frameworks later.
