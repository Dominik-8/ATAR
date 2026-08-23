# ATAR — Agent Trust & Attribution Root

> The free, decentralized **trust layer** for AI agents — the `SSL/CA` of the agent era.
> No servers. No blockchain. No cost.

ATAR gives every AI agent a self-sovereign cryptographic identity (`did:agent:`)
and lets agents vouch for one another with signed, tamper-evident attestations.
Think of it as a **passport + word-of-mouth trust network** for software agents:
anyone can verify who an agent is and who vouches for it — offline, for $0.

This is the still-unclaimed **top layer** of the AI era: transport (MCP/A2A) is
solved, but *trust & attribution* is not. ATAR is the open protocol for it.

## Quickstart

```bash
pip install -e .
export ATAR_HOME=~/.atar

# 1. Create two agent identities
atar keygen --name alice
atar keygen --name bob

# 2. Alice vouches for Bob (score 0..1, scope = capability area)
atar vouch --from alice --for <bob-did> --score 0.95 --scope coding \
    --out bob-vouch.json

# 3. Anyone verifies the vouch offline
atar verify bob-vouch.json   # -> VALID
```

## Why it matters (the "top layer" thesis)

- **Transport is solved.** MCP (tools) and A2A (agent-to-agent) are now
  consolidated under the Linux Foundation. You cannot reinvent HTTP.
- **Trust is not.** No free, decentralized, serverless "who is this agent and
  who vouches for it" layer exists in 2026. Central registries reintroduce a
  server; blockchains cost gas and are empirically hollow (ERC-8004: 59–90%
  Sybil reviewers).
- **ATAR is the gap.** Identity + vouching with zero infrastructure. The
  protocol itself captures no value (a public good, like HTTP) — value accrues
  to the applications built on top (directories, "Know Your Agent" analytics),
  exactly as Google built on top of a free HTTP.

## Honest constraints

- **Sybil resistance is partial.** Free, serverless identity means anyone can
  mint unlimited agents. ATAR provides the *mechanism* (signed vouches);
  meaningful reputation emerges from the web-of-trust, not from the protocol.
  We do not promise Sybil-proofing — that is mathematically incompatible with
  "free + decentralized + zero-server".
- **Bootstrap needs a seed.** Adoption is the real risk. We seed ATAR by
  forcing our own agents (e.g. ATAR) to use it, riding MCP/A2A as carriers
  rather than competing with them.

## Project status

Phase 1 (MVP) complete: Ed25519 identity, signed vouch blobs, CLI.
Next: ATC carrier format (HTTP/A2A/MCP headers), gossiped transparency log.

See [SPEC.md](SPEC.md) for the wire format.
