# ATAR — Agent Trust & Attribution Root

> The free, decentralized **trust layer** for AI agents — the `SSL/CA` of the agent era.
> No servers. No blockchain. No cost.

[![CI](https://github.com/Dominik-8/ATAR/actions/workflows/ci.yml/badge.svg)](https://github.com/Dominik-8/ATAR/actions)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org)
[![Design: ATAR dark](https://img.shields.io/badge/design-ATAR%20dark%20%7C%20%2339ff14-neon)](https://github.com/Dominik-8/ATAR)

ATAR gives every AI agent a self-sovereign cryptographic identity (`did:agent:`)
and lets agents vouch for one another with signed, tamper-evident attestations.
Think of it as a **passport + word-of-mouth trust network** for software agents:
anyone can verify who an agent is and who vouches for it — offline, for $0.

This is the still-unclaimed **top layer** of the AI era: transport (MCP/A2A) is
solved, but *trust & attribution* is not. ATAR is the open protocol for it.

## Contents

- [Why it matters](#why-it-matters-the-top-layer-thesis)
- [Install](#install)
- [Quickstart](#quickstart)
- [How it works](#how-it-works)
- [CLI reference](#cli-reference)
- [Visual identity](#visual-identity-seed_agent-style)
- [Project status](#project-status)
- [Honest constraints](#honest-constraints)
- [Contributing](#contributing)

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

## Install

```bash
pip install atar
```

## Quickstart

```bash
# 1. create two agent identities
atar keygen --name alice
atar keygen --name bob

# 2. alice vouches for bob's competence in "coding"
atar vouch --from alice --for "did:agent:..." --score 0.95 --scope coding \
    --out bob-vouch.json

# 3. anyone verifies the vouch offline (no server, no internet)
atar verify bob-vouch.json          # -> VALID

# 4. build an agent card (DID + name + vouches) to present on contact
atar card --name bob --out card.json

# 5. render the Know-Your-Agent dashboard from a local trust graph
atar dashboard --seed "did:agent:..." --scope coding --out dash.html
```

## How it works

1. **Identity** — Ed25519 keypair; `did:agent:` derived from the public key.
   Self-resolving, offline-verifiable, $0.
2. **Vouch** — a signed attestation: *issuer vouches subject for scope@score*.
   Tamper-evident (any change invalidates the signature).
3. **ATC Carrier** — vouches encoded as header-safe tokens + an "agent card"
   JSON, presented inline over HTTP/A2A/MCP. ATAR rides *on top* of existing
   transports; it replaces nothing.
4. **Transparency graph** — vouches are content-addressed (sha256 of their
   bytes), so they can be gossiped with no operator. Each agent computes
   *transitive trust* locally from a seed of trusted roots.

See [`SPEC.md`](SPEC.md) for the full wire format.

## CLI reference

| Command | Purpose |
|---|---|
| `atar keygen --name N` | create an agent identity, print its `did:agent:` |
| `atar vouch --from A --for DID --score S --scope C` | create a signed vouch |
| `atar verify PATH` | verify a vouch blob file → `VALID`/`INVALID` |
| `atar card --name N` | build an agent card (DID + vouches) |
| `atar verify-card PATH` | verify every vouch in an agent card |
| `atar graph --seed DID --scope C` | print transitive-trust ranking (CLI) |
| `atar dashboard --seed DID --scope C` | render Know-Your-Agent HTML dashboard |

## Visual identity (ATAR-style)

ATAR shares ATAR's dark, ATAR-corporate look so the two projects read as one
family:

| Token | Value | Use |
|---|---|---|
| `--bg` | `#0a0a0b` | near-black background |
| `--accent` | `#39ff14` | gift-green / neon (trust, valid, verified) |
| `--accent-dim` | `#1f7a12` | dimmed green borders/badges |
| `--accent-blue` | `#2f81f7` | GitHub-blue, for `did:agent:` identifiers |
| `--text` | `#e8e8ea` | primary text |
| `--muted` | `#8a8a90` | secondary text |
| Font | Segoe UI / -apple-system | system UI stack |

The canonical tokens live in [`atar/theme.css`](atar/theme.css) — reuse them for
any ATAR UI, web page, or digest so the design stays consistent.

## Project status

| Phase | Status |
|---|---|
| 1 — Ed25519 identity + sign/verify | ✅ |
| 2 — ATC carrier (tokens + agent cards) | ✅ |
| 3 — Transparency log + transitive trust graph | ✅ |
| 4 — Bootstrap (ATAR adopts ATAR) | ✅ |
| 4b — `atar graph` CLI | ✅ |
| 4c — Demo trust network | ✅ |
| 6 — Know-Your-Agent dashboard | ✅ |
| 8 — `atar dashboard` CLI | ✅ |

Next: real-agent seeding (Phase 4d), vouch persistence/gossip (Phase 7).

## Honest constraints

- **Sybil resistance is partial.** Free, serverless identity means anyone can
  mint unlimited agents. ATAR provides the *mechanism* (signed vouches);
  meaningful reputation emerges from the web-of-trust, not from the protocol.
  We do not promise Sybil-proofing — that is mathematically incompatible with
  "free + decentralized + zero-server".
- **Bootstrap needs a seed.** Adoption is the real risk. We seed ATAR by
  forcing our own agents (e.g. ATAR) to use it, riding MCP/A2A as carriers
  rather than competing with them.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Security issues: [SECURITY.md](SECURITY.md).

## License

MIT — see [LICENSE](LICENSE).
