# ATAR Realignment Roadmap

Adopted 2026-09-08. This roadmap re-aims ATAR after a critical review of the
project against the 2026 agent-trust landscape (ERC-8004, A2A signed Agent
Cards, W3C agent-identity work, ai-wot).

## The idea

ATAR stops being a fifth parallel format for agent identity and becomes the
**trust engine on top of the existing standards**: `did:key` for identity,
W3C Verifiable Credentials for vouches, A2A-compatible signed agent cards for
presentation. What makes ATAR unique stays at the core: transitive trust
computation, the full lifecycle (revocation, TTL, rotation), an honest threat
model, and operator tooling (`audit`, `watch`, `export`/`import`, dashboard).
The new claim: *ATAR is the open-source trust graph with a full lifecycle
that speaks the standard formats.*

## Stage A — Honesty and foundation (1–2 weeks)

- **A1 — DID method decision.** The `did:agent:` method name is registered to
  another project in the W3C registry (May 2026). **Decision (2026-09-08):
  adopt `did:key`** — a finished standard, no registration, and ATAR's
  identity is already just an Ed25519 key. "ATAR" stays the protocol name.
  → [#2](https://github.com/Dominik-8/ATAR/issues/2)
- **A2 — Correct the claims.** Honest landscape positioning (ERC-8004, A2A,
  W3C, ai-wot exist); precise "offline-verifiable" (signatures offline,
  revocation status via gossip); honest TTL semantics (re-signing, not
  re-earning). → [#3](https://github.com/Dominik-8/ATAR/issues/3)
- **A3 — Close two protocol gaps.** Verify revocation signatures at every
  intake path + issuer binding ([#4](https://github.com/Dominik-8/ATAR/issues/4));
  proof-of-possession challenge for agent cards
  ([#5](https://github.com/Dominik-8/ATAR/issues/5)).

## Stage B — Standards alignment (3–4 weeks)

- **B1 — Identity as `did:key`.** New identity type (Multibase/Multicodec per
  spec). Migration: existing `did:agent:` identities stay importable (alias in
  the store), old vouches stay verifiable — no data loss, no hard cut. Spec §2
  rewrite; `keygen` outputs `did:key`.
- **B2 — Vouches as W3C Verifiable Credentials.** VC export + verify alongside
  the native format: `credentialSubject` with scope/score/claim, proof as an
  Ed25519 Data Integrity signature. The lean native format stays internal; the
  VC path is the bridge out — any VC tooling can check an ATAR vouch. Spec §3
  gains the VC mapping.
- **B3 — A2A-compatible signed agent card.** Rebuild the card (§11.2) as an
  A2A Agent Card with a signature extension instead of the own
  `atar-agent-card/1.0` schema, so any A2A-speaking system can read it and
  ATAR supplies the trust data as an extension.

## Stage C — Becoming real (ongoing, after B)

- **C1 — Minimal network transport for gossip.** ✅ Shipped 2026-09-08:
  `atar peer` serves the local store over HTTP (GET/POST of vouches and
  revocations, still content-addressed, no central server) and
  `atar sync --with http://...` / `auto-sync` gossip with remote peers.
  Spec: SPEC §9.1.
- **C2 — One framework plugin as adoption proof.** ✅ Shipped
  2026-09-08: `atar.integrations.crewai` — CrewAI agents get a did:key
  identity automatically, earn an operator-signed vouch after each successful
  task, and present a signed A2A-compatible card. Docs:
  `docs/crewai-plugin.md`; example: `atar.examples.crewai_integration`.
- **C3 — Score semantics and negative signals.** Define what `score 0.95`
  means (units, evidence references) so scores compare across operators; add
  signed disputes next to positive vouches and revocations.
- **C4 — Standardization path.** Join the W3C agent-identity community work
  and bring ATAR's lifecycle ideas (revocation, TTL, rotation) there;
  optionally an IETF Internet-Draft via the datatracker. Influence through
  the standards track instead of competing with ERC-8004 and A2A.

## What deliberately stays

Ed25519 crypto, the test suite, the transitive trust algorithm (SPEC §8.1),
the complete lifecycle (revocation, TTL, rotation/reissue), the operator
tooling, and the honest documentation culture. That is the lead over the
competition — the realignment puts it on standard rails instead of throwing
it away.
