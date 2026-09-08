# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed (pre-publication audit)
- `atar card` now reads the persistent vouch store instead of scanning
  loose files, so cards include the vouches the store actually holds.
- Trust computation (`atar graph`, dashboard) now counts only valid,
  unrevoked, unexpired vouches and applies the SPEC §8.2 dispute discount,
  as SPEC §8.1 always promised. Revoked agents stay visible in the
  dashboard, flagged REVOKED with trust 0.
- SPEC §8 `vouch_id` formula synced with the implementation
  (`"vouch:"` prefix, `ts` excluded).
- README install leads with install-from-source; the stale PyPI package
  (`1.0.0a1`, pre-realignment) is marked pending update.
- Package metadata and repo description reflect the did:key realignment;
  version on master is `1.0.0a2.dev0` (alpha development toward the next
  packaged release).

### Added (realignment C4, prep only)
- Standardization drafts for review (nothing submitted): a W3C
  agent-identity community intro post and an IETF Internet-Draft skeleton
  (`draft-dbrueck-atar-lifecycle-00`) positioning ATAR's lifecycle
  (revocation, TTL, rotation, disputes) as the contribution. Both live in
  `docs/standardization/` and supersede the pre-realignment
  `draft-dbrueck-atar-00.txt` (kept for history).

### Added (realignment C3)
- Score semantics (SPEC §3.2): score defined as dimensionless issuer
  confidence with calibration anchors, plus optional signed `evidence`
  references on vouches (`create_vouch(..., evidence=[...])`) so scores carry
  an inspectable basis and compare across operators.
- Signed disputes (SPEC §8.2): any agent can file a signed warning against a
  foreign vouch (`atar dispute` / `atar disputes`). Disputes are
  content-addressed, verified at every intake path, gossip over both sync
  transports (filesystem + HTTP `/disputes`), are surfaced by `atar verify`
  as an advisory note, and discount vouches in trust computation only when
  the disputer is itself trusted (≥ 0.5), so Sybil smears move nothing.

### Added (realignment C2)
- CrewAI plugin (`atar.integrations.crewai`): framework agents get a
  persistent did:key identity automatically, earn a signed operator vouch
  after each successfully completed task, and can present a signed
  A2A-compatible agent card. No hard CrewAI dependency (duck-typed). Working
  example: `python -m atar.examples.crewai_integration`; docs:
  `docs/crewai-plugin.md`.

### Added (realignment C1)
- HTTP gossip transport: `atar peer` serves the local store over a slim HTTP
  endpoint (GET/POST of vouches and revocations, content-addressed, no central
  server), and `atar sync --with http://...` / `auto-sync` exchange with
  remote peers the same way they do with filesystem peers. Intake rules are
  identical on both transports (signature verification, issuer binding,
  revoked/expired vouches never admitted). Spec: SPEC §9.1.

### Changed (realignment B3)
- The agent card is now an **A2A-compatible signed Agent Card** (SPEC §11.2):
  ATAR trust data (identity, vouch tokens, PoP proof) lives in a declared
  capability extension, and `atar card` signs the whole card (JWS-style EdDSA
  entry in the card's `signatures` array). The standalone
  `atar-agent-card/1.0` schema is replaced; legacy cards stay verifiable.

### Added (realignment B2)
- Vouches export as W3C Verifiable Credentials (VC 2.0): `credentialSubject`
  carries scope/score/claim, proofs are `eddsa-jcs-2022` Data Integrity proofs
  (JCS / RFC 8785 + SHA-256 + Ed25519). New `atar vc-export` / `atar vc-verify`
  commands; verification is fully offline. The native vouch format stays the
  internal representation — the VC path is the interop bridge.

### Changed (realignment B1)
- Identity is now W3C `did:key` (multicodec `ed25519-pub` + multibase
  base58btc) instead of ATAR's own `did:agent:` spelling. `atar keygen` prints
  `did:key` DIDs; new vouches/claims/rotations/cards record the `did:key` form.
- Migration without data loss: legacy `did:agent:` DIDs stay decodable
  everywhere, old vouches/revocations/rotations verify unchanged, and trust
  decisions (revocation matching, transitive-trust graph, agent-card subject
  collection) compare canonical aliases so both spellings are one identity.

## [1.0.0a1] - 2026-09-06

### Added
- Ed25519 `did:agent:` identity (self-sovereign, offline-verifiable)
- Signed vouch blobs with canonical JSON serialization
- ATC Carrier (vouch tokens + agent cards)
- Transitive trust graph (web-of-trust)
- Revocation (signed, local/P2P)
- Freshness / TTL (passive decay)
- Key rotation (recovery without total loss)
- Decentralized sync (gossip)
- Multi-scope dashboard (CLI + live server)
- Reproducible network bootstrap (TOML)
- Portable export/import (.atpkg)
- Health monitoring (audit + watch)
- Signed capability claims (issue/verify-claim)
- 122 tests, CI green
- RFC Draft (draft-dbrueck-atar-00)
- PyPI release (`pip install atar-trust`)

[1.0.0a1]: https://github.com/Dominik-8/ATAR/releases/tag/v1.0.0a1
