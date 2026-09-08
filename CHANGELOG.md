# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added (overnight hardening, 2026-09)
- `atar identities`: list the local identities (name -> DID). A new user
  following the quickstart had no way to see the identities they created —
  `atar list` shows vouches, not identities, and the only record was inside
  `keys.json`. Private keys are never printed.
- Randomized invariant tests for the trust computation
  (`tests/test_trust_invariants.py`, seeded stdlib random, no new deps):
  non-negativity, seed baseline, self-vouch exclusion (SPEC §13),
  revocation monotonicity, inert Sybil disputers (SPEC §8.2), and scope
  isolation. Two further invariants are encoded as strict xfails that
  document a known issue filed for the owner's decision: trust propagation
  is currently order-dependent (identical edge sets yield different scores
  depending on insertion order, and adding a vouch can lower a score),
  because a node is propagated with its trust at first-visit time and never
  re-queued when its trust later improves.

- Public interoperability test vectors under `tests/vectors/` (documented in
  `docs/test-vectors.md`): golden, byte-exact vectors for `did:key`/`did:agent:`
  derivation, JCS canonicalization, the native vouch format + content address,
  the revocation entry format, and the W3C VC export with its `eddsa-jcs-2022`
  proof. `tests/test_vectors.py` asserts the implementation keeps matching
  them, so a second implementation can verify interop against fixed targets
  and format drift cannot sneak in silently.

### Fixed (overnight hardening, 2026-09)
- keys.json (which holds private keys) had the same cross-process
  lost-update window as the vouch store: two concurrent CLI commands
  (keygen/rotate/reissue --commit/import) could silently drop each other's
  identities. All four write paths now run the load -> mutate -> save cycle
  under the advisory file lock. Regression-tested with 6 concurrent
  keygens.
- The README quickstart actually works end-to-end now: it jumped from
  `atar verify` straight to `atar card`/`atar dashboard`, so a new user's
  first run showed "0 vouches" everywhere (the blob was never added to the
  local store). The quickstart now includes the `atar add` step, and
  `atar vouch` prints a hint that the blob is not in the store yet.
  Regression-tested by walking the documented flow via the CLI.
- The file-backed stores (vouches, revocations, disputes) no longer lose
  entries when two processes write concurrently: the load -> mutate -> save
  cycle now runs under a cross-process advisory lock (`<file>.lock`) and
  refreshes/merges from disk before writing. Previously a running
  `atar peer` plus a CLI command (or two parallel syncs) could silently drop
  each other's entries — atomic writes alone never covered that window.
  Regression-tested both interleaved in-process and with 4 concurrent
  writer processes.

### Fixed (senior-engineer pre-release audit, 2026-09)
- Trust computation no longer counts self-vouches: a self-endorsement used to
  inflate the issuer's own transitive trust (0.9 became 1.8); SPEC §13 always
  said self-vouches contribute nothing. Regression-tested.
- Dashboard: the scope label is HTML-escaped in the single-scope renderer.
  The live server reflects `?scope=` into the page, so an unescaped scope was
  a reflected-XSS hole (the same class the stored-XSS regressions cover).
- `atar import --force` now actually stores the vouches it counts (previously
  it reported them as imported without writing anything); forced imports are
  still signature-verified.
- `atar keygen` refuses to silently overwrite an existing identity (the old
  key — and every vouch its DID issued or received — would be orphaned
  without warning); `--force` opts in explicitly.
- `atar reissue` now requires a recorded rotation: without one it would have
  re-signed *other* agents' vouches under the caller's key.
- HTTP gossip intake skips malformed remote entries instead of crashing:
  vouch, revocation, and dispute pulls from untrusted peers are guarded.
- `atar sync --with <url>` reports an unreachable peer and continues, like
  `auto-sync` always did, instead of dying with a traceback.
- The agent registry (`agents/registry.json`, which holds private keys) is
  now written owner-only (`0o600`), matching `keys.json`.
- Store, revocation, dispute, registry and key files are written atomically
  (temp file + rename), so a crash mid-write cannot truncate them.
- `create_vouch` validates the score (finite, in [0.0, 1.0], SPEC §3);
  `atar bootstrap` skips invalid config vouches with a clean message.
- `python -m atar.cli` exposes all commands again (a mid-file `__main__`
  guard used to hide `dispute`/`disputes` from that entry path).
- Docs synced: test counts (235), the `/disputes` peer routes (SPEC §9.1),
  the `dashboard` CLI row (SPEC §14), the insertion-vs-evaluation wording for
  revocation/expiry (SPEC §9), and a stale demo diagram score.
- Release workflow now runs the full test suite before building/publishing.

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
  `docs/standardization/legacy/draft-dbrueck-atar-00.txt` (kept for history).

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
