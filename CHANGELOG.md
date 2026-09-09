# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- MCP server (`atar mcp`, optional extra `atar-trust[mcp]`): ATAR's trust
  surface as a read-only MCP server over stdio. Tools: `verify_vouch`,
  `verify_vouch_token`, `verify_agent_card`, `trust_scores` (the same
  transitive computation as `atar graph`, honoring revocation/TTL/disputes),
  `vouches_for` and `list_known_agents`. Any MCP host (Claude, ChatGPT,
  Cursor, Copilot, ...) can verify agent trust artifacts against the
  operator's local store. The server never signs: reputation is minted by
  the operator through the CLI, never by a connected client. Runs the real
  MCP protocol in tests via the in-memory client.
- JSON Schemas for every wire format (`schemas/`, draft 2020-12): native
  vouch, VC export, revocation, dispute, rotation and the A2A-compatible
  agent card with the ATAR trust extension. A second implementation can now
  validate ATAR messages with any standard validator instead of reading
  Python code; `tests/test_schemas.py` validates the golden vectors against
  the schemas in both directions (vectors pass, broken instances fail), so
  schemas, vectors and implementation cannot drift apart without a red build.
- Property-based fuzz coverage (`tests/test_property_fuzz.py`, hypothesis
  pinned in the dev extra): DID encode/decode round-trips and graceful
  rejection of arbitrary input, JCS canonicalization fixed-point and key-order
  invariance, graceful rejection of arbitrary JSON/strings/bytes by every
  verification entry point (`verify_vouch`, `verify_token`,
  `verify_credential`, `verify_card_signature`, `verify_agent_card`,
  `verify_revocation_entry`, `verify_dispute_entry`, `verify_rotation`), and
  positive round-trips for vouch tokens, the VC bridge, disputes and
  rotations.

### Fixed
- `verify_agent_card` and `verify_token` now reject structurally malformed
  input gracefully instead of crashing: non-dict cards, `capabilities`/
  `extensions`/`params` of the wrong type, and non-string tokens previously
  raised `AttributeError`/`TypeError` at the trust-verification boundary
  (found by the new fuzz tests).
- Standardization package (review-ready, not submitted): the complete
  Internet-Draft `draft-dbrueck-atar-lifecycle-00` (kramdown source plus
  validated RFCXML, text and HTML renderings) specifying the attestation
  lifecycle (revocation, freshness/TTL, key rotation, disputes, gossip
  transport, score semantics); the polished W3C Agent Identity Registry
  Protocol Community Group intro post; and a click-by-click review and
  submission guide (`docs/standardization/`).

- CI packaging gate: every push now builds the sdist and wheel, installs
  both into clean environments, and smoke-tests the installed CLI
  (`keygen` -> `vouch` -> `verify` roundtrip plus a version match against
  `pyproject.toml`), so a broken distribution fails CI before a release.

### Changed
- Applied the deferred repo-wide `ruff format` sweep (94 files). Purely
  cosmetic: every changed file is AST-identical to its previous revision and
  the full test suite passes unchanged. No behavior change.

## [1.0.0a2] - 2026-09-09

### Added (overnight hardening, 2026-09)
- Two more trust invariants pinned under random graphs: a dense isolated
  Sybil cluster vouching only for itself earns exactly zero trust (nodes
  unreachable from the seed never appear in the trust map), and
  re-issuing a vouch with a fresh timestamp (SPEC §7 refresh) dedups by
  claim and never double-counts trust weight.
- PoP hardening pins: two new tests lock the proof-of-possession DID
  binding - a proof made for one card's DID can never validate against a
  different card even when the same nonce is reused (cross-card replay).
- Dashboard cards no longer print the agent name twice (header + body);
  the revoked strikethrough moved to the card header. Verified by
  rendered screenshot.
- DID arguments now accept local identity names everywhere the docs told
  users to paste a DID: `atar vouch --for`, `atar issue --for`,
  `atar graph --seed`, `atar dashboard --seed` (`resolved 'bob' ->
  did:key:...` is echoed on resolution; unknown names get a clear error).
  The README quickstart no longer requires copy-pasting DIDs.
- Export/import round-trip now carries the whole trust graph: bundles
  include disputes (previously dropped - silent loss of negative signals,
  SPEC 8.2) and agent names from BOTH identity stores (registry AND
  keys.json; previously registry only, and import never restored them).
  Import restores names DID-only into `known-agents.json` (merged at the
  lowest priority by `known_agent_names()`), never into keys.json - no
  private material is implied - and never clobbers an existing local
  identity name without `--force`. Dispute import uses the same verified
  intake as gossip.
- Peer endpoint hardening: unexpected intake errors now return a 500 JSON
  body instead of dropping the connection mid-thread (matters more now that
  the peer is multi-threaded), and a non-list batch payload
  (`{"vouches": {...}}`) gets a clear 400 instead of silently reporting
  zero counts. POST routing deduplicated across the three endpoints.
- Docs coherence sweep: SPEC §14 gained the missing `atar graph` row;
  `docs/test-vectors.md` section references corrected (JCS is §4, VC
  mapping is §3.1, rotation is §10.1); ROADMAP now marks stages A1-A3 and
  B1-B3 as shipped 2026-09-08 (verified against closed issues #2-#5 and
  the landing commits); SPEC §15 status paragraph updated from "moving
  onto" to the actual shipped state; the stale 3-command usage example in
  the `cli.py` docstring now points at `atar --help` / SPEC §14.
- Fixed CI red since 5aa3ad8: `.gitignore` generated-artifact patterns
  (`agent-card.json`, `rotation.json`, `vouch*.json`, ...) were
  repo-wide and swallowed same-named fixtures under `tests/vectors/` —
  green locally, FileNotFoundError on CI. All artifact patterns are now
  root-scoped, the two fixtures are tracked, and a regression test fails
  at add-time if any vector ever matches an ignore rule again
  (`git check-ignore --no-index`, so force-adding cannot mask it).
- The HTTP gossip peer now serves with `ThreadingHTTPServer`: gossip
  requests no longer serialize behind one slow peer. Made safe by the new
  store locks; regression-tested with 4 concurrent HTTP clients posting
  disjoint vouches (all 16 land).
- `atar graph` resolves known agent names (registry + keygen identities)
  in the trust ranking, like the dashboard does, instead of raw DIDs only.
- `atar identities`: list the local identities (name -> DID). A new user
  following the quickstart had no way to see the identities they created —
  `atar list` shows vouches, not identities, and the only record was inside
  `keys.json`. Private keys are never printed.
- Randomized invariant tests for the trust computation
  (`tests/test_trust_invariants.py`, seeded stdlib random, no new deps):
  non-negativity, seed baseline, self-vouch exclusion (SPEC §13),
  revocation monotonicity, inert Sybil disputers (SPEC §8.2), and scope
  isolation.

- Extended the vectors to the remaining wire formats: ATC vouch token
  (§11.1), the A2A-compatible signed agent card (§11.2), and the signed
  key-rotation statement (§7).
- Public interoperability test vectors under `tests/vectors/` (documented in
  `docs/test-vectors.md`): golden, byte-exact vectors for `did:key`/`did:agent:`
  derivation, JCS canonicalization, the native vouch format + content address,
  the revocation entry format, and the W3C VC export with its `eddsa-jcs-2022`
  proof. `tests/test_vectors.py` asserts the implementation keeps matching
  them, so a second implementation can verify interop against fixed targets
  and format drift cannot sneak in silently.

### Fixed (2026-09-09, owner-approved algorithm correction)
- **Trust propagation is now order-independent and monotone** (SPEC §8.1,
  owner decision 2026-09-09). The previous traversal propagated each node
  with its trust at first-visit time and never re-queued a node whose trust
  later improved, so identical edge sets produced different scores depending
  on vouch insertion order, and adding a valid vouch could lower an existing
  score. `compute_trust` now computes the bounded fixed point over all paths
  (depth ≤ 8, contribution floor 1e-9, decay applied per hop), summing
  contributions in canonical (sorted) edge order so identical edge sets are
  bit-identical. Computed scores change where the old traversal dropped
  late-arriving contributions — this is the intended correction, approved
  by the owner ahead of 1.0.0a2. The two strict-xfail repro tests are now
  permanent passing regressions; new tests pin exact cycle values at the
  depth bound, the depth-8 cap itself, and bit-identical scores across all
  insertion orders of random graphs. Performance is unchanged in practice
  (~100 ms per computation on a dense 200-node / 2000-vouch graph, within
  ~4% of the old traversal; real graphs are far smaller).

### Fixed (overnight hardening, 2026-09)
- A network without a configured trust seed no longer renders a bogus
  anonymous "?" card with `trust=1.000` on the live dashboard (a seedless
  computation artifact shown as if it were a trusted agent). Both render
  paths now show an honest setup notice instead. Visually verified.
- Dashboards and the live server showed "?" for every agent (and "via ?"
  for trust paths) when the network was built with plain CLI commands —
  names resolved only from the bootstrap registry, never from keys.json.
  Both renderers now use `known_agent_names()` (registry + keygen
  identities). Visually verified.
- agents/registry.json (bootstrap identities, also private-key-bearing) had
  the same race; `register` and `seed_trust_root` now reload under the lock
  before writing. Regression-tested with 6 concurrent registrations.
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
- README install led with install-from-source while the stale PyPI
  package (`1.0.0a1`, pre-realignment) was pending update; `1.0.0a2`
  replaces it on PyPI.
- Package metadata and repo description reflect the did:key realignment;
  this release packages master as `1.0.0a2`.

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

[1.0.0a2]: https://github.com/Dominik-8/ATAR/compare/v1.0.0a1...v1.0.0a2
[1.0.0a1]: https://github.com/Dominik-8/ATAR/releases/tag/v1.0.0a1
