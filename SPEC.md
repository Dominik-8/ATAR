# ATAR — Agent Trust & Attribution Root

**Protocol Specification — Version 2.0 (Stable)**

> ATAR is the trust layer for autonomous agents. It gives every agent a
> self-sovereign `did:key` identity (legacy `did:agent:` DIDs stay valid, §2.1),
> lets agents vouch for each other's
> capabilities, and lets any observer verify vouch signatures **offline, for
> $0, with no server**. (Revocation and expiry state is data, not signatures:
> it propagates peer-to-peer via gossip, §9.) Trust propagates transitively
> (web-of-trust) and can be revoked, expired, or rotated — so the graph stays
> alive instead of rotting.

Status: **implemented and tested** (267 tests, CI green). This document is the
authoritative wire + algorithm spec.

---

## 1. Design principles

| Principle | Consequence |
|---|---|
| **No server** | Identity = Ed25519 keypair. DID derived from public key. Nothing to host. |
| **Offline-verifiable signatures** | Any vouch *signature* verifies with the issuer's public key alone. No round-trip. Revocation/freshness *status* is current only as of the last gossip sync (§9). |
| **Content-addressed** | Every vouch/revocation has a deterministic ID → gossip + dedup without an operator. |
| **Trust is scoped** | An agent is trusted *for a capability*, not universally. |
| **Trust is alive** | Revocation (active kill) + Freshness/TTL (passive decay) + Rotation (recovery). |
| **Decentralized by default** | Peers exchange state over local file sync; no central coordinator. |

---

## 2. Identity — `did:key`

An agent identity is an Ed25519 keypair (RFC 8032). The DID is derived **solely**
from the public key — no registration, no server:

```
did:key:z<base58btc( 0xED 0x01 || public_key_raw_bytes )>
```

- `did:key` is the W3C DID method for pure cryptographic keys: self-describing,
  no registry, no resolution step — the DID *is* the key.
- Multicodec prefix `ed25519-pub` = `0xED 0x01` (unsigned varint); multibase
  prefix `z` = base58btc (Bitcoin alphabet, no padding).
- `public_key_raw_bytes` = 32-byte Ed25519 public key.
- Verification: reconstruct the public key from the DID and use Ed25519
  `verify()`. If the DID does not match the signature, the object is invalid.

### 2.1 Legacy `did:agent:` identifiers (migration)

Identifiers minted before the 2026-09 standards realignment used ATAR's own
spelling:

```
did:agent:<base58(public_key_raw_bytes)>
```

Both encodings embed the **same 32 raw key bytes** — a `did:agent:` DID is
simply the unframed form of the same identity. Migration therefore needs no
re-issuance and loses nothing:

1. **Decoding.** Every component that reconstructs a public key from a DID
   accepts BOTH spellings. Old vouches, revocations, rotation statements, and
   agent cards verify unchanged — signatures stay valid because the signed
   bytes are untouched.
2. **Aliasing.** A `did:agent:` DID and the `did:key` DID of the same key are
   one identity. Every comparison that decides trust — revocation
   issuer-matching (§6), transitive-trust graph nodes (§8.1), agent-card
   subject collection (§11.2) — compares canonical aliases: the `did:key` form.
3. **Canonicalization on write.** Everything ATAR newly produces (`keygen`,
   vouches, claims, rotations, cards) records the `did:key` form, even when the
   input was a legacy DID.
4. **Import.** Stores and keyfiles holding `did:agent:` identities import
   unchanged; the `did:key` alias is computed on read. There is no cut-over
   date and no flag day.

---

## 3. Vouch (attestation blob)

A **vouch** is a signed statement by an *issuer* agent endorsing a *subject*
agent for a capability *scope* with a *score*.

```json
{
  "payload": {
    "type": "vouch",
    "issuer": "did:key:...",
    "subject": "did:key:...",
    "score": 0.95,
    "scope": "coding",
    "claim": null,
    "ts": 1690000000
  },
  "signature": "<hex(ed25519(canonical_payload_bytes))>"
}
```

**Rules**
- `score` ∈ [0.0, 1.0], float.
- `scope` is a free-form string naming a capability area
  (`coding`, `research`, `finance`, `intelligence`, …).
- `claim` is optional free text, used only for *self-vouches*
  (`issuer == subject`).
- `evidence` is an optional list of references (URIs or free-form pointers)
  to the observations behind the score (§3.2). When present it is part of the
  signed payload — and of the content address (§8).
- `ts` is a Unix epoch timestamp (seconds). **Used for Freshness (§7).**
- `signature` is the hex-encoded Ed25519 signature over the **canonical** JSON
  of `payload` (§4).
- `issuer` MUST be the DID whose private key produced `signature`.

### 3.1 Vouches as W3C Verifiable Credentials (interop bridge)

The native vouch above stays ATAR's internal format. For interop, any vouch
can be exported as a W3C Verifiable Credential (VC 2.0) — the bridge that lets
standard VC tooling check an ATAR vouch.

Field mapping:

| Vouch payload | Verifiable Credential |
|---|---|
| `issuer` | `issuer` (canonical `did:key`, §2.1) |
| `subject` | `credentialSubject.id` |
| `scope` | `credentialSubject["atar:scope"]` |
| `score` | `credentialSubject["atar:score"]` |
| `claim` | `credentialSubject["atar:claim"]` (omitted when null) |
| `ts` | `validFrom` (ISO 8601 UTC) |

```json
{
  "@context": ["https://www.w3.org/ns/credentials/v2",
               {"atar": "https://github.com/Dominik-8/ATAR/ns#"}],
  "type": ["VerifiableCredential", "ATARVouch"],
  "issuer": "did:key:z6Mk...",
  "validFrom": "2026-09-08T10:00:00Z",
  "credentialSubject": {
    "id": "did:key:z6Mk...",
    "atar:scope": "coding",
    "atar:score": 0.95
  },
  "proof": {
    "type": "DataIntegrityProof",
    "cryptosuite": "eddsa-jcs-2022",
    "created": "2026-09-08T10:00:00Z",
    "verificationMethod": "did:key:z6Mk...#z6Mk...",
    "proofPurpose": "assertionMethod",
    "proofValue": "z<base58btc(ed25519 signature)>"
  }
}
```

**Rules**
- Proof: Data Integrity `eddsa-jcs-2022` — JCS (RFC 8785) canonicalization,
  SHA-256, Ed25519. Signing input: `sha256(jcs(proofOptions)) ||
  sha256(jcs(credential))`; `proofValue` is the multibase (base58btc, `z`)
  signature.
- `verificationMethod` MUST belong to `issuer` (`<issuer>#<multibase>`);
  verification is offline (the key comes from the `did:key`; contexts are
  identifiers and are never fetched).
- Export re-signs: the VC proof is a fresh signature by the issuer over the VC,
  so exporting requires the issuer's key. Importing a VC into a native store
  likewise goes through re-issuance — the native signature signs different
  bytes, so there is no lossless VC→vouch conversion.
- Revocation (§6) and TTL (§7) deliberately stay ATAR-side: the VC proves the
  signed attestation; *current* trust state comes from the ATAR store.

CLI: `atar vc-export VOUCH --from NAME` (issuer-signed export),
`atar vc-verify VC` (offline proof verification).

### 3.2 Score semantics — what `score 0.95` means

A score is a **dimensionless confidence** in [0.0, 1.0]: the issuer's
subjective probability that the subject will perform reliably in `scope`,
*as observed by the issuer*. It is not a measurement with physical units and
never aggregates across scopes — scores compare only within a scope and are
only as meaningful as the issuer behind them (which is why trust is computed
transitively, §8.1: an unknown issuer's 0.99 contributes nothing).

Calibration anchors (recommended, not enforced):

| Score | Meaning |
|---|---|
| 1.0 | The issuer stakes its own reputation without reservation (e.g. its own subagent, long flawless track record). |
| 0.8 | Repeatedly observed good performance. Default for a single successfully observed task (see the CrewAI plugin). |
| 0.5 | Neutral: no negative evidence, no strong positive evidence. |
| 0.2 | Weak or indirect evidence only. |
| 0.0 | No confidence — do not vouch at all (a 0-scored vouch adds no trust). |

**Evidence references.** Scores SHOULD carry their basis in the optional
`evidence` list: URIs or pointers to the tasks, reviews, logs, or documents
the score rests on (`https://…/task/42`, `ticket:ATAR-7`, a content hash).
Evidence lets a verifier *re-check the basis* instead of trusting the number
blindly, and makes scores comparable across operators: two 0.9 vouches with
inspectable evidence beat one bare 0.99. Evidence is signed with the vouch
and joins its content address — it cannot be edited after the fact.

TTL interaction (§7): re-signing refreshes the *freshness* of the claim, not
its evidence. Honest re-vouching after new observations SHOULD reference the
new evidence; mechanical re-signing keeps the old evidence and only resets
the clock.

---

## 4. Canonical serialization

For signing and verifying, `payload` is serialized deterministically:

```python
json.dumps(payload, sort_keys=True, separators=(",", ":"))
```

This guarantees byte-identical input for signer and verifier.

---

## 5. Verification algorithm

1. Parse `payload` and `signature`.
2. Assert `issuer` is a decodable `did:key` (or legacy `did:agent:`, §2.1) DID.
3. Reconstruct the issuer public key from the DID (base58-decode, 32 raw bytes,
   `Ed25519PublicKey.from_public_bytes`).
4. Compute canonical bytes of `payload` (§4).
5. `public_key.verify(bytes.fromhex(signature), canonical_bytes)`.
6. If any step raises → **INVALID**. Otherwise → signature valid.

A vouch is **trust-valid** only if, *additionally*:
- it is **not** on the local revocation list (§6), and
- it is **not** expired under the active TTL (§7).

---

## 6. Revocation (signed, local/P2P)

A vouch may be **revoked** by its issuer. Revocation is modelled on CRL/OCSP
but local and peer-propagated — no CA.

One revocation entry:

```json
{
  "vid": "<canonical vouch id>",
  "revoked_by": "did:key:...",
  "ts": 1690000000,
  "signature": "<base64(ed25519 over \"vid|revoked_by|ts\")>"
}
```

**Rules**
- `vid` = canonical vouch ID (§8).
- `revoked_by` MUST equal the revoked vouch's `issuer` DID.
- `signature` is verified against `revoked_by`'s public key — and this check
  is **enforced at every intake path** (sync, import, load), not only at
  definition time: an entry whose signature does not verify is dropped,
  exactly like a forged vouch (§9 defense-in-depth). Both DID spellings embed
  the raw Ed25519 key (§2), so any peer can verify any entry standalone.
- A revocation only *applies* to a vouch when `revoked_by` equals the vouch's
  `issuer`. A well-formed entry signed by anyone else is inert: it may sit in
  a list, but it revokes nothing.
- A revoked vouch is treated as **REVOKED** even when its original signature is
  still cryptographically valid.
- Revocation lists are content-addressed and gossip-synced like vouches (§9),
  so a revocation propagates across the network.

---

## 7. Freshness / TTL (passive decay)

Revocation kills trust *actively*. Freshness lets stale trust *decay*: a vouch
older than the active max-age is **EXPIRED** and rejected. This forces periodic
re-vouching, so the graph stays alive instead of accumulating zombie trust.

Honest semantics: TTL forces the *issuer to re-sign* (a freshness signal —
"the issuer still stands behind this"), not the subject to *re-earn* trust.
An issuer can re-sign mechanically; TTL bounds how long a silent issuer's
vouches keep working, it does not by itself create new evidence of
trustworthiness.

```
is_fresh(vouch, ttl) := (now - vouch.payload.ts) <= ttl
```

Default recommendation: `ttl = 180 days`. A verifier MAY set a stricter
`--max-age`; absence of a max-age means trust never expires *except* by
revocation.

---

## 8. Content addressing (Transparency)

Vouches and revocations are content-addressed so they gossip and dedup without
an operator:

```
vouch_id = "vouch:" + sha256( canonical_json(payload without ts) )
```

The `ts` field is excluded from the hash: a vouch is identified by its
*claim* (issuer, subject, scope, score, claim, evidence), not by when it was
signed. Two vouches making the same claim at different times collapse to one
ID, so re-issues and re-bootstraps dedup instead of duplicating the graph.

Agents keep a local store and compute **transitive trust** from a seed root.

### 8.1 Trust computation

Given a seed DID (your own identity, or a trusted root) and a scope:

- The seed starts at trust `1.0`.
- For each valid, unrevoked, unexpired vouch `issuer → subject (score s)`,
  the subject's trust is increased by `issuer_trust × s × decay^depth`.
- Propagation is bounded (depth ≤ 8, or until contribution < 1e-9).
- Only cryptographically valid vouches are admitted, so a forgery cannot inject
  fake trust.

### 8.2 Disputes — signed negative signals

Revocation (§6) belongs to the issuer. Everyone else gets the **dispute**: a
signed warning against a *foreign* vouch, gossiped like any other object.

```json
{
  "vid": "<canonical vouch id>",
  "disputed_by": "did:key:...",
  "reason": "<free text>",
  "ts": 1690000000,
  "signature": "<base64(ed25519 over \"vid|disputed_by|reason|ts\")>"
}
```

**Rules**
- `disputed_by` MUST NOT be the vouch's `issuer` — the issuer's negative
  signal is revocation (§6). Where the vouch is known, issuer-signed disputes
  are rejected at intake.
- Signatures are verified at every intake path (sync, import, load, HTTP
  peer), exactly like revocations (§6). A forged dispute never enters a list.
- Disputes are content-addressed by `vid|disputed_by|reason` and dedup; they
  gossip over both transports (§9 filesystem, §9.1 HTTP `/disputes`).
- A dispute **never invalidates** a vouch. It is advisory: `atar verify`
  still prints VALID but notes disputes on record; `atar disputes` lists them.
- **Trust computation:** `compute_trust` runs two passes when a dispute list
  is present. Pass 1 establishes trust ignoring disputes; pass 2 excludes any
  vouch carrying a valid dispute from a disputer whose pass-1 trust is
  ≥ 0.5. A warning counts only from inside the trusted graph — a Sybil
  minting disputes cannot move anyone's score (§13).

---

## 9. Gossip / Sync (decentralized exchange)

Peers exchange vouches **and** revocations between their local stores. No
server, no coordinator:

```
atar sync --with <peer_home>      # one-shot exchange
atar auto-sync                    # reads atar_peers.json, for cron/agent hooks
```

- Vouches are added if valid + new (dedup by `vouch_id`); vouches revoked by
  their issuer are never admitted.
- Revocations are merged (dedup by `vid`) after signature verification (§6);
  when the revoked vouch is known at merge time, non-issuer entries are
  rejected at intake — and a non-issuer entry never applies at evaluation,
  wherever it came from.
- **Defense-in-depth:** vouches revoked by their issuer are never admitted
  to the store, whatever transport they arrive on (§6 enforced at insertion).
  Expiry (§7) is enforced at *evaluation* time — verify, trust computation,
  audit — because expiry is relative to the current time: a vouch admitted
  today may expire tomorrow, so insertion-time rejection cannot work.
- Revocation lists are merged so a revocation made by one peer reaches all.

### 9.1 HTTP peer transport

Filesystem sync requires a shared disk. To gossip between **separate
operators**, any peer can expose its local store over a slim HTTP endpoint —
still content-addressed, still serverless in the trust sense (every peer is
equal; there is no central coordinator or registry):

```
atar peer --port 8790            # serve this ATAR_HOME over HTTP
atar sync --with http://host:8790   # exchange with a remote peer
# atar_peers.json entries may be URLs too (auto-sync handles both)
```

Endpoint surface (JSON only):

| Route | Semantics |
|---|---|
| `GET /` | peer info: `{"protocol": "atar-peer/1.0", "vouches": n, "revocations": m, "disputes": k}` |
| `GET /vouches` | the peer's full vouch set |
| `POST /vouches` | one vouch blob or `{"vouches": [...]}` → `{"added", "duplicates", "rejected"}` |
| `GET /revocations` | the peer's full revocation list |
| `POST /revocations` | one entry or `{"revocations": [...]}` → `{"added", "duplicates", "rejected"}` |
| `GET /disputes` | the peer's full dispute list (§8.2) |
| `POST /disputes` | one entry or `{"disputes": [...]}` → `{"added", "duplicates", "rejected"}` |

Malformed remote entries are skipped, never fatal: a peer (or anything
answering on that port) cannot crash a sync with junk data.

Intake rules are identical to filesystem sync (§6, §9): vouch signatures are
verified, issuer-revoked vouches are never admitted, revocation
entries are signature-verified and issuer-bound when the vouch is known. The
transport is dumb on purpose — all trust decisions stay in the store. Peers
exchange full sets and dedup by content address, so sync is idempotent and
order-independent. The endpoint binds to `127.0.0.1` by default; exposing it
to a network is the operator's explicit choice (`--bind`).

---

## 10. Key rotation (recovery without total loss)

When a key leaks, an agent rotates instead of starting from zero.

### 10.1 Rotation statement

```json
{
  "type": "rotation",
  "old_did": "did:key:...",
  "new_did": "did:key:...",
  "ts": 1690000000,
  "signature": "<hex(ed25519 over canonical rotation payload, signed by OLD key)>"
}
```

The **old** key signs "I am now `<new_did>`". Verifiers confirm continuity:
`verify_rotation` checks the statement is genuinely signed by `old_did`.

### 10.2 Re-issue + commit

After rotation, the agent re-signs its out-going vouches under the **new** key
(preserving `score`/`scope`/`subject`, stamping a fresh `ts`). With
`atar reissue --commit`, the re-issued vouches are written to the store **and**
the old-key vouches are revoked — the old key is fully retired, trust carried
forward. The trust graph survives a key compromise.

The retirement revocations are signed with the **old** key: §6 requires
`revoked_by` to be the vouch's issuer, and only the old key can sign for the
old DID. `atar rotate` therefore retains the old private key locally for
exactly this purpose, and `reissue --commit` deletes it afterwards.

---

## 11. ATC — Agent Trust Carrier

ATC lets an agent present its identity + vouches **inline** on first contact,
over any existing transport. ATAR rides on top of MCP/A2A/HTTP as a carrier.

### 11.1 Vouch token

```
token = base64url( canonical_json(vouch_blob) )   # no padding
```

The receiver decodes, then runs §5 verification offline.

### 11.2 Agent card (A2A-compatible, signed)

The card is a standard **A2A Agent Card** — any A2A-speaking system can read
it. ATAR's trust data rides in a declared capability extension, and the whole
card is signed, so the trust data is tamper-evident:

```json
{
  "name": "bob",
  "description": "ATAR agent 'bob' - identity and vouches carried in the ATAR trust extension",
  "url": "urn:atar:agent:did:key:z6Mk...",
  "version": "1.0.0",
  "capabilities": {
    "extensions": [{
      "uri": "https://github.com/Dominik-8/ATAR/ext/atar-trust/1.0",
      "description": "ATAR trust data: identity, vouch tokens, optional PoP",
      "required": false,
      "params": {
        "identity": "did:key:z6Mk...",
        "vouches": ["<token>", "<token>", "..."],
        "proof": { "nonce": "...", "signature": "..." }
      }
    }]
  },
  "defaultInputModes": ["application/json"],
  "defaultOutputModes": ["application/json"],
  "skills": [],
  "signatures": [{
    "protected": "<b64u({\"alg\":\"EdDSA\",\"kid\":\"did:key:z6Mk...#z6Mk...\",\"typ\":\"JWS\"})>",
    "signature": "<b64u(ed25519 signature)>"
  }]
}
```

**Rules**
- The extension params carry the presented `identity` DID, the vouch tokens
  (§11.1), and — when challenged — the `proof` (§11.3).
- `signatures` follows the A2A Agent Card signing convention (JWS flattened
  JSON entries): the signing input is `b64u(protected) || "." ||
  b64u(payload)` where the payload is the canonical JSON (§4) of the card
  minus `signatures`; `kid` MUST identify the presented identity (§2.1 alias
  rules apply).
- `url` is the agent's A2A endpoint when it has one; offline agents use a
  `urn:atar:agent:<did>` identifier URI.
- An agent attaches its card (with revocation-aware verification of the
  vouches) to every brief it sends.
- Legacy `atar-agent-card/1.0` cards stay verifiable: verifiers read the old
  standalone layout as the same trust data, and report the absent signature
  as "unsigned", not "invalid".

### 11.3 Proof of possession (challenge–response)

A card alone proves only that *someone* holds the subject's vouches — copied
bytes present identically. To prove the presenter controls the card's key,
the recipient runs a nonce challenge:

1. The recipient generates a fresh nonce (≥128-bit random) and sends it to
   the presenter.
2. The presenter signs `atar-pop/1|<did>|<nonce>` with the private key behind
   the card's DID and attaches
   `"proof": {"nonce": "<nonce>", "signature": "<hex ed25519>"}` to the card.
3. The recipient reconstructs the public key from the card's DID, verifies
   the signature, and checks the nonce matches the one it sent.

A fresh nonce per presentation prevents replay of a captured proof.

CLI: `atar card --name N --challenge NONCE` embeds the proof;
`atar verify-card CARD --challenge NONCE` enforces it (exit 1 on failure).

---

## 12. Multi-scope & dashboard

Trust is scoped (§3). The dashboard renders **one section per scope**
(`atar serve`, `atar scopes`), so an operator sees at a glance *who is trusted
for what*. Revoked agents are shown as **REVOKED** (red) in the dashboard and
via `atar verify` (exit code 2) and `atar verify-card`.

---

## 13. Threat model (honest)

| Threat | Status |
|---|---|
| **Forgery** | Impossible without the issuer's private key (Ed25519). |
| **Card copying** (presenting someone else's agent card) | Mitigated by proof-of-possession (§11.3): the recipient's fresh nonce must be signed by the card's key. |
| **Tampering** | Any `payload` change invalidates the signature. |
| **Forged revocation** | Rejected at intake: every revocation entry's signature is verified against `revoked_by` on sync/import/load (§6). |
| **Cross-key revocation** (attacker revokes someone else's vouch with their own key) | Inert: a revocation applies only when `revoked_by` is the vouch's issuer (§6). |
| **Stale trust** | Mitigated by Freshness/TTL (§7) — trust must be renewed. A *future-dated* `ts` is treated as fresh (an issuer can postpone its own vouch's expiry); issuers gain nothing by doing this visibly, and verifiers MAY reject timestamps beyond local clock skew. |
| **Key leak** | Mitigated by Revocation (§6) + Rotation (§10) — recover without total loss. |
| **Zombie trust** | Mitigated by Revocation + Freshness combined. |
| **Undisputed fraud** (third party observes a bad vouch, issuer stays silent) | Mitigated by disputes (§8.2): any agent can file a signed warning; trusted disputers discount the vouch in trust computation. |
| **Dispute spam / Sybil smear** | Disputes from untrusted identities are stored and shown but move no scores (§8.2 threshold). |
| **Sybil** | **Out of scope.** Free identity means anyone can mint agents and
  self-vouch. Self-vouches contribute nothing (issuer must already be trusted).
  Real trust requires real agents vouching. ATAR provides the mechanism;
  reputation emerges from the graph, not the protocol. |

---

## 14. CLI surface (reference)

| Command | Purpose |
|---|---|
| `atar keygen --name X` | generate identity, print DID |
| `atar identities` | list local identities (name -> DID) |
| `atar vouch --from A --for <did> --score S --scope C` | create signed vouch |
| `atar verify [--max-age N]` | VALID / REVOKED / EXPIRED / INVALID |
| `atar card --name X [--challenge N]` | build an agent card (with PoP proof when challenged) |
| `atar verify-card PATH [--challenge N]` | verify card vouches (+ PoP proof when challenged) |
| `atar revoke <vouch.json>` | add to local revocation list |
| `atar add <vouch.json>` | add to store (rejects revoked/expired) |
| `atar list` / `atar scopes` | inspect store / list scopes |
| `atar sync --with <peer>` / `atar auto-sync` | gossip exchange (directory or `http(s)://` peer URL) |
| `atar dashboard [--seed DID] [--scope C] [--out F]` | render the Know-Your-Agent HTML dashboard |
| `atar peer [--port P] [--bind B]` | serve the local store as an HTTP gossip peer (§9.1) |
| `atar dispute VOUCH --from N --reason R` / `atar disputes` | file / list signed disputes against foreign vouches (§8.2) |
| `atar rotate --name X` | generate new key + rotation statement |
| `atar reissue --name X [--commit]` | re-sign under new key (commit = +add +revoke old) |
| `atar bootstrap --config agents.toml` | reproducible network |
| `atar serve [--port P]` | live multi-scope dashboard |
| `atar audit [--max-age N]` | health-check: counts valid/revoked/expired/invalid per scope |
| `atar export [--include-keys] FILE` | bundle trust graph (or full identity) to `.atpkg` |
| `atar import FILE` | restore a network bundle into the local store |
| `atar watch [--interval S] [--once]` | monitor health; alert on unhealthy transition |
| `atar issue --from N --for DID --scope S --score X [--claim C]` | issue a signed capability claim (standalone file) |
| `atar verify-claim FILE` | verify a signed capability claim (independent of store) |
| `atar vc-export F --from N` | export a vouch as a W3C Verifiable Credential (§3.1) |
| `atar vc-verify FILE` | verify an exported VC offline (§3.1) |

---

## 15. Status & roadmap

**Realignment (2026-09-08):** ATAR is moving onto the standard formats —
`did:key` identity, W3C Verifiable Credentials for vouches, A2A-compatible
signed agent cards — while keeping its core (transitive trust, lifecycle,
tooling). The staged plan (A: honesty + security, B: standards alignment,
C: network/plugin/standardization) lives in
[ROADMAP.md](ROADMAP.md); the `did:agent:` → `did:key` decision is recorded
in issue #2.

**Implemented (phases 1–31):** identity, vouch, ATC, transparency/transitive
trust, revocation (local + gossip + dashboard + verify + add/sync), freshness/
TTL, key rotation (rotate + reissue + commit), gossip sync + auto-sync,
multi-scope dashboard + live server, real-agent bootstrap (seed_agent + reporting_agent
cron), issue/verify-claim (Phase 26), audit/export/import/watch tooling,
professional repo (LICENSE/CI/templates). Full CLI surface in §14.

**Not yet implemented:** wider real-agent adoption across distinct owners
(§14 `bootstrap` is the path), formal RFC publication (this spec is the draft
for it).
