# ATAR — Agent Trust & Attribution Root

**Protocol Specification — Version 2.0 (Stable)**

> ATAR is the trust layer for autonomous agents. It gives every agent a
> self-sovereign `did:agent:` identity, lets agents vouch for each other's
> capabilities, and lets any observer verify that trust **offline, for $0,
> with no server**. Trust propagates transitively (web-of-trust) and can be
> revoked, expired, or rotated — so the graph stays alive instead of rotting.

Status: **implemented and tested** (78 tests, CI green). This document is the
authoritative wire + algorithm spec.

---

## 1. Design principles

| Principle | Consequence |
|---|---|
| **No server** | Identity = Ed25519 keypair. DID derived from public key. Nothing to host. |
| **Offline-verifiable** | Any vouch verifies with the issuer's public key alone. No round-trip. |
| **Content-addressed** | Every vouch/revocation has a deterministic ID → gossip + dedup without an operator. |
| **Trust is scoped** | An agent is trusted *for a capability*, not universally. |
| **Trust is alive** | Revocation (active kill) + Freshness/TTL (passive decay) + Rotation (recovery). |
| **Decentralized by default** | Peers exchange state over local file sync; no central coordinator. |

---

## 2. Identity — `did:agent:`

An agent identity is an Ed25519 keypair (RFC 8032). The DID is derived **solely**
from the public key — no registration, no server:

```
did:agent:<base58(public_key_raw_bytes)>
```

- `public_key_raw_bytes` = 32-byte Ed25519 public key.
- Encoding: base58 (Bitcoin alphabet), no padding.
- Verification: reconstruct the public key from the DID and use Ed25519
  `verify()`. If the DID does not match the signature, the object is invalid.

---

## 3. Vouch (attestation blob)

A **vouch** is a signed statement by an *issuer* agent endorsing a *subject*
agent for a capability *scope* with a *score*.

```json
{
  "payload": {
    "type": "vouch",
    "issuer": "did:agent:...",
    "subject": "did:agent:...",
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
- `ts` is a Unix epoch timestamp (seconds). **Used for Freshness (§7).**
- `signature` is the hex-encoded Ed25519 signature over the **canonical** JSON
  of `payload` (§4).
- `issuer` MUST be the DID whose private key produced `signature`.

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
2. Assert `issuer` starts with `did:agent:`.
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
  "revoked_by": "did:agent:...",
  "ts": 1690000000,
  "signature": "<base64(ed25519 over \"vid|revoked_by|ts\")>"
}
```

**Rules**
- `vid` = canonical vouch ID (§8).
- `revoked_by` MUST equal the revoked vouch's `issuer` DID.
- `signature` is verified against `revoked_by`'s public key.
- A revoked vouch is treated as **REVOKED** even when its original signature is
  still cryptographically valid.
- Revocation lists are content-addressed and gossip-synced like vouches (§9),
  so a revocation propagates across the network.

---

## 7. Freshness / TTL (passive decay)

Revocation kills trust *actively*. Freshness lets stale trust *decay*: a vouch
older than the active max-age is **EXPIRED** and rejected. This forces periodic
re-vouching, so the graph stays alive instead of accumulating zombie trust.

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
vouch_id = sha256( canonical_json(payload) )      # hex, no "vouch:" prefix
```

Agents keep a local store and compute **transitive trust** from a seed root.

### 8.1 Trust computation

Given a seed DID (your own identity, or a trusted root) and a scope:

- The seed starts at trust `1.0`.
- For each valid, unrevoked, unexpired vouch `issuer → subject (score s)`,
  the subject's trust is increased by `issuer_trust × s × decay^depth`.
- Propagation is bounded (depth ≤ 8, or until contribution < 1e-9).
- Only cryptographically valid vouches are admitted, so a forgery cannot inject
  fake trust.

---

## 9. Gossip / Sync (decentralized exchange)

Peers exchange vouches **and** revocations between their local stores. No
server, no coordinator:

```
atar sync --with <peer_home>      # one-shot exchange
atar auto-sync                    # reads atar_peers.json, for cron/agent hooks
```

- Vouches are added if valid + new (dedup by `vouch_id`).
- Revocations are merged (dedup by `vid`).
- **Defense-in-depth:** revoked or expired vouches are never admitted to the
  store, even via sync (§6/§7 enforced at insertion).
- Revocation lists are merged so a revocation made by one peer reaches all.

---

## 10. Key rotation (recovery without total loss)

When a key leaks, an agent rotates instead of starting from zero.

### 10.1 Rotation statement

```json
{
  "type": "rotation",
  "old_did": "did:agent:...",
  "new_did": "did:agent:...",
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

---

## 11. ATC — Agent Trust Carrier

ATC lets an agent present its identity + vouches **inline** on first contact,
over any existing transport. ATAR rides on top of MCP/A2A/HTTP as a carrier.

### 11.1 Vouch token

```
token = base64url( canonical_json(vouch_blob) )   # no padding
```

The receiver decodes, then runs §5 verification offline.

### 11.2 Agent card

```json
{
  "schema": "atar-agent-card/1.0",
  "did": "did:agent:...",
  "name": "bob",
  "atar": { "vouches": ["<token>", "<token>", "..."] }
}
```

ATAR attaches a verifiable agent card (with revocation-aware verification) to
every brief it sends.

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
| **Tampering** | Any `payload` change invalidates the signature. |
| **Stale trust** | Mitigated by Freshness/TTL (§7) — trust must be renewed. |
| **Key leak** | Mitigated by Revocation (§6) + Rotation (§10) — recover without total loss. |
| **Zombie trust** | Mitigated by Revocation + Freshness combined. |
| **Sybil** | **Out of scope.** Free identity means anyone can mint agents and
  self-vouch. Self-vouches contribute nothing (issuer must already be trusted).
  Real trust requires real agents vouching. ATAR provides the mechanism;
  reputation emerges from the graph, not the protocol. |

---

## 14. CLI surface (reference)

| Command | Purpose |
|---|---|
| `atar keygen --name X` | generate identity, print DID |
| `atar vouch --from A --for <did> --score S --scope C` | create signed vouch |
| `atar verify [--max-age N]` | VALID / REVOKED / EXPIRED / INVALID |
| `atar revoke <vouch.json>` | add to local revocation list |
| `atar add <vouch.json>` | add to store (rejects revoked/expired) |
| `atar list` / `atar scopes` | inspect store / list scopes |
| `atar sync --with <peer>` / `atar auto-sync` | gossip exchange |
| `atar rotate --name X` | generate new key + rotation statement |
| `atar reissue --name X [--commit]` | re-sign under new key (commit = +add +revoke old) |
| `atar bootstrap --config agents.toml` | reproducible network |
| `atar serve [--port P]` | live multi-scope dashboard |
| `atar audit [--max-age N]` | health-check: counts valid/revoked/expired/invalid per scope |
| `atar export [--include-keys] FILE` | bundle trust graph (or full identity) to `.atpkg` |
| `atar import FILE` | restore a network bundle into the local store |

---

## 15. Status & roadmap

**Implemented (phases 1–27b):** identity, vouch, ATC, transparency/transitive
trust, revocation (local + gossip + dashboard + verify + add/sync), freshness/
TTL, key rotation (rotate + reissue + commit), gossip sync + auto-sync,
multi-scope dashboard + live server, real-agent bootstrap (ATAR + daily-brief
cron), professional repo (LICENSE/CI/templates).

**Not yet implemented:** wider real-agent adoption (§14 `bootstrap` is the
path), formal RFC publication (this spec is the draft for it).
