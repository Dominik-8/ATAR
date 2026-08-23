# ATAR Protocol Specification (Draft, Phase 1)

This document defines the ATAR wire format for agent identity and attestation.
It is intentionally minimal, serverless, and verifiable offline.

## 1. Identity (`did:agent:`)

An agent identity is an Ed25519 key pair (RFC 8032). The agent ID (DID) is
derived **solely** from the public key — no registration, no server:

```
did:agent:<base58(public_key_raw_bytes)>
```

- `public_key_raw_bytes` = 32-byte Ed25519 public key (`public_bytes_raw()`).
- Encoding: base58 (bitcoin alphabet), no padding.
- Verification: reconstruct the public key from the DID and use Ed25519
  `verify()`. If the DID does not match the signature, the vouch is invalid.

## 2. Vouch (attestation blob)

A vouch is a signed statement by an *issuer* agent endorsing a *subject* agent
for a capability *scope* with a *score*.

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
  "signature": "<hex(ed25519(raw_payload_bytes))>"
}
```

Rules:
- `score` ∈ [0.0, 1.0], float.
- `scope` is a free-form string identifying the capability area
  (e.g. `coding`, `research`, `finance`).
- `claim` is an optional free-text field, used only for *self-vouches*
  (`issuer == subject`) where the agent asserts something about itself.
- `ts` is a Unix epoch timestamp (seconds).
- `signature` is the hex-encoded Ed25519 signature over the **canonical**
  JSON of `payload` (see §3).
- `issuer` MUST be the DID whose private key produced `signature`. Otherwise
  the vouch is invalid.

## 3. Canonical serialization

For signing and verifying, `payload` is serialized deterministically:

```
json.dumps(payload, sort_keys=True, separators=(",", ":"))
```

This guarantees byte-identical input for signer and verifier.

## 4. Verification algorithm

1. Parse `payload` and `signature`.
2. Assert `issuer` starts with `did:agent:`.
3. Reconstruct the issuer public key from the DID (base58-decode, take 32 raw
   bytes, `Ed25519PublicKey.from_public_bytes`).
4. Compute canonical bytes of `payload` (§3).
5. `public_key.verify(bytes.fromhex(signature), canonical_bytes)`.
6. If any step raises (invalid DID, bad key, signature mismatch) → **INVALID**.
   Otherwise → **VALID**.

## 5. Threat model (honest)

- **Forgery:** Impossible without the issuer's private key (Ed25519).
- **Tampering:** Any change to `payload` invalidates the signature.
- **Sybil:** An attacker can mint unlimited identities and self-vouch. This is
  out of scope for the protocol; trust emerges from the transitive web-of-trust
  (who vouches for whom), not from the protocol layer. We make no Sybil-proof
  guarantee.

## 6. ATC — Agent Trust Carrier (Phase 2)

ATC lets an agent present its identity + vouches **inline** on first contact,
over any existing transport. ATAR does not replace MCP/A2A/HTTP — it rides on
top as a carrier.

### 6.1 Vouch token

A vouch blob (§2) is encoded as a header-safe token:

```
token = base64url( canonical_json(vouch_blob) )   # no padding
```

The receiver decodes, then runs the §4 verification. Tampered tokens fail
verification (base64 or signature error).

### 6.2 Agent card

An agent sends a self-describing "business card":

```json
{
  "schema": "atar-agent-card/1.0",
  "did": "did:agent:...",
  "name": "bob",
  "atar": {
    "vouches": [ "<token>", "<token>", ... ]
  }
}
```

- `did` — the presenting agent's own DID.
- `vouches` — list of ATC tokens (§6.1) the agent wants to present.
- The receiver verifies each token offline (§4) and builds a trust report
  (valid vs invalid vouches). No server, no round-trip to a registry.

### 6.3 Transport bindings (non-normative)

- **HTTP:** `X-ATAR-Card: <base64url(json card)>` request/response header, or
  `X-ATAR-Vouch: <token>` for a single vouch.
- **A2A:** `agentCard.atar` extension field.
- **MCP:** metadata field `atar_card` on tool/resource descriptors.

## 7. Transparency Log & Transitive Trust (Phase 3)

ATAR needs no central registry. Vouches are **content-addressed**: each vouch
has a deterministic ID

```
vouch_id = "vouch:" + sha256( canonical_json(payload) )   # hex
```

This lets agents share vouches over any gossip/mirror layer (no operator) and
deduplicate by ID. Each agent keeps a local `TrustGraph` and computes
**transitive trust** from a seed of trusted roots.

### 7.1 Trust computation

Given a seed DID (e.g. your own identity, or a personhood root) and a scope:

- The seed starts at trust `1.0`.
- For each valid vouch `issuer → subject (score s, scope)`, the subject's
  trust is increased by `issuer_trust × s × decay^depth`.
- Propagation is bounded (depth ≤ 8, or until contribution < 1e-9).
- Only **cryptographically valid** vouches are admitted to the graph, so a
  forged vouch (wrong signature) cannot inject fake trust.

This is the Web-of-Trust model: trust flows along signed edges, and an agent
you have never met can still be trusted transitively if enough trusted agents
vouch for it.

### 7.2 Honest constraint (Sybil)

Free, serverless identity means anyone can mint unlimited agents and
self-vouch. Because self-vouches contribute nothing (the issuer must already
be trusted to pass trust along), a Sybil only gains trust if *real* agents
vouch for it. ATAR provides the mechanism; reputation emerges from the graph,
not from the protocol. We make no Sybil-proof guarantee.

## 8. Roadmap (non-normative)



- **Phase 2 — ATC (Agent Trust Carrier):** a wire format (HTTP header
  `X-ATAR-Vouch`, A2A extension, MCP metadata) letting agents present a vouch
  inline on first contact.
- **Phase 3 — Transparency log:** gossiped, content-addressed vouch graph
  (no operator), enabling local reputation computation.
- **Phase 4 — Bootstrap:** existing agents (ATAR) adopt ATAR identities.
- **Phase 5 — Standardization:** RFC-style spec, public repo, PyPI, adoption.
