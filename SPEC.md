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

## 6. Roadmap (non-normative)

- **Phase 2 — ATC (Agent Trust Carrier):** a wire format (HTTP header
  `X-ATAR-Vouch`, A2A extension, MCP metadata) letting agents present a vouch
  inline on first contact.
- **Phase 3 — Transparency log:** gossiped, content-addressed vouch graph
  (no operator), enabling local reputation computation.
- **Phase 4 — Bootstrap:** existing agents (ATAR) adopt ATAR identities.
- **Phase 5 — Standardization:** RFC-style spec, public repo, PyPI, adoption.
