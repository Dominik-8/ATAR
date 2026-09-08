# Interoperability test vectors

`tests/vectors/` holds golden vectors that pin ATAR's wire formats byte-for-byte.
They exist so a second implementation can prove it interoperates without reading
this codebase first — the same role test vectors play for RFCs.

| File | Format pinned | Spec section |
| --- | --- | --- |
| `identity.json` | Ed25519 seed → raw public key → `did:key` (multicodec + multibase base58btc) and legacy `did:agent:` | SPEC §2 |
| `jcs.json` | JSON Canonicalization Scheme (RFC 8785) subset used by the VC bridge | SPEC §4 (used by §3.1) |
| `native-vouch.json` | Native vouch wire format, deterministic Ed25519 signature, canonical vouch ID (`vouch:` + sha256, `ts`/`signature` excluded) | SPEC §3 |
| `revocation.json` | Signed revocation entry (`vid\|revoked_by\|ts`, base64 Ed25519) | SPEC §6 |
| `vc-export.json` | Vouch → W3C Verifiable Credential mapping and the `eddsa-jcs-2022` Data Integrity proof | SPEC §3.1 |
| `atc-token.json` | ATC vouch token (base64url of canonical JSON) for header transport | SPEC §11.1 |
| `agent-card.json` | A2A-compatible signed agent card with the ATAR trust extension | SPEC §11.2 |
| `rotation.json` | Signed key-rotation statement (old key binds the new DID) | SPEC §10.1 |

Rules for working with them:

- The private keys are test-only seeds (`identity.json`); never use them anywhere else.
- Ed25519 signatures are deterministic, so every signed vector is reproducible
  from the inputs shown. The one deliberate exception is `proof.created` in the
  signed credential, which is pinned to a fixed timestamp for reproducibility.
- `tests/test_vectors.py` asserts the implementation keeps matching these files
  exactly. If a format change is ever intentional, the vectors and this page must
  change in the same commit — silent format drift is a breaking change for
  everyone who verified against them.
