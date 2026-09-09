# JSON Schemas for ATAR wire formats

Machine-readable JSON Schema (draft 2020-12) definitions of every ATAR wire
format, so a second implementation can validate messages without reading
Python code. They complement the golden byte-level vectors in
[`tests/vectors/`](../tests/vectors) (see
[`docs/test-vectors.md`](../docs/test-vectors.md)): the vectors pin the exact
bytes, these schemas pin the structure and value ranges.

| Schema | Format | Spec section |
| --- | --- | --- |
| `vouch.schema.json` | Native signed vouch (`payload` + hex signature) | SPEC §3 |
| `vc-vouch.schema.json` | Vouch as W3C Verifiable Credential (unsigned or with `eddsa-jcs-2022` proof) | SPEC §3.3 |
| `revocation.schema.json` | Signed revocation entry | SPEC §6 |
| `dispute.schema.json` | Signed third-party dispute entry | SPEC §8.2 |
| `rotation.schema.json` | Signed key-rotation statement | SPEC §10.1 |
| `agent-card.schema.json` | A2A agent card with the ATAR trust extension + `signatures` | SPEC §11.2/11.3 |

Notes:

- The DID pattern accepts `did:key:z…` (multibase base58btc) and legacy
  `did:agent:…`. Schema-level validation is structural only — signature
  *verification* always happens against the embedded key, not the schema.
- `agent-card.schema.json` deliberately constrains only the ATAR-relevant
  parts of a card. The normative Agent Card schema belongs to the A2A
  project; ATAR cards are a signed superset.
- `tests/test_schemas.py` validates the golden vectors against these schemas
  and checks that mutated (invalid) instances are rejected, so the schemas
  cannot drift from the implementation without a red build.

Validate a vouch with any draft-2020-12 validator, e.g. Python:

```python
import json, jsonschema

schema = json.load(open("schemas/vouch.schema.json"))
vouch = json.load(open("my-vouch.json"))
jsonschema.validate(vouch, schema)
```
