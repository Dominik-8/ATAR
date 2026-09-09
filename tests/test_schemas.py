"""JSON Schemas for ATAR's wire formats stay honest.

The schemas in ``schemas/`` are the machine-readable contract for second
implementations. These tests prove two directions:

* every golden vector in ``tests/vectors/`` validates against its schema
  (schemas never drift tighter than the implementation), and
* structurally broken instances are rejected (schemas never drift looser).

A schema change and a format change must land in the same commit, same rule
as the vectors themselves (docs/test-vectors.md).
"""

import copy
import json
from pathlib import Path

import jsonschema
import pytest

from atar.identity import generate_identity
from atar.vouch import create_vouch

ROOT = Path(__file__).resolve().parent.parent
SCHEMAS = ROOT / "schemas"
VECTORS = ROOT / "tests" / "vectors"

SCHEMA_FILES = [
    "vouch.schema.json",
    "vc-vouch.schema.json",
    "revocation.schema.json",
    "dispute.schema.json",
    "rotation.schema.json",
    "agent-card.schema.json",
]


def _load(directory: Path, name: str) -> dict:
    return json.loads((directory / name).read_text(encoding="utf-8"))


def _assert_invalid(schema: dict, instance) -> None:
    with pytest.raises(jsonschema.ValidationError):
        jsonschema.validate(instance, schema)


@pytest.mark.parametrize("name", SCHEMA_FILES)
def test_schemas_are_valid_json_schema(name: str) -> None:
    schema = _load(SCHEMAS, name)
    validator_cls = jsonschema.validators.validator_for(schema)
    validator_cls.check_schema(schema)


def test_golden_vouch_validates() -> None:
    schema = _load(SCHEMAS, "vouch.schema.json")
    jsonschema.validate(_load(VECTORS, "native-vouch.json")["vouch"], schema)


def test_golden_vc_export_validates() -> None:
    schema = _load(SCHEMAS, "vc-vouch.schema.json")
    vectors = _load(VECTORS, "vc-export.json")
    jsonschema.validate(vectors["unsigned_credential"], schema)
    jsonschema.validate(vectors["signed_credential"], schema)


def test_golden_revocation_validates() -> None:
    schema = _load(SCHEMAS, "revocation.schema.json")
    jsonschema.validate(_load(VECTORS, "revocation.json")["entry"], schema)


def test_golden_rotation_validates() -> None:
    schema = _load(SCHEMAS, "rotation.schema.json")
    jsonschema.validate(_load(VECTORS, "rotation.json")["statement"], schema)


def test_golden_agent_card_validates() -> None:
    schema = _load(SCHEMAS, "agent-card.schema.json")
    vectors = _load(VECTORS, "agent-card.json")
    jsonschema.validate(vectors["unsigned_card"], schema)
    jsonschema.validate(vectors["signed_card"], schema)


def test_atc_token_vector_vouch_validates() -> None:
    schema = _load(SCHEMAS, "vouch.schema.json")
    jsonschema.validate(_load(VECTORS, "atc-token.json")["vouch"], schema)


def test_fresh_vouches_from_the_implementation_validate() -> None:
    """Anything create_vouch emits must satisfy the published schema."""
    schema = _load(SCHEMAS, "vouch.schema.json")
    issuer, subject = generate_identity(), generate_identity()
    for kwargs in (
        {"score": 0.0, "scope": "coding"},
        {"score": 1.0, "scope": "ops", "claim": "self claim"},
        {"score": 0.42, "scope": "research", "evidence": ["https://example.org/e/1"]},
    ):
        jsonschema.validate(create_vouch(issuer, subject.public_key, **kwargs), schema)


# --- the schemas must also REJECT broken instances ---------------------------


def _golden_vouch() -> dict:
    return _load(VECTORS, "native-vouch.json")["vouch"]


def test_vouch_schema_rejects_broken_instances() -> None:
    schema = _load(SCHEMAS, "vouch.schema.json")
    v = _golden_vouch()

    missing_sig = copy.deepcopy(v)
    del missing_sig["signature"]
    _assert_invalid(schema, missing_sig)

    bad_score = copy.deepcopy(v)
    bad_score["payload"]["score"] = 1.5  # outside [0, 1]
    _assert_invalid(schema, bad_score)

    bad_did = copy.deepcopy(v)
    bad_did["payload"]["issuer"] = "did:web:example.org"  # unsupported method
    _assert_invalid(schema, bad_did)

    bad_type = copy.deepcopy(v)
    bad_type["payload"]["type"] = "endorsement"
    _assert_invalid(schema, bad_type)

    bad_sig = copy.deepcopy(v)
    bad_sig["signature"] = "zz" + bad_sig["signature"][2:]  # non-hex
    _assert_invalid(schema, bad_sig)

    extra = copy.deepcopy(v)
    extra["payload"]["backdoor"] = True  # additionalProperties: false
    _assert_invalid(schema, extra)


def test_revocation_schema_rejects_broken_instances() -> None:
    schema = _load(SCHEMAS, "revocation.schema.json")
    entry = _load(VECTORS, "revocation.json")["entry"]

    bad_vid = dict(entry, vid=entry["vid"].replace("vouch:", ""))
    _assert_invalid(schema, bad_vid)

    bad_ts = dict(entry, ts="yesterday")
    _assert_invalid(schema, bad_ts)


def test_rotation_schema_rejects_broken_instances() -> None:
    schema = _load(SCHEMAS, "rotation.schema.json")
    stmt = _load(VECTORS, "rotation.json")["statement"]

    wrong_type = dict(stmt, type="key-rotation")
    _assert_invalid(schema, wrong_type)

    missing_new = {k: v for k, v in stmt.items() if k != "new_did"}
    _assert_invalid(schema, missing_new)


def test_vc_schema_rejects_broken_instances() -> None:
    schema = _load(SCHEMAS, "vc-vouch.schema.json")
    vc = _load(VECTORS, "vc-export.json")["signed_credential"]

    no_vc_type = copy.deepcopy(vc)
    no_vc_type["type"] = ["ATARVouch"]  # missing VerifiableCredential
    _assert_invalid(schema, no_vc_type)

    wrong_suite = copy.deepcopy(vc)
    wrong_suite["proof"]["cryptosuite"] = "eddsa-2022"
    _assert_invalid(schema, wrong_suite)

    bad_score = copy.deepcopy(vc)
    bad_score["credentialSubject"]["atar:score"] = -0.1
    _assert_invalid(schema, bad_score)


def test_agent_card_schema_rejects_broken_instances() -> None:
    schema = _load(SCHEMAS, "agent-card.schema.json")
    card = _load(VECTORS, "agent-card.json")["signed_card"]

    no_name = copy.deepcopy(card)
    del no_name["name"]
    _assert_invalid(schema, no_name)

    bad_sig_entry = copy.deepcopy(card)
    bad_sig_entry["signatures"][0]["signature"] = "not base64url !!!"
    _assert_invalid(schema, bad_sig_entry)
