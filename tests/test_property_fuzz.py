"""Property-based fuzz tests for ATAR's parsing and verification boundary.

Hand-written adversarial cases (test_crypto_boundary_adversarial.py) pin the
malformed inputs we thought of. These hypothesis properties explore the input
space we did NOT think of:

* every verify function must reject garbage gracefully (return False / a clean
  report), never crash with an uncaught exception — the parser boundary is the
  attack surface of a trust protocol;
* DID encoding/decoding and JCS canonicalization must round-trip and be
  order-invariant, or two honest implementations silently diverge.

Runs deterministically (derandomize=True) so CI failures reproduce exactly.
"""

import json
import random

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st

from atar.atc import (
    verify_agent_card,
    verify_card_signature,
    verify_token,
    vouch_from_token,
    vouch_to_token,
)
from atar.dispute import create_dispute, verify_dispute_entry
from atar.identity import (
    Identity,
    did_key_from_public,
    is_supported_did,
    legacy_did_agent_from_public,
    normalize_did,
    public_key_from_did,
)
from atar.jcs import canonicalize
from atar.revocation import verify_revocation_entry
from atar.rotation import RotationStatement, rotate_identity, verify_rotation
from atar.vc import (
    credential_to_vouch_payload,
    sign_credential,
    verify_credential,
    vouch_to_credential,
)
from atar.vouch import create_vouch, verify_vouch

SETTINGS = settings(
    max_examples=60,
    deadline=None,
    derandomize=True,
    suppress_health_check=[HealthCheck.too_slow],
)

_SAFE_INT = st.integers(min_value=-(2**53) + 1, max_value=2**53 - 1)
# Integral floats with abs >= 2**53 are excluded on purpose: canonicalize()
# prints them as integer literals (ECMAScript Number::toString semantics),
# which Python's json.loads re-parses as *ints* outside the ±2^53 safe range,
# so the re-canonicalization fixed point does not exist for them in Python
# types (it does exist under ECMAScript's single Number type).
_SAFE_FLOAT = st.floats(allow_nan=False, allow_infinity=False, width=64).filter(
    lambda n: not (n.is_integer() and abs(n) >= 2**53)
)
_JSON_SCALAR = st.one_of(st.none(), st.booleans(), _SAFE_INT, _SAFE_FLOAT, st.text())
_JSON = st.recursive(
    _JSON_SCALAR,
    lambda children: st.one_of(
        st.lists(children, max_size=5),
        st.dictionaries(st.text(max_size=12), children, max_size=5),
    ),
    max_leaves=25,
)


def _identity() -> Identity:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    priv = Ed25519PrivateKey.generate()
    return Identity(private_key=priv, public_key=priv.public_key())


# --- DID encoding ------------------------------------------------------------


@given(raw=st.binary(min_size=32, max_size=32))
@SETTINGS
def test_did_key_roundtrip_for_any_key_bytes(raw: bytes) -> None:
    pub = Ed25519PublicKey.from_public_bytes(raw)
    did = did_key_from_public(pub)
    assert public_key_from_did(did).public_bytes_raw() == raw
    # legacy alias of the same key normalizes to the same canonical DID
    legacy = legacy_did_agent_from_public(pub)
    assert normalize_did(legacy) == did
    assert is_supported_did(did) and is_supported_did(legacy)


@given(value=st.one_of(st.text(), _JSON))
@SETTINGS
def test_did_parsing_never_raises_unexpected(value) -> None:
    """Any input either decodes or raises the documented ValueError."""
    try:
        pub = public_key_from_did(value)
    except ValueError:
        assert not is_supported_did(value)
    else:
        # anything that parses must re-encode to a canonical did:key
        assert normalize_did(value) == did_key_from_public(pub)


# --- JCS canonicalization ----------------------------------------------------


@given(value=_JSON)
@SETTINGS
def test_jcs_roundtrip_and_idempotence(value) -> None:
    blob = canonicalize(value)
    parsed = json.loads(blob.decode("utf-8"))
    assert canonicalize(parsed) == blob  # canonical form is a fixed point


@given(
    items=st.lists(
        st.tuples(st.text(min_size=1, max_size=10), _JSON),
        min_size=2,
        max_size=8,
        unique_by=lambda kv: kv[0],
    ),
    seed=st.integers(),
)
@SETTINGS
def test_jcs_key_order_invariant(items, seed: int) -> None:
    forward = dict(items)
    shuffled = dict(items)
    random.Random(seed).shuffle(items)
    shuffled = dict(items)
    assert canonicalize(forward) == canonicalize(shuffled)


# --- verification boundary: garbage in, graceful False out --------------------


@given(value=_JSON)
@SETTINGS
def test_verify_vouch_never_raises(value) -> None:
    assert verify_vouch(value) is False


@given(value=st.one_of(st.text(), st.binary(), _JSON))
@SETTINGS
def test_verify_token_never_raises(value) -> None:
    assert verify_token(value) is False


@given(value=_JSON)
@SETTINGS
def test_verify_credential_never_raises(value) -> None:
    assert verify_credential(value) is False


@given(value=_JSON)
@SETTINGS
def test_verify_card_signature_never_raises(value) -> None:
    assert verify_card_signature(value) is False


@given(value=_JSON)
@SETTINGS
def test_verify_agent_card_never_raises(value) -> None:
    report = verify_agent_card(value)
    assert isinstance(report, dict)


@given(value=_JSON)
@SETTINGS
def test_verify_revocation_entry_never_raises(value) -> None:
    assert verify_revocation_entry(value) is False


@given(value=_JSON)
@SETTINGS
def test_verify_dispute_entry_never_raises(value) -> None:
    assert verify_dispute_entry(value) is False


@given(
    old_did=st.one_of(st.text(), _JSON),
    new_did=st.one_of(st.text(), _JSON),
    ts=st.one_of(_SAFE_INT, st.text(), st.none()),
    signature=st.one_of(st.text(), _JSON),
)
@SETTINGS
def test_verify_rotation_never_raises(old_did, new_did, ts, signature) -> None:
    stmt = RotationStatement(
        old_did=old_did, new_did=new_did, ts=ts, signature=signature
    )
    assert verify_rotation(stmt) is False


# --- positive roundtrips: valid objects keep verifying ------------------------


@given(
    score=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    scope=st.text(min_size=1, max_size=30),
    claim=st.text(min_size=1, max_size=60),
)
@SETTINGS
def test_valid_vouch_survives_token_and_verify(
    score: float, scope: str, claim: str
) -> None:
    issuer = _identity()
    subject = _identity()
    vouch = create_vouch(
        issuer, subject.public_key, score=score, scope=scope, claim=claim
    )
    assert verify_vouch(vouch) is True
    restored = vouch_from_token(vouch_to_token(vouch))
    assert verify_vouch(restored) is True
    assert restored["payload"] == vouch["payload"]


@given(
    score=st.floats(min_value=0.0, max_value=1.0, allow_nan=False),
    scope=st.text(min_size=1, max_size=30),
    claim=st.text(min_size=1, max_size=60),
)
@SETTINGS
def test_valid_vouch_survives_vc_bridge(score: float, scope: str, claim: str) -> None:
    issuer = _identity()
    subject = _identity()
    vouch = create_vouch(
        issuer, subject.public_key, score=score, scope=scope, claim=claim
    )
    vc = sign_credential(vouch_to_credential(vouch), issuer)
    assert verify_credential(vc) is True
    payload = credential_to_vouch_payload(vc)
    for field in ("issuer", "subject", "scope", "claim"):
        assert payload[field] == vouch["payload"][field]
    assert abs(payload["score"] - vouch["payload"]["score"]) < 1e-9


@given(reason=st.text(max_size=60))
@SETTINGS
def test_valid_dispute_verifies(reason: str) -> None:
    issuer = _identity()
    subject = _identity()
    disputer = _identity()  # disputes must come from a third party (SPEC §8.2)
    vouch = create_vouch(issuer, subject.public_key, score=0.5, scope="s", claim="c")
    entry = create_dispute(disputer, vouch, reason=reason)
    assert verify_dispute_entry(entry) is True


@SETTINGS
@given(st.data())
def test_valid_rotation_verifies(data) -> None:
    old = _identity()
    new = _identity()
    stmt = rotate_identity(old, new)
    assert verify_rotation(stmt) is True
    # and a tampered rotation (different new key) must fail
    other = _identity()
    tampered = RotationStatement(
        old_did=stmt.old_did,
        new_did=did_key_from_public(other.public_key),
        ts=stmt.ts,
        signature=stmt.signature,
    )
    assert verify_rotation(tampered) is False
