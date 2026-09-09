"""Adversarial negative tests for the cryptographic verification boundary.

These prove that the verification functions (the ones we just narrowed from a
broad `except Exception` to specific exceptions) reject malformed input
gracefully — returning False / a clean report — instead of crashing or
hiding bugs. This is the regression guard for the security audit fix.

If any of these RAISES instead of returning False, the silent-catch removal
regressed.
"""

import base64

from atar.vouch import verify_vouch
from atar.rotation import verify_rotation, RotationStatement
from atar.atc import verify_token, verify_agent_card
from atar.revocation import verify_vouch_revocation_aware, RevocationList


# --- malformed vouches: every one must return False, never raise ---
_BAD_VOUCHES = [
    None,
    {},
    {"payload": {}, "signature": "00"},
    {"signature": "00"},  # missing payload
    {
        "payload": {
            "issuer": "did:agent:X",
            "subject": "did:agent:Y",
            "score": 1.0,
            "scope": "s",
            "ts": 1,
        },
        "signature": "00",
    },
    {
        "payload": {
            "type": "vouch",
            "issuer": "did:agent:!!",  # bad base58
            "subject": "did:agent:YYYY",
            "score": 1.0,
            "scope": "s",
            "ts": 1,
        },
        "signature": "00",
    },
    {
        "payload": {
            "type": "vouch",
            "issuer": "did:agent:AAAA",
            "subject": "did:agent:BBBB",
            "score": 1.0,
            "scope": "s",
            "ts": 1,
        },
        "signature": "not-hex-at-all",
    },  # bad hex
    {
        "payload": {
            "type": "vouch",
            "issuer": "did:agent:AAAA",
            "subject": "did:agent:BBBB",
            "score": 1.0,
            "scope": "s",
            "ts": 1,
        },
        "signature": "deadbeef",
    },  # wrong-length sig
    {"payload": "i am a string not a dict", "signature": "00"},
    {
        "payload": {
            "issuer": 123,
            "subject": 456,
            "score": 1.0,  # wrong types
            "scope": "s",
            "ts": 1,
        },
        "signature": "00",
    },
    {
        "payload": {
            "type": "vouch",
            "issuer": "no-prefix",  # missing did:agent:
            "subject": "did:agent:BBBB",
            "score": 1.0,
            "scope": "s",
            "ts": 1,
        },
        "signature": "00",
    },
]


def test_verify_vouch_rejects_all_malformed():
    for bad in _BAD_VOUCHES:
        try:
            result = verify_vouch(bad)
        except Exception as exc:  # pragma: no cover - this is what we forbid
            raise AssertionError(f"verify_vouch raised on {bad!r}: {exc}")
        assert result is False, f"malformed vouch {bad!r} should be False, got {result}"


def test_verify_rotation_rejects_malformed():
    bad = [
        RotationStatement(
            old_did="did:agent:AAAA",
            new_did="did:agent:BBBB",
            ts=1,
            signature="not-hex",
        ),
        RotationStatement(
            old_did="did:bad", new_did="did:agent:BBBB", ts=1, signature="00"
        ),
        None,
    ]
    for stmt in bad:
        try:
            result = (
                verify_rotation(stmt) if stmt is not None else verify_rotation(None)
            )
        except Exception as exc:  # pragma: no cover
            raise AssertionError(f"verify_rotation raised on {stmt!r}: {exc}")
        assert result is False


def test_verify_token_rejects_malformed():
    bad_tokens = ["", "???", "not-base64-at-all-!!!", "eyJ9", "aGVsbG8="]
    for tok in bad_tokens:
        try:
            result = verify_token(tok)
        except Exception as exc:  # pragma: no cover
            raise AssertionError(f"verify_token raised on {tok!r}: {exc}")
        assert result is False


def test_verify_agent_card_handles_all_invalid():
    card = {
        "schema": "atar-agent-card/1.0",
        "did": "did:agent:AAAA",
        "name": "evil",
        "atar": {"vouches": ["", "garbage", "!!!notbase64!!!"]},
    }
    try:
        report = verify_agent_card(card)
    except Exception as exc:  # pragma: no cover
        raise AssertionError(f"verify_agent_card raised: {exc}")
    assert report["valid_vouches"] == []
    assert len(report["invalid_vouches"]) == 3


def test_verify_vouch_revocation_aware_rejects_malformed():
    rlist = RevocationList()
    for bad in _BAD_VOUCHES:
        try:
            result = verify_vouch_revocation_aware(bad, rlist)
        except Exception as exc:  # pragma: no cover
            raise AssertionError(
                f"verify_vouch_revocation_aware raised on {bad!r}: {exc}"
            )
        assert result is False
