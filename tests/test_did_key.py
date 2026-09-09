"""B1 — did:key identity: W3C-standard identifiers with legacy did:agent: support.

Covers the multibase/multicodec encoding against an independently computed
test vector, both-direction decoding, alias normalization, and the migration
guarantees (old vouches stay verifiable, no data loss, no hard cut).
"""

import json

from click.testing import CliRunner
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from atar.identity import (
    Identity,
    did_aliases,
    did_from_public,
    did_key_from_public,
    generate_identity,
    is_supported_did,
    legacy_did_agent_from_public,
    normalize_did,
    public_key_from_did,
)
from atar.revocation import RevocationList, revoke_vouch
from atar.transparency import TrustGraph
from atar.vouch import create_vouch, verify_vouch

# Deterministic key (seed bytes 0..31) — cross-checked against the independent
# `multiformats` implementation (multicodec ed25519-pub + multibase base58btc).
VECTOR_SEED = bytes(range(32))
VECTOR_PUB_HEX = "03a107bff3ce10be1d70dd18e74bc09967e4d6309ba50d5f1ddc8664125531b8"
VECTOR_DID_KEY = "did:key:z6MkehRgf7yJbgaGfYsdoAsKdBPE3dj2CYhowQdcjqSJgvVd"
VECTOR_DID_AGENT = "did:agent:FAe4sisG95oZ42w7buUn5qEE4TAnfTTFPiguZUHmhiF"


def _vector_identity():
    priv = Ed25519PrivateKey.from_private_bytes(VECTOR_SEED)
    return Identity(private_key=priv, public_key=priv.public_key())


def test_did_key_matches_spec_vector():
    ident = _vector_identity()
    assert ident.public_key.public_bytes_raw().hex() == VECTOR_PUB_HEX
    assert did_key_from_public(ident.public_key) == VECTOR_DID_KEY
    assert legacy_did_agent_from_public(ident.public_key) == VECTOR_DID_AGENT


def test_did_key_shape_and_roundtrip():
    ident = generate_identity()
    did = did_from_public(ident.public_key)
    # every ed25519 did:key starts with z6Mk (multibase 'z' + multicodec ed25519-pub)
    assert did.startswith("did:key:z6Mk")
    assert (
        public_key_from_did(did).public_bytes_raw()
        == ident.public_key.public_bytes_raw()
    )


def test_legacy_did_agent_still_decodes():
    ident = _vector_identity()
    pub = public_key_from_did(VECTOR_DID_AGENT)
    assert pub.public_bytes_raw() == ident.public_key.public_bytes_raw()


def test_normalize_did_aliases_legacy_to_did_key():
    assert normalize_did(VECTOR_DID_AGENT) == VECTOR_DID_KEY
    assert normalize_did(VECTOR_DID_KEY) == VECTOR_DID_KEY
    assert did_aliases(VECTOR_DID_KEY) == (VECTOR_DID_KEY, VECTOR_DID_AGENT)
    assert did_aliases(VECTOR_DID_AGENT) == (VECTOR_DID_KEY, VECTOR_DID_AGENT)


def test_malformed_dids_rejected():
    assert not is_supported_did("did:web:example.com")  # unknown method
    assert not is_supported_did("did:key:uQ3h2xr...")  # wrong multibase
    assert not is_supported_did("did:key:z6Mktooshort")  # wrong key length
    assert not is_supported_did("did:agent:!!")  # bad base58
    assert not is_supported_did("not-a-did")
    assert not is_supported_did(None)
    import pytest

    with pytest.raises(ValueError):
        public_key_from_did("did:web:example.com")


def test_new_vouches_use_did_key_and_verify():
    issuer = generate_identity()
    subject = generate_identity()
    v = create_vouch(issuer, subject.public_key, score=0.9, scope="coding")
    assert v["payload"]["issuer"].startswith("did:key:")
    assert v["payload"]["subject"].startswith("did:key:")
    assert verify_vouch(v)


def test_legacy_did_agent_vouch_still_verifies():
    """A vouch signed under the old did:agent: scheme verifies unchanged —
    the signature is over the original payload, and did:agent: still yields
    the issuer's key."""
    issuer = generate_identity()
    subject = generate_identity()
    v = create_vouch(issuer, subject.public_key, score=0.9, scope="coding")
    # rewrite payload to the legacy spelling and re-sign (simulating a
    # pre-realignment vouch byte-for-byte)
    legacy_issuer = legacy_did_agent_from_public(issuer.public_key)
    legacy_subject = legacy_did_agent_from_public(subject.public_key)
    v["payload"]["issuer"] = legacy_issuer
    v["payload"]["subject"] = legacy_subject
    from atar.vouch import _canonical

    v["signature"] = issuer.sign(_canonical(v["payload"])).hex()
    assert verify_vouch(v)


def test_revocation_matches_across_spellings():
    """A pre-realignment vouch (did:agent: payload) revoked post-realignment:
    the revocation's revoked_by is the canonical did:key of the same key, and
    the match is alias-aware (SPEC §6 + §2) — no trust escapes the migration."""
    from atar.revocation import revoke_payload_id
    from atar.vouch import _canonical

    issuer = generate_identity()
    subject = generate_identity()
    v = create_vouch(issuer, subject.public_key, score=0.9, scope="coding")
    # simulate the pre-realignment vouch byte-for-byte
    v["payload"]["issuer"] = legacy_did_agent_from_public(issuer.public_key)
    v["payload"]["subject"] = legacy_did_agent_from_public(subject.public_key)
    v["signature"] = issuer.sign(_canonical(v["payload"])).hex()
    assert verify_vouch(v)
    rl = RevocationList()
    # revoke_vouch records revoked_by canonically (did:key) post-realignment
    assert revoke_vouch(rl, issuer, revoke_payload_id(v))
    assert rl.is_revoked_for(v)  # alias match: did:key revoker, did:agent: issuer


def test_trust_graph_unifies_spellings():
    """Trust computed from a did:key seed flows through a did:agent: vouch
    edge — the same key is one node, whatever the spelling."""
    seed = generate_identity()
    other = generate_identity()
    v = create_vouch(seed, other.public_key, score=0.9, scope="coding")
    legacy_v = json.loads(json.dumps(v))
    legacy_v["payload"]["issuer"] = legacy_did_agent_from_public(seed.public_key)
    legacy_v["payload"]["subject"] = legacy_did_agent_from_public(other.public_key)
    from atar.vouch import _canonical

    legacy_v["signature"] = seed.sign(_canonical(legacy_v["payload"])).hex()
    g = TrustGraph()
    assert g.add(legacy_v)
    trust = g.compute_trust(seed_did=did_from_public(seed.public_key), scope="coding")
    assert trust[did_from_public(other.public_key)] > 0.9 - 1e-9


def test_keygen_cli_outputs_did_key(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    from atar.cli import cli

    r = CliRunner().invoke(cli, ["keygen", "--name", "alice"])
    assert r.exit_code == 0
    did = r.output.strip()
    assert did.startswith("did:key:z6Mk")
    assert is_supported_did(did)


def test_legacy_keyfile_identity_still_usable(tmp_path, monkeypatch):
    """Migration: an identity created before the realignment (did:agent: in
    keys.json) still signs vouches, and vouching FOR a legacy DID works."""
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    from atar.cli import cli

    runner = CliRunner()
    # hand-craft a pre-realignment keys.json entry
    ident = generate_identity()
    legacy_did = legacy_did_agent_from_public(ident.public_key)
    (tmp_path / "keys.json").write_text(
        json.dumps(
            {
                "old": {
                    "private": ident.private_key.private_bytes_raw().hex(),
                    "did": legacy_did,
                }
            }
        )
    )
    subject = generate_identity()
    legacy_subject = legacy_did_agent_from_public(subject.public_key)
    r = runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "old",
            "--for",
            legacy_subject,
            "--score",
            "0.9",
            "--scope",
            "coding",
            "--out",
            str(tmp_path / "v.json"),
        ],
    )
    assert r.exit_code == 0, r.output
    blob = json.loads((tmp_path / "v.json").read_text())
    assert verify_vouch(blob)
    # new vouches record BOTH sides canonically (did:key), even when the
    # keyfile and the --for argument use the legacy spelling
    assert blob["payload"]["issuer"] == normalize_did(legacy_did)
    assert blob["payload"]["subject"] == normalize_did(legacy_subject)
