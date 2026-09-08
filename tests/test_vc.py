"""B2 — vouches as W3C Verifiable Credentials (VC export + verify, SPEC §3.1).

The native vouch format stays internal; the VC path is the interop bridge:
proofs are eddsa-jcs-2022 Data Integrity proofs (JCS / RFC 8785 + SHA-256 +
Ed25519), so any VC tooling can check an exported ATAR vouch offline.
"""

import json

import pytest
from click.testing import CliRunner

from atar.identity import (
    generate_identity, legacy_did_agent_from_public, normalize_did,
)
from atar.jcs import canonicalize
from atar.vc import (
    CRYPTOSUITE, VC_CONTEXT_V2, VC_TYPE_VOUCH,
    credential_to_vouch_payload, sign_credential, verify_credential,
    vouch_to_credential,
)
from atar.vouch import _canonical, create_vouch


# --- JCS (RFC 8785) — vectors cross-checked against the reference ---------
# implementation (rfc8785) during development, hardcoded here so the repo
# carries no extra dependency.

@pytest.mark.parametrize("obj,expected", [
    ({"b": 1, "a": 2}, b'{"a":2,"b":1}'),
    ({"num": 0.1}, b'{"num":0.1}'),
    ({"num": 1e-7}, b'{"num":1e-7}'),
    ({"num": 333333333.33333329}, b'{"num":333333333.3333333}'),
    ({"num": 4.50}, b'{"num":4.5}'),
    ({"num": 1e21}, b'{"num":1e+21}'),
    ({"num": -0.0}, b'{"num":0}'),
    ({"s": '\t\n"\\'}, b'{"s":"\\t\\n\\"\\\\"}'),
    ({"uni": "héllo €"}, '{"uni":"héllo €"}'.encode("utf-8")),
    ({"z": [1, 2.5, None, True, False]}, b'{"z":[1,2.5,null,true,false]}'),
])
def test_jcs_vectors(obj, expected):
    assert canonicalize(obj) == expected


def test_jcs_rejects_unsafe_integer():
    with pytest.raises(ValueError):
        canonicalize({"n": 2**53})


# --- VC mapping ------------------------------------------------------------

def _vouch(**kw):
    issuer = kw.pop("issuer", None) or generate_identity()
    subject = generate_identity()
    v = create_vouch(issuer, subject.public_key,
                     score=kw.pop("score", 0.95), scope=kw.pop("scope", "coding"),
                     **kw)
    return issuer, v


def test_vouch_to_credential_mapping():
    issuer, v = _vouch(score=0.95, scope="coding")
    cred = vouch_to_credential(v)
    assert VC_CONTEXT_V2 in cred["@context"]
    assert cred["type"] == ["VerifiableCredential", VC_TYPE_VOUCH]
    assert cred["issuer"] == v["payload"]["issuer"]
    assert cred["credentialSubject"]["id"] == v["payload"]["subject"]
    assert cred["credentialSubject"]["atar:scope"] == "coding"
    assert cred["credentialSubject"]["atar:score"] == 0.95
    assert "atar:claim" not in cred["credentialSubject"]  # omitted when None
    assert cred["validFrom"].endswith("Z")


def test_claim_carried_into_credential():
    issuer = generate_identity()
    v = create_vouch(issuer, issuer.public_key, score=1.0, scope="coding",
                     claim="does solid code reviews")
    cred = vouch_to_credential(v)
    assert cred["credentialSubject"]["atar:claim"] == "does solid code reviews"


def test_sign_and_verify_credential():
    issuer, v = _vouch()
    vc = sign_credential(vouch_to_credential(v), issuer)
    proof = vc["proof"]
    assert proof["cryptosuite"] == CRYPTOSUITE
    assert proof["verificationMethod"].startswith(vc["issuer"] + "#")
    assert proof["proofValue"].startswith("z")
    assert verify_credential(vc)


def test_tampered_credential_fails():
    issuer, v = _vouch()
    vc = sign_credential(vouch_to_credential(v), issuer)
    vc["credentialSubject"]["atar:score"] = 0.1
    assert not verify_credential(vc)


def test_wrong_verification_method_fails():
    """A proof bound to a key other than the issuer's must not verify."""
    issuer, v = _vouch()
    vc = sign_credential(vouch_to_credential(v), issuer)
    other = generate_identity()
    from atar.identity import did_from_public
    vc["proof"]["verificationMethod"] = (
        did_from_public(other.public_key) + "#" + did_from_public(other.public_key).split(":")[2])
    assert not verify_credential(vc)


def test_malformed_credentials_fail():
    issuer, v = _vouch()
    good = sign_credential(vouch_to_credential(v), issuer)
    assert not verify_credential({})
    assert not verify_credential("not a vc")
    no_ctx = json.loads(json.dumps(good)); no_ctx["@context"] = []
    assert not verify_credential(no_ctx)
    wrong_suite = json.loads(json.dumps(good)); wrong_suite["proof"]["cryptosuite"] = "eddsa-rdfc-2022"
    assert not verify_credential(wrong_suite)


def test_legacy_vouch_exports_with_canonical_did_key_issuer():
    """A pre-realignment (did:agent:) vouch exports with identifiers
    canonicalized to did:key, and the exported VC verifies."""
    issuer = generate_identity()
    subject = generate_identity()
    v = create_vouch(issuer, subject.public_key, score=0.9, scope="coding")
    v["payload"]["issuer"] = legacy_did_agent_from_public(issuer.public_key)
    v["payload"]["subject"] = legacy_did_agent_from_public(subject.public_key)
    v["signature"] = issuer.sign(_canonical(v["payload"])).hex()
    cred = vouch_to_credential(v)
    assert cred["issuer"] == normalize_did(v["payload"]["issuer"])
    assert cred["issuer"].startswith("did:key:")
    vc = sign_credential(cred, issuer)
    assert verify_credential(vc)


def test_credential_to_vouch_payload_roundtrip():
    issuer, v = _vouch(score=0.77, scope="research")
    vc = sign_credential(vouch_to_credential(v), issuer)
    payload = credential_to_vouch_payload(vc)
    assert payload["issuer"] == v["payload"]["issuer"]
    assert payload["subject"] == v["payload"]["subject"]
    assert payload["score"] == 0.77
    assert payload["scope"] == "research"
    assert payload["ts"] == v["payload"]["ts"]


def test_sign_credential_rejects_non_issuer_key():
    issuer, v = _vouch()
    cred = vouch_to_credential(v)
    with pytest.raises(ValueError):
        sign_credential(cred, generate_identity())


# --- CLI --------------------------------------------------------------------

def test_vc_export_and_verify_cli(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    from atar.cli import cli
    runner = CliRunner()
    r = runner.invoke(cli, ["keygen", "--name", "alice"])
    assert r.exit_code == 0
    alice_did = r.output.strip()
    r = runner.invoke(cli, ["vouch", "--from", "alice", "--for", alice_did,
                            "--score", "0.9", "--scope", "coding",
                            "--out", str(tmp_path / "v.json")])
    assert r.exit_code == 0, r.output
    r = runner.invoke(cli, ["vc-export", str(tmp_path / "v.json"), "--from", "alice",
                            "--out", str(tmp_path / "v.vc.json")])
    assert r.exit_code == 0, r.output
    vc = json.loads((tmp_path / "v.vc.json").read_text())
    assert verify_credential(vc)
    r = runner.invoke(cli, ["vc-verify", str(tmp_path / "v.vc.json")])
    assert r.exit_code == 0 and "VALID" in r.output
    # tampered file fails
    vc["credentialSubject"]["atar:score"] = 0.01
    (tmp_path / "bad.vc.json").write_text(json.dumps(vc))
    r = runner.invoke(cli, ["vc-verify", str(tmp_path / "bad.vc.json")])
    assert r.exit_code == 1 and "INVALID" in r.output


def test_vc_export_rejects_non_issuer(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    from atar.cli import cli
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    runner.invoke(cli, ["keygen", "--name", "mallory"])
    alice_did = json.loads((tmp_path / "keys.json").read_text())["alice"]["did"]
    runner.invoke(cli, ["vouch", "--from", "alice", "--for", alice_did,
                        "--score", "0.9", "--scope", "coding",
                        "--out", str(tmp_path / "v.json")])
    r = runner.invoke(cli, ["vc-export", str(tmp_path / "v.json"), "--from", "mallory"])
    assert r.exit_code == 1
