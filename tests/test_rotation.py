import os
import json
import tempfile

from atar.rotation import (
    rotate_identity, verify_rotation, reissue_vouch,
)
from atar.identity import generate_identity, did_from_public
from atar.vouch import create_vouch, verify_vouch


def test_rotation_statement_verifies():
    old = generate_identity()
    new = generate_identity()
    stmt = rotate_identity(old, new)
    assert verify_rotation(stmt) is True
    # a rotation forged by the new key (not old) must fail
    forged = rotate_identity(new, old)  # signs with 'new' claiming old->new
    # forge: swap so it claims old_did->new_did but signed by new
    bad = type(forged)(old_did=did_from_public(old.public_key),
                       new_did=did_from_public(new.public_key),
                       ts=forged.ts, signature=forged.signature)
    assert verify_rotation(bad) is False


def test_reissue_vouch_re_signs_under_new_key():
    old = generate_identity()
    new = generate_identity()
    subj = generate_identity()
    v = create_vouch(old, subj.public_key, score=0.9, scope="coding")
    # original is verifiable under old issuer
    assert verify_vouch(v) is True
    # re-issue under new key
    r = reissue_vouch(old, new, v, scope="coding")
    assert verify_vouch(r) is True
    # the re-issued vouch's issuer is the NEW did, not the old
    assert r["payload"]["issuer"] == did_from_public(new.public_key)
    assert r["payload"]["issuer"] != did_from_public(old.public_key)
    # score/scope preserved
    assert r["payload"]["score"] == 0.9
    assert r["payload"]["scope"] == "coding"
    # the re-issued vouch is NOT identical to the old (different issuer + ts)
    from atar.transparency import canonical_vouch_id
    assert canonical_vouch_id(r) != canonical_vouch_id(v)


def test_reissue_preserves_subject_trust_path():
    """A re-issued vouch keeps the subject reachable for the same scope."""
    issuer_old = generate_identity()
    issuer_new = generate_identity()
    subject = generate_identity()
    v = create_vouch(issuer_old, subject.public_key, score=0.8, scope="intelligence")
    r = reissue_vouch(issuer_old, issuer_new, v)
    # both old and new vouches are individually valid
    assert verify_vouch(v) is True
    assert verify_vouch(r) is True
    # subject is endorsed at same score/scope under the new issuer
    assert r["payload"]["subject"] == did_from_public(subject.public_key)
    assert r["payload"]["score"] == 0.8
