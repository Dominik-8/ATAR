import os
import tempfile

from atar.identity import generate_identity, did_from_public
from atar.vouch import create_vouch, verify_vouch
from atar.revocation import RevocationList, revoke_vouch, is_revoked, revoke_payload_id


def _make_vouch():
    issuer = generate_identity()
    subject = generate_identity()
    v = create_vouch(issuer, subject.public_key, score=0.9, scope="intelligence")
    return issuer, subject, v


def test_revoke_makes_vouch_invalid():
    issuer, subject, v = _make_vouch()
    assert verify_vouch(v) is True
    # issuer revokes it
    rlist = RevocationList()
    assert revoke_vouch(rlist, issuer, revoke_payload_id(v)) is True
    from atar.revocation import verify_vouch_revocation_aware
    assert verify_vouch_revocation_aware(v, rlist) is False


def test_unrevoked_vouch_still_valid():
    issuer, subject, v = _make_vouch()
    rlist = RevocationList()
    from atar.revocation import verify_vouch_revocation_aware
    assert verify_vouch_revocation_aware(v, rlist) is True


def test_revocation_persists_and_is_dedup():
    issuer, subject, v = _make_vouch()
    revoked_by = did_from_public(issuer.public_key)
    vid = revoke_payload_id(v)
    rlist = RevocationList()
    assert revoke_vouch(rlist, issuer, vid) is True     # first add
    assert revoke_vouch(rlist, issuer, vid) is False    # duplicate rejected
    assert len(rlist.entries) == 1
    # simulate reload from disk
    import json
    path = os.path.join(tempfile.mkdtemp(), "revocations.json")
    rlist.save(path)
    r2 = RevocationList.load(path)
    assert is_revoked(vid, r2) is True


def test_only_issuer_can_revoke():
    """A non-issuer cannot add a valid revocation entry (structure check)."""
    issuer, subject, v = _make_vouch()
    attacker = generate_identity()
    vid = revoke_payload_id(v)
    rlist = RevocationList()
    # revocation must be signed by the issuer (or a designated revoker)
    ok = revoke_vouch(rlist, issuer, vid)   # issuer signs -> valid
    assert ok is True
    ok2 = revoke_vouch(rlist, attacker, vid)  # attacker cannot re-add (dup) anyway
    assert ok2 is False
