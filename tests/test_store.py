import os
import json
import tempfile

from atar.identity import generate_identity, did_from_public
from atar.vouch import create_vouch
from atar.store import VouchStore, add_vouch_file, load_store, save_store


def test_vouch_store_persists_and_reloads():
    d = tempfile.mkdtemp()
    store_path = os.path.join(d, "vouches.json")
    s = VouchStore(store_path)
    assert len(s.all()) == 0
    # add a vouch
    issuer = generate_identity()
    subj = generate_identity()
    v = create_vouch(issuer, subj.public_key, score=0.9, scope="coding")
    assert s.add(v) is True
    # reload from disk -> still there
    s2 = VouchStore(store_path)
    assert len(s2.all()) == 1
    assert s2.all()[0]["payload"]["subject"] == did_from_public(subj.public_key)


def test_store_rejects_invalid_vouch():
    d = tempfile.mkdtemp()
    s = VouchStore(os.path.join(d, "vouches.json"))
    # a forged blob (no signature) must be rejected
    forged = {"payload": {"issuer": "did:agent:x", "subject": "did:agent:y",
                          "score": 1.0, "scope": "coding"}, "signature": "deadbeef"}
    assert s.add(forged) is False
    assert len(s.all()) == 0


def test_store_dedup_by_content():
    d = tempfile.mkdtemp()
    s = VouchStore(os.path.join(d, "vouches.json"))
    issuer = generate_identity()
    subj = generate_identity()
    v = create_vouch(issuer, subj.public_key, score=0.9, scope="coding")
    assert s.add(v) is True
    assert s.add(v) is False  # same content -> no duplicate
    assert len(s.all()) == 1


def test_roundtrip_helpers(tmp_path):
    d = tmp_path / "vstore.json"
    s = VouchStore(str(d))
    issuer = generate_identity()
    subj = generate_identity()
    v = create_vouch(issuer, subj.public_key, score=0.7, scope="intelligence")
    add_vouch_file(s, v)
    s2 = load_store(str(d))
    assert len(s2.all()) == 1
    saved = save_store(s2)
    assert saved is True
