"""Regression: canonical_vouch_id must ignore `ts` (and the signature), so the
same claim issued at two different times collapses to one vouch. This is what
makes `bootstrap` idempotent and prevents re-bootstrap from duplicating the
trust graph. Before the fix, ts was part of the hash -> every bootstrap re-added
all vouches (4 instead of 2 on the second run)."""

from atar.transparency import canonical_vouch_id


def _vouch(ts):
    return {"payload": {"type": "vouch", "issuer": "did:agent:A",
                         "subject": "did:agent:B", "score": 0.9,
                         "scope": "core", "claim": None, "ts": ts},
            "signature": "deadbeef"}


def test_canonical_vouch_id_ignores_ts():
    a = _vouch(1000)
    b = _vouch(9999)  # different timestamp, same claim
    assert canonical_vouch_id(a) == canonical_vouch_id(b)


def test_canonical_vouch_id_differs_by_claim():
    a = _vouch(1000)
    c = dict(a)
    c["payload"] = dict(a["payload"])
    c["payload"]["score"] = 0.5  # different score -> different claim
    assert canonical_vouch_id(a) != canonical_vouch_id(c)
