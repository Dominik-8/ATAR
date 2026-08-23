import os
import time
import json
import tempfile

from atar.revocation import RevocationList, revoke_vouch, revoke_payload_id
from atar.identity import generate_identity, did_from_public
from atar.vouch import create_vouch, verify_vouch


def _make_vouch():
    issuer = generate_identity()
    subj = generate_identity()
    v = create_vouch(issuer, subj.public_key, score=0.9, scope="intelligence")
    return issuer, v


def test_vouch_expires_after_ttl():
    """A vouch past its TTL is treated as not-trusted (freshness enforcement)."""
    from atar.freshness import is_fresh, VOUCH_TTL_DEFAULT
    issuer, v = _make_vouch()
    # freshly created vouch (ts near now) is fresh
    assert is_fresh(v, ttl=VOUCH_TTL_DEFAULT) is True
    # a vouch whose ts is older than the TTL is stale
    old = dict(v)
    old["payload"] = dict(v["payload"])
    old["payload"]["ts"] = int(time.time()) - (VOUCH_TTL_DEFAULT + 100)
    assert is_fresh(old, ttl=VOUCH_TTL_DEFAULT) is False


def test_revoked_vs_expired_distinct():
    """Expiry is independent of revocation: a vouch can be fresh-but-revoked
    or valid-but-expired. Both must be rejected by a trust-aware check."""
    from atar.freshness import is_fresh, VOUCH_TTL_DEFAULT, trust_valid
    issuer, v = _make_vouch()
    # valid + fresh
    assert trust_valid(v, ttl=VOUCH_TTL_DEFAULT) is True
    # fresh but we add it to a revocation list
    rl = RevocationList()
    assert revoke_vouch(rl, issuer, revoke_payload_id(v)) is True
    assert trust_valid(v, revocation_list=rl, ttl=VOUCH_TTL_DEFAULT) is False
    # not revoked but expired
    old = dict(v)
    old["payload"] = dict(v["payload"])
    old["payload"]["ts"] = int(time.time()) - (VOUCH_TTL_DEFAULT + 100)
    assert trust_valid(old, ttl=VOUCH_TTL_DEFAULT) is False


def test_freshness_cli_flag(tmp_path, monkeypatch):
    """atar verify --max-age reports EXPIRED for a stale (but validly signed) vouch."""
    from click.testing import CliRunner
    from atar.cli import cli
    from atar.identity import generate_identity, did_from_public
    from atar.vouch import create_vouch
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    issuer = generate_identity()
    subj = generate_identity()
    # build a validly-signed vouch whose ts is far in the past
    old_v = create_vouch(issuer, subj.public_key, score=0.9, scope="coding",
                         ts=int(time.time()) - 999999)
    out = tmp_path / "v.json"
    out.write_text(json.dumps(old_v), encoding="utf-8")
    r = CliRunner().invoke(cli, ["verify", "--max-age", "86400", str(out)])
    assert r.exit_code != 0
    assert "EXPIRED" in r.output.upper()
