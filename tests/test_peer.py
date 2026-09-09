"""Stage C1: HTTP gossip transport (SPEC 9.1)."""

import json
import os
from urllib import request as urlrequest
from urllib.error import HTTPError

import pytest
from click.testing import CliRunner

from atar.cli import cli
from atar.identity import generate_identity
from atar.peer import is_url, run_peer, sync_with_url
from atar.revocation import RevocationList, revoke_vouch
from atar.store import VouchStore
from atar.transparency import canonical_vouch_id
from atar.vouch import create_vouch


def _get(url):
    with urlrequest.urlopen(url, timeout=5) as r:
        return json.loads(r.read().decode())


def _post(url, obj):
    data = json.dumps(obj).encode()
    req = urlrequest.Request(
        url, data=data, headers={"Content-Type": "application/json"}
    )
    with urlrequest.urlopen(req, timeout=5) as r:
        return json.loads(r.read().decode())


@pytest.fixture
def server(tmp_path):
    """A live peer endpoint backed by a fresh ATAR_HOME."""
    home = str(tmp_path / "peer_home")
    os.makedirs(home)
    srv = run_peer(port=0, bind="127.0.0.1", home=home, _block=False)
    yield f"http://127.0.0.1:{srv.server_address[1]}", home
    srv.shutdown()
    srv.server_close()


def _make_vouch(score=0.9, scope="coding"):
    issuer = generate_identity()
    subject = generate_identity()
    return (
        create_vouch(issuer, subject.public_key, score=score, scope=scope),
        issuer,
        subject,
    )


def test_is_url():
    assert is_url("http://localhost:8790")
    assert is_url("https://peer.example.com")
    assert not is_url("/home/agent/.atar")
    assert not is_url("relative/path")


def test_info_endpoint(server):
    url, _ = server
    info = _get(url + "/")
    assert info["protocol"] == "atar-peer/1.0"
    assert info["vouches"] == 0


def test_vouch_post_get_roundtrip(server):
    url, home = server
    vouch, _, _ = _make_vouch()
    resp = _post(url + "/vouches", vouch)
    assert resp == {"added": 1, "duplicates": 0, "rejected": 0}
    # content-addressed dedup: same blob again is a duplicate, not an error
    resp2 = _post(url + "/vouches", {"vouches": [vouch]})
    assert resp2 == {"added": 0, "duplicates": 1, "rejected": 0}
    got = _get(url + "/vouches")
    assert len(got["vouches"]) == 1
    assert got["vouches"][0] == vouch
    # and it really landed in the peer's store
    assert VouchStore(os.path.join(home, "vouches.json")).count() == 1


def test_invalid_vouch_rejected_over_http(server):
    url, home = server
    vouch, _, _ = _make_vouch()
    vouch["payload"]["score"] = 0.1  # tamper -> signature no longer verifies
    resp = _post(url + "/vouches", vouch)
    assert resp["rejected"] == 1 and resp["added"] == 0
    assert VouchStore(os.path.join(home, "vouches.json")).count() == 0


def test_revocation_post_get_roundtrip(server):
    url, _ = server
    vouch, issuer, _ = _make_vouch()
    _post(url + "/vouches", vouch)
    rl = RevocationList()
    assert revoke_vouch(rl, issuer, canonical_vouch_id(vouch))
    entry = rl.all()[0]
    resp = _post(url + "/revocations", entry)
    assert resp == {"added": 1, "duplicates": 0, "rejected": 0}
    got = _get(url + "/revocations")
    assert got["revocations"] == [entry]


def test_forged_revocation_rejected_over_http(server):
    url, _ = server
    vouch, _, _ = _make_vouch()
    attacker = generate_identity()
    rl = RevocationList()
    # attacker signs a revocation for someone else's vouch with their own key
    revoke_vouch(rl, attacker, canonical_vouch_id(vouch))
    forged = rl.all()[0]
    _post(url + "/vouches", vouch)  # peer knows the vouch -> issuer binding enforced
    resp = _post(url + "/revocations", forged)
    assert resp["rejected"] == 1
    assert _get(url + "/revocations")["revocations"] == []


def test_issuer_revoked_vouch_never_admitted_over_http(server):
    url, _ = server
    vouch, issuer, _ = _make_vouch()
    rl = RevocationList()
    revoke_vouch(rl, issuer, canonical_vouch_id(vouch))
    _post(url + "/revocations", rl.all()[0])
    resp = _post(url + "/vouches", vouch)
    assert resp["rejected"] == 1  # defense-in-depth: revoked by issuer


def test_sync_with_url_both_directions(server, tmp_path):
    url, _home = server
    vouch_remote, _, _ = _make_vouch(scope="research")
    _post(url + "/vouches", vouch_remote)
    local_store = VouchStore(str(tmp_path / "local" / "vouches.json"))
    local_rl = RevocationList()
    vouch_local, _, _ = _make_vouch(scope="coding")
    local_store.add(vouch_local)
    counts = sync_with_url(url, local_store, local_rl)
    assert counts["vouches_in"] == 1
    assert counts["vouches_out"] == 1
    assert local_store.get(canonical_vouch_id(vouch_remote))
    peer_vids = {canonical_vouch_id(v) for v in _get(url + "/vouches")["vouches"]}
    assert canonical_vouch_id(vouch_local) in peer_vids


def test_sync_cli_with_http_peer(server, tmp_path, monkeypatch):
    url, _peer_home = server
    my_home = str(tmp_path / "me")
    os.makedirs(my_home)
    monkeypatch.setenv("ATAR_HOME", my_home)
    # remote has a vouch; we have none -> sync pulls it
    vouch, _, _ = _make_vouch()
    _post(url + "/vouches", vouch)
    runner = CliRunner()
    r = runner.invoke(cli, ["sync", "--with", url])
    assert r.exit_code == 0, r.output
    assert "+1 vouches" in r.output
    assert VouchStore(os.path.join(my_home, "vouches.json")).count() == 1


def test_auto_sync_cli_with_http_peer(server, tmp_path, monkeypatch):
    url, _peer_home = server
    my_home = str(tmp_path / "me")
    os.makedirs(my_home)
    monkeypatch.setenv("ATAR_HOME", my_home)
    vouch, _, _ = _make_vouch()
    _post(url + "/vouches", vouch)
    with open(os.path.join(my_home, "atar_peers.json"), "w") as _f:
        json.dump({"peers": [url]}, _f)
    runner = CliRunner()
    r = runner.invoke(cli, ["auto-sync"])
    assert r.exit_code == 0, r.output
    assert VouchStore(os.path.join(my_home, "vouches.json")).count() == 1


def test_auto_sync_unreachable_url_is_skipped(tmp_path, monkeypatch):
    my_home = str(tmp_path / "me")
    os.makedirs(my_home)
    monkeypatch.setenv("ATAR_HOME", my_home)
    with open(os.path.join(my_home, "atar_peers.json"), "w") as _f:
        json.dump(
            {"peers": ["http://127.0.0.1:1"]},
            _f,
        )
    runner = CliRunner()
    r = runner.invoke(cli, ["auto-sync"])
    assert r.exit_code == 0, r.output
    assert "unreachable" in r.output


def test_unknown_route_404(server):
    url, _ = server
    with pytest.raises(HTTPError):
        _get(url + "/nope")
