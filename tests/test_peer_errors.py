"""Peer endpoint error handling: bad input gets a clean 4xx, unexpected
failures get a 500 JSON body instead of a dropped connection."""

from __future__ import annotations

import json
import urllib.error
import urllib.request as urlrequest

import pytest

import atar.peer
from atar.identity import generate_identity
from atar.peer import run_peer
from atar.vouch import create_vouch


@pytest.fixture()
def peer(tmp_path):
    server = run_peer(port=0, bind="127.0.0.1", home=str(tmp_path), _block=False)
    yield server.server_address[1]
    server.shutdown()
    server.server_close()


def _post(port: int, path: str, payload) -> tuple[int, dict]:
    data = json.dumps(payload).encode()
    req = urlrequest.Request(
        f"http://127.0.0.1:{port}{path}",
        data=data,
        headers={"Content-Type": "application/json"},
    )
    try:
        with urlrequest.urlopen(req, timeout=10) as resp:
            return resp.status, json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        return exc.code, json.loads(exc.read())


def test_non_list_batch_payload_gets_400_not_silent_zero(peer):
    status, body = _post(peer, "/vouches", {"vouches": {"not": "a list"}})
    assert status == 400
    assert "list" in body["error"]


def test_garbage_items_count_as_rejected(peer):
    status, body = _post(peer, "/vouches", {"vouches": [42, "x", None, {}]})
    assert status == 200
    assert body == {"added": 0, "duplicates": 0, "rejected": 4}


def test_unexpected_intake_error_gets_500_json(peer, monkeypatch):
    def boom(self, vouch):
        raise RuntimeError("disk exploded")

    monkeypatch.setattr(atar.peer._PeerState, "admit_vouch", boom)
    issuer, subject = generate_identity(), generate_identity()
    vouch = create_vouch(
        issuer, subject.public_key, score=0.9, scope="coding", ts=1_700_000_000
    )
    status, body = _post(peer, "/vouches", vouch)
    assert status == 500
    assert body == {"error": "internal error"}
