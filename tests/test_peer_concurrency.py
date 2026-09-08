"""Concurrent HTTP gossip to one peer loses nothing.

The peer endpoint switched from single-threaded HTTPServer to
ThreadingHTTPServer once the stores gained the cross-process write lock;
this test proves concurrent POSTs from parallel clients all land.
"""

from __future__ import annotations

import json
import threading
import urllib.request as urlrequest

from atar.identity import generate_identity
from atar.peer import run_peer
from atar.store import VouchStore
from atar.vouch import create_vouch


def test_concurrent_http_gossip_posts_all_land(tmp_path):
    home = str(tmp_path)
    server = run_peer(port=0, bind="127.0.0.1", home=home, _block=False)
    port = server.server_address[1]
    try:
        subject = generate_identity()
        batches = []
        for k in range(4):
            issuer = generate_identity()
            batches.append([
                create_vouch(issuer, subject.public_key,
                             score=round(0.5 + 0.01 * (k * 4 + j), 3),
                             scope="coding", ts=1_700_000_000 + k * 100 + j)
                for j in range(4)
            ])

        errors = []

        def post_all(batch):
            try:
                data = json.dumps({"vouches": batch}).encode()
                req = urlrequest.Request(
                    f"http://127.0.0.1:{port}/vouches", data=data,
                    headers={"Content-Type": "application/json"})
                with urlrequest.urlopen(req, timeout=15) as resp:
                    counts = json.loads(resp.read())
                assert counts["added"] == len(batch), counts
            except Exception as exc:  # noqa: BLE001 - reported below
                errors.append(exc)

        threads = [threading.Thread(target=post_all, args=(b,)) for b in batches]
        for t in threads:
            t.start()
        for t in threads:
            t.join()
        assert not errors, errors

        store = VouchStore(str(tmp_path / "vouches.json"))
        assert store.count() == 16
    finally:
        server.shutdown()
        server.server_close()
