"""Cross-process concurrency regression for keys.json (private key material).

Same lost-update class as the vouch store: two concurrent CLI commands each
did load -> mutate -> save on keys.json and could silently drop each other's
identities — losing a *private key* write is worse than losing a vouch.
All four write paths (keygen, rotate, reissue --commit key retirement,
import --keys) now run under the store's advisory file lock.
"""

from __future__ import annotations

import json
import multiprocessing

from click.testing import CliRunner

from atar.cli import cli


def _keygen_worker(home: str, name: str) -> None:
    import os
    os.environ["ATAR_HOME"] = home
    r = CliRunner().invoke(cli, ["keygen", "--name", name])
    assert r.exit_code == 0, r.output


def test_concurrent_keygens_lose_no_identities(tmp_path):
    home = str(tmp_path)
    names = [f"agent{k}" for k in range(6)]
    procs = [multiprocessing.Process(target=_keygen_worker, args=(home, n))
             for n in names]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    assert all(p.exitcode == 0 for p in procs)

    keys = json.loads((tmp_path / "keys.json").read_text())
    assert sorted(keys) == sorted(names)
    for rec in keys.values():
        assert rec["did"].startswith("did:key:")
        assert len(rec["private"]) == 64
