"""Cross-process concurrency regressions for the file-backed stores.

Atomic writes (temp file + rename) stop torn files, but they do NOT stop
lost updates: two processes that each load -> mutate -> save the same store
used to silently drop each other's entries (a running ``atar peer`` plus a
CLI command, or two concurrent syncs). The stores now serialize the whole
read-modify-write cycle on an advisory lock file and refresh/merge from
disk before writing.
"""

from __future__ import annotations

import multiprocessing
import os

from atar.dispute import DisputeList, create_dispute
from atar.identity import generate_identity
from atar.revocation import RevocationList, revoke_vouch
from atar.store import VouchStore
from atar.vouch import create_vouch


def _make_vouch(issuer, subject, score: float = 0.9) -> dict:
    return create_vouch(issuer, subject.public_key, score=score, scope="coding")


def test_interleaved_store_instances_keep_both_vouches(tmp_path):
    """A store constructed before another process writes must not lose that
    write when it saves later (the classic lost-update interleaving)."""
    path = str(tmp_path / "vouches.json")
    alice = generate_identity()
    bob = generate_identity()
    v1 = _make_vouch(alice, bob)
    v2 = _make_vouch(bob, alice)

    a = VouchStore(path)
    b = VouchStore(path)  # b loads before a's write lands
    assert a.add(v1)
    assert b.add(v2)  # must refresh from disk under the lock, not clobber v1

    final = VouchStore(path)
    assert final.count() == 2


def _add_vouches_worker(path: str, vouches: list) -> None:
    store = VouchStore(path)
    for v in vouches:
        store.add(v)


def test_concurrent_processes_lose_no_vouches(tmp_path):
    """N processes adding disjoint valid vouches to one store file must end
    with every vouch present — the exact peer-server-vs-CLI race."""
    path = str(tmp_path / "vouches.json")
    procs_n, per = 4, 4
    issuers = [generate_identity() for _ in range(procs_n)]
    subject = generate_identity()
    batches = [
        [_make_vouch(issuers[p], subject, score=0.5 + 0.01 * (p * per + j))
         for j in range(per)]
        for p in range(procs_n)
    ]
    procs = [
        multiprocessing.Process(target=_add_vouches_worker, args=(path, batch))
        for batch in batches
    ]
    for p in procs:
        p.start()
    for p in procs:
        p.join()
    assert all(p.exitcode == 0 for p in procs)

    final = VouchStore(path)
    assert final.count() == procs_n * per
    # the lock file is an implementation detail next to the store, and the
    # store itself stays a single valid JSON document
    assert os.path.exists(path + ".lock")


def test_revocation_list_merge_on_save(tmp_path):
    path = str(tmp_path / "revocations.json")
    alice = generate_identity()
    bob = generate_identity()
    v1 = _make_vouch(alice, bob)
    v2 = _make_vouch(bob, alice)

    rl_a = RevocationList()
    rl_b = RevocationList()
    assert revoke_vouch(rl_a, alice, _vid_of(v1))
    rl_a.save(path)
    # rl_b loaded nothing, revokes a different vouch, saves later
    assert revoke_vouch(rl_b, bob, _vid_of(v2))
    rl_b.save(path)

    merged = RevocationList.load(path)
    assert merged.is_revoked(_vid_of(v1))
    assert merged.is_revoked(_vid_of(v2))


def test_dispute_list_merge_on_save(tmp_path):
    path = str(tmp_path / "disputes.json")
    carol = generate_identity()
    dave = generate_identity()
    target = _make_vouch(generate_identity(), generate_identity())

    dl_a = DisputeList()
    dl_b = DisputeList()
    assert dl_a.add(create_dispute(carol, target, reason="inflated score"))
    dl_a.save(path)
    assert dl_b.add(create_dispute(dave, target, reason="wrong scope"))
    dl_b.save(path)

    merged = DisputeList.load(path)
    assert len(merged.disputes_for(target)) == 2


def _vid_of(vouch: dict) -> str:
    from atar.transparency import canonical_vouch_id
    return canonical_vouch_id(vouch)
