"""Persistent vouch store — durability for the ATAR trust graph.

Vouches are kept in a single JSON file (content-addressed by vouch ID, so
dedup is automatic). No server, no database, no cost. This is the layer that
lets a trust network *survive restarts* — a prerequisite for seeding real
agents (Phase 4d).

Design: append-only-ish JSON list, validated on add (invalid vouches never
enter the store), deduped by canonical vouch ID.
"""

from __future__ import annotations

import contextlib
import json
import os

from .transparency import canonical_vouch_id, verify_vouch


def _lock_fd(f) -> None:
    """Best-effort blocking exclusive lock on an open file (POSIX + Windows)."""
    if os.name == "posix":
        import fcntl

        fcntl.flock(f.fileno(), fcntl.LOCK_EX)
    elif os.name == "nt":  # pragma: no cover - windows only
        import msvcrt

        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)


def _unlock_fd(f) -> None:
    if os.name == "posix":
        import fcntl

        fcntl.flock(f.fileno(), fcntl.LOCK_UN)
    elif os.name == "nt":  # pragma: no cover - windows only
        import msvcrt

        f.seek(0)
        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)


@contextlib.contextmanager
def file_lock(path: str):
    """Cross-process advisory lock guarding read-modify-write cycles on
    ``path`` (the lock lives in ``<path>.lock`` next to the data file).

    Atomic writes alone do not stop *lost updates*: two processes that each
    load -> mutate -> save the same store can silently drop each other's
    entries (a running ``atar peer`` plus a CLI command, or two concurrent
    syncs). Serializing the whole cycle on an OS-level advisory lock closes
    that window. Locking is best-effort: on platforms without ``fcntl``/
    ``msvcrt`` the lock degrades to a no-op rather than breaking the store.
    """
    lock_path = path + ".lock"
    os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
    with open(lock_path, "a+b") as f:
        try:
            _lock_fd(f)
        except OSError:  # pragma: no cover - locking unsupported/failed
            pass
        try:
            yield
        finally:
            try:
                _unlock_fd(f)
            except OSError:  # pragma: no cover
                pass


def atomic_save_json(obj, path: str) -> None:
    """Write JSON to ``path`` atomically (temp file + os.replace).

    A crash mid-write must never leave a truncated store behind: the previous
    complete file stays in place until the new one is fully written.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(obj, f, indent=2)
    os.replace(tmp, path)


class VouchStore:
    """A local, file-backed collection of valid vouches."""

    def __init__(self, path: str) -> None:
        self.path = path
        self._vouches: dict[str, dict] = {}
        self._load()

    def _load(self) -> None:
        if not os.path.exists(self.path):
            return
        try:
            with open(self.path, "r", encoding="utf-8") as f:
                data = json.load(f)
            for v in data.get("vouches", []):
                vid = canonical_vouch_id(v)
                self._vouches[vid] = v
        except (json.JSONDecodeError, KeyError):
            # corrupt store — start clean rather than crash
            self._vouches = {}

    def _save(self) -> None:
        atomic_save_json({"vouches": list(self._vouches.values())}, self.path)

    def add(self, vouch: dict) -> bool:
        """Add a vouch if valid + new. Returns True if stored.

        The load -> dedup -> save cycle runs under a cross-process file lock
        and refreshes from disk first, so a vouch written by another process
        (a running peer endpoint, a parallel sync) since this store was
        constructed is never silently dropped.
        """
        if not verify_vouch(vouch):
            return False
        vid = canonical_vouch_id(vouch)
        with file_lock(self.path):
            self._load()
            if vid in self._vouches:
                return False  # already present (dedup)
            self._vouches[vid] = vouch
            self._save()
        return True

    def get(self, vid: str) -> dict | None:
        """Return the vouch with this canonical ID, or None."""
        return self._vouches.get(vid)

    def all(self) -> list[dict]:
        return list(self._vouches.values())

    def count(self) -> int:
        return len(self._vouches)


def add_vouch_file(store: VouchStore, vouch: dict) -> bool:
    return store.add(vouch)


def load_store(path: str) -> VouchStore:
    return VouchStore(path)


def save_store(store: VouchStore) -> bool:
    store._save()
    return True
