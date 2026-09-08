"""Persistent vouch store — durability for the ATAR trust graph.

Vouches are kept in a single JSON file (content-addressed by vouch ID, so
dedup is automatic). No server, no database, no cost. This is the layer that
lets a trust network *survive restarts* — a prerequisite for seeding real
agents (Phase 4d).

Design: append-only-ish JSON list, validated on add (invalid vouches never
enter the store), deduped by canonical vouch ID.
"""

from __future__ import annotations

import json
import os

from .transparency import canonical_vouch_id, verify_vouch


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
        os.makedirs(os.path.dirname(self.path) or ".", exist_ok=True)
        with open(self.path, "w", encoding="utf-8") as f:
            json.dump({"vouches": list(self._vouches.values())}, f, indent=2)

    def add(self, vouch: dict) -> bool:
        """Add a vouch if valid + new. Returns True if stored."""
        if not verify_vouch(vouch):
            return False
        vid = canonical_vouch_id(vouch)
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
