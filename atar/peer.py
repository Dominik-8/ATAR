"""HTTP peer endpoint — gossip between separate operators (Stage C1).

Filesystem sync (`atar sync --with <peer_home>`) only works when both agents
share a filesystem. This module adds the slim network transport: every operator
can expose their local store over HTTP, and peers exchange vouches and
revocations directly — still content-addressed, still no central server.

Endpoint surface (JSON only, stdlib only):

    GET  /             -> {"protocol": "atar-peer/1.0", counts}
    GET  /vouches      -> {"vouches": [vouch_blob, ...]}
    POST /vouches      <- one vouch blob or {"vouches": [...]}
                          -> {"added": n, "duplicates": n, "rejected": n}
    GET  /revocations  -> {"revocations": [entry, ...]}
    POST /revocations  <- one entry or {"revocations": [...]}
                          -> {"added": n, "duplicates": n, "rejected": n}
    GET  /disputes     -> {"disputes": [entry, ...]}
    POST /disputes     <- one entry or {"disputes": [...]}
                          -> {"added": n, "duplicates": n, "rejected": n}

Intake rules mirror filesystem sync exactly (SPEC §6/§9): vouch signatures are
verified, issuer-revoked vouches are never admitted, revocation entries are
signature-verified and issuer-bound when the vouch is known. Nothing enters a
store unverified, whatever transport it arrived on.
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib import request as urlrequest
from urllib.error import URLError

from .dispute import DisputeList
from .revocation import RevocationList, verify_revocation_entry
from .store import VouchStore
from .vouch import verify_vouch

PROTOCOL = "atar-peer/1.0"


def _default_home() -> str:
    return os.environ.get("ATAR_HOME", os.path.join(os.path.expanduser("~"), ".atar"))


def is_url(peer: str) -> bool:
    """True iff a peer address is an HTTP(S) endpoint rather than a local dir."""
    return peer.startswith("http://") or peer.startswith("https://")


class _PeerState:
    """Store + revocation list backing one peer endpoint (per ATAR_HOME)."""

    def __init__(self, home: str) -> None:
        self.home = home
        self.store_path = os.path.join(home, "vouches.json")
        self.revocations_path = os.path.join(home, "revocations.json")
        self.disputes_path = os.path.join(home, "disputes.json")

    def store(self) -> VouchStore:
        return VouchStore(self.store_path)

    def revocations(self) -> RevocationList:
        return RevocationList.load(self.revocations_path)

    def disputes(self) -> DisputeList:
        return DisputeList.load(self.disputes_path)

    def admit_vouch(self, vouch: dict) -> str:
        """'added' | 'duplicate' | 'rejected' — same rules as filesystem sync."""
        if not verify_vouch(vouch):
            return "rejected"
        rl = self.revocations()
        if rl.is_revoked_for(vouch):
            return "rejected"  # revoked by its issuer: never admitted (SPEC §9)
        return "added" if self.store().add(vouch) else "duplicates"

    def admit_revocation(self, entry: dict) -> str:
        """'added' | 'duplicate' | 'rejected' — signature + issuer binding."""
        try:
            vid = entry["vid"]
        except (KeyError, TypeError):
            return "rejected"
        rl = self.revocations()
        if rl.is_revoked(vid):
            return "duplicates"
        if not verify_revocation_entry(entry):
            return "rejected"
        ok = rl.add(entry["revoked_by"], vid, entry["ts"], entry["signature"],
                    vouch=self.store().get(vid))
        if not ok:
            return "rejected"
        rl.save(self.revocations_path)
        return "added"

    def admit_dispute(self, entry: dict) -> str:
        """'added' | 'duplicates' | 'rejected' — signature always verified;
        issuer-disputes rejected at intake when the vouch is known (§8.2)."""
        from .dispute import _entry_id, verify_dispute_entry
        try:
            eid = _entry_id(entry)
        except (KeyError, TypeError):
            return "rejected"
        dl = self.disputes()
        if eid in dl.entries:
            return "duplicates"
        if not verify_dispute_entry(entry):
            return "rejected"
        if not dl.add(entry, vouch=self.store().get(entry.get("vid", ""))):
            return "rejected"
        dl.save(self.disputes_path)
        return "added"


def make_peer_handler(state: _PeerState):
    class PeerHandler(BaseHTTPRequestHandler):
        def _send_json(self, obj: dict, status: int = 200) -> None:
            payload = json.dumps(obj).encode("utf-8")
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)

        def _read_json(self):
            try:
                length = int(self.headers.get("Content-Length", "0"))
            except ValueError:
                return None
            if length <= 0 or length > 10 * 1024 * 1024:
                return None
            try:
                return json.loads(self.rfile.read(length).decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                return None

        def do_GET(self):  # noqa: N802  (stdlib API)
            if self.path == "/" or self.path.startswith("/?"):
                self._send_json({
                    "protocol": PROTOCOL,
                    "vouches": state.store().count(),
                    "revocations": len(state.revocations().all()),
                    "disputes": len(state.disputes().all()),
                })
            elif self.path == "/vouches":
                self._send_json({"vouches": state.store().all()})
            elif self.path == "/revocations":
                self._send_json({"revocations": state.revocations().all()})
            elif self.path == "/disputes":
                self._send_json({"disputes": state.disputes().all()})
            else:
                self._send_json({"error": "not found"}, status=404)

        def do_POST(self):  # noqa: N802  (stdlib API)
            body = self._read_json()
            if body is None:
                self._send_json({"error": "invalid JSON body"}, status=400)
                return
            if self.path == "/vouches":
                items = body.get("vouches") if isinstance(body, dict) and "vouches" in body else [body]
                counts = {"added": 0, "duplicates": 0, "rejected": 0}
                for v in items if isinstance(items, list) else []:
                    counts[state.admit_vouch(v)] += 1
                self._send_json(counts)
            elif self.path == "/revocations":
                items = body.get("revocations") if isinstance(body, dict) and "revocations" in body else [body]
                counts = {"added": 0, "duplicates": 0, "rejected": 0}
                for e in items if isinstance(items, list) else []:
                    counts[state.admit_revocation(e)] += 1
                self._send_json(counts)
            elif self.path == "/disputes":
                items = body.get("disputes") if isinstance(body, dict) and "disputes" in body else [body]
                counts = {"added": 0, "duplicates": 0, "rejected": 0}
                for e in items if isinstance(items, list) else []:
                    counts[state.admit_dispute(e)] += 1
                self._send_json(counts)
            else:
                self._send_json({"error": "not found"}, status=404)

        def log_message(self, *args):  # silence default stderr logging
            return

    return PeerHandler


def run_peer(port: int = 8790, bind: str = "127.0.0.1", home: str | None = None,
             _block: bool = True):
    """Serve the local store over HTTP. ``_block=False`` returns the server
    (used by tests; the caller must ``shutdown()`` it)."""
    state = _PeerState(home or _default_home())
    server = HTTPServer((bind, port), make_peer_handler(state))
    if not _block:
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return server
    print(f"ATAR peer endpoint → http://{bind}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


# --- client side ------------------------------------------------------------

def _get_json(url: str, timeout: float = 10.0) -> dict:
    with urlrequest.urlopen(url, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _post_json(url: str, obj: dict, timeout: float = 10.0) -> dict:
    data = json.dumps(obj).encode("utf-8")
    req = urlrequest.Request(url, data=data,
                             headers={"Content-Type": "application/json"})
    with urlrequest.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def sync_with_url(url: str, store: VouchStore, rlist: RevocationList,
                  disputes_path: str | None = None) -> dict:
    """Exchange vouches + revocations (+ disputes) with a remote peer over HTTP.

    Pull: take everything valid + new from the peer (skipping vouches revoked
    by their issuer, defense-in-depth). Push: POST our full sets; the peer
    dedups content-addressed and reports how much it accepted. Returns counts.
    """
    base = url.rstrip("/")
    counts = {"vouches_in": 0, "vouches_out": 0, "revocations_in": 0,
              "revocations_out": 0, "disputes_in": 0, "disputes_out": 0,
              "rejected_by_peer": 0}

    remote_vouches = _get_json(f"{base}/vouches").get("vouches", [])
    for v in remote_vouches:
        if rlist.is_revoked_for(v):
            continue
        if store.add(v):
            counts["vouches_in"] += 1

    if store.all():
        resp = _post_json(f"{base}/vouches", {"vouches": store.all()})
        counts["vouches_out"] = int(resp.get("added", 0))
        counts["rejected_by_peer"] += int(resp.get("rejected", 0))

    remote_revs = _get_json(f"{base}/revocations").get("revocations", [])
    for e in remote_revs:
        if rlist.add(e["revoked_by"], e["vid"], e["ts"], e["signature"],
                     vouch=store.get(e["vid"])):
            counts["revocations_in"] += 1

    if rlist.all():
        resp = _post_json(f"{base}/revocations", {"revocations": rlist.all()})
        counts["revocations_out"] = int(resp.get("added", 0))
        counts["rejected_by_peer"] += int(resp.get("rejected", 0))

    # disputes (SPEC 8.2): warnings travel the network too
    dlist = DisputeList.load(disputes_path) if disputes_path else DisputeList()
    remote_disps = _get_json(f"{base}/disputes").get("disputes", [])
    for e in remote_disps:
        if dlist.add(e, vouch=store.get(e["vid"])):
            counts["disputes_in"] += 1
    if disputes_path:
        dlist.save(disputes_path)
    if dlist.all():
        resp = _post_json(f"{base}/disputes", {"disputes": dlist.all()})
        counts["disputes_out"] = int(resp.get("added", 0))
        counts["rejected_by_peer"] += int(resp.get("rejected", 0))

    return counts
