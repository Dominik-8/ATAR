"""Live Know-Your-Agent dashboard — a local, serverless web view.

Serves the trust-network dashboard over a tiny built-in HTTP server (Python
stdlib only — no dependencies, no cost). Open it in a browser to watch your
private agent network. The page re-renders from the persistent store on every
request, so it always reflects the current state.

Multi-scope (Phase 13/25): the dashboard shows one section per scope. Use the
`?scope=` query parameter to zoom into a single scope.

Usage:
    from atar.web import run_server
    run_server(port=8765)   # then visit http://localhost:8765

Private, local, $0. Never exposes the network externally (bind to 127.0.0.1).
"""

from __future__ import annotations

import json
import os
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from .dashboard import (
    render_dashboard_html,
    render_multi_scope_html,
    dashboard_data,
)
from .store import VouchStore
from .agent_bootstrap import AgentRegistry


def _store_path() -> str:
    home = os.environ.get("ATAR_HOME", os.path.join(os.path.expanduser("~"), ".atar"))
    return os.path.join(home, "vouches.json")


def _store_path_exists() -> bool:
    return os.path.exists(_store_path())


def _all_scopes() -> list[str]:
    """Every scope present across all vouches in the store (sorted, distinct)."""
    try:
        vouches = VouchStore(_store_path()).all()
    except Exception:
        return ["intelligence"]
    scopes = sorted({v["payload"].get("scope") for v in vouches
                     if v["payload"].get("scope")})
    return scopes or ["intelligence"]


def _build_net() -> dict:
    """Build the network dict from the registry + persistent store."""
    try:
        reg = AgentRegistry()
        seed = reg.seed_did or ""
        vouches = reg._store.all()
        from .agent_bootstrap import known_agent_names
        agents = known_agent_names()  # registry + plain keygen identities
    except Exception:
        seed = ""
        vouches = VouchStore(_store_path()).all() if _store_path_exists() else []
        agents = {}
    return {"agents": agents, "seed_did": seed, "vouches": vouches}


def build_dashboard_response(*, scope: str | None = None) -> str:
    """Single-scope render (used when ?scope= is given)."""
    net = _build_net()
    if not net["seed_did"]:
        from .dashboard import render_no_seed_html
        return render_no_seed_html()
    sc = scope or "intelligence"
    return render_dashboard_html(net, scope=sc)


def build_dashboard_response_multi(*, scopes: list[str] | None = None,
                                   focus: str | None = None) -> str:
    """Multi-scope render (one section per scope). If `focus` is set, that
    scope is shown as a single full view (alias for build_dashboard_response)."""
    net = _build_net()
    if not net["seed_did"]:
        from .dashboard import render_no_seed_html
        return render_no_seed_html()
    if focus:
        return render_dashboard_html(net, scope=focus)
    sc = scopes or _all_scopes()
    return render_multi_scope_html(net, scopes=sc)


class DashboardHandler(BaseHTTPRequestHandler):
    """Serves the multi-scope dashboard on GET / and JSON on GET /api."""

    def do_GET(self):  # noqa: N802  (stdlib API)
        if self.path.startswith("/api"):
            self._serve_json()
        else:
            self._serve_html()

    def _serve_html(self):
        try:
            qs = parse_qs(urlparse(self.path).query)
            scope_param = qs.get("scope", [None])[0]
            if scope_param:
                body = build_dashboard_response(scope=scope_param)
            else:
                body = build_dashboard_response_multi()
        except Exception as exc:  # pragma: no cover - defensive
            import html as _html
            body = f"<h1>ATAR dashboard error</h1><pre>{_html.escape(str(exc))}</pre>"
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _serve_json(self):
        reg = AgentRegistry()
        net = reg.build_network(scope="intelligence")
        data = dashboard_data(net, scope="intelligence")
        # also report all scopes + counts (Phase 20/25)
        all_scopes = _all_scopes()
        out = {"scopes": all_scopes, "agents": data["agents"]}
        payload = json.dumps(out, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence default stderr logging
        return


def run_server(port: int = 8765, bind: str = "127.0.0.1", _block: bool = True):
    """Start the local dashboard server.

    When ``_block=False`` (used by tests) it returns the server object so the
    caller can ``shutdown()`` it; otherwise it blocks until interrupted.
    """
    server = HTTPServer((bind, port), DashboardHandler)
    if not _block:
        t = threading.Thread(target=server.serve_forever, daemon=True)
        t.start()
        return server
    print(f"ATAR dashboard → http://{bind}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
