"""Live Know-Your-Agent dashboard — a local, serverless web view.

Serves the trust-network dashboard over a tiny built-in HTTP server (Python
stdlib only — no dependencies, no cost). Open it in a browser to watch your
private agent network. The page re-renders from the persistent store on every
request, so it always reflects the current state.

Usage:
    from atar.web import run_server
    run_server(port=8765)   # then visit http://localhost:8765

Private, local, $0. Never exposes the network externally (bind to 127.0.0.1).
"""

from __future__ import annotations

import json
from http.server import BaseHTTPRequestHandler, HTTPServer

from .dashboard import render_dashboard_html
from .store import VouchStore
from .agent_bootstrap import AgentRegistry
from .identity import did_from_public


def build_dashboard_response(*, scope: str = "intelligence") -> str:
    """Build the dashboard HTML from the current persistent store + registry."""
    try:
        reg = AgentRegistry()
        seed = reg.seed_did or ""
        vouches = reg._store.all()
    except Exception:
        reg = None
        seed = ""
        vouches = VouchStore(_store_path()).all() if _store_path_exists() else []
    net = {"agents": {}, "seed_did": seed, "vouches": vouches}
    # enrich agent names if registry available
    if reg is not None:
        net["agents"] = {
            n: d["did"] for n, d in reg._agents.items() if n != "_seed"
        }
    return render_dashboard_html(net, scope=scope)


def _store_path() -> str:
    import os
    home = os.environ.get("ATAR_HOME", os.path.join(os.path.expanduser("~"), ".atar"))
    return os.path.join(home, "vouches.json")


def _store_path_exists() -> bool:
    return os.path.exists(_store_path())


class DashboardHandler(BaseHTTPRequestHandler):
    """Serves the dashboard on GET / and a JSON view on GET /api."""

    def do_GET(self):  # noqa: N802  (stdlib API)
        if self.path.startswith("/api"):
            self._serve_json()
        else:
            self._serve_html()

    def _serve_html(self):
        scope = "intelligence"
        try:
            body = build_dashboard_response(scope=scope)
        except Exception as exc:  # pragma: no cover - defensive
            body = f"<h1>ATAR dashboard error</h1><pre>{exc}</pre>"
        payload = body.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def _serve_json(self):
        reg = AgentRegistry()
        net = reg.build_network(scope="intelligence")
        from .dashboard import dashboard_data
        data = dashboard_data(net, scope="intelligence")
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):  # silence default stderr logging
        return


def run_server(port: int = 8765, bind: str = "127.0.0.1"):
    """Start the local dashboard server. Blocks until interrupted."""
    server = HTTPServer((bind, port), DashboardHandler)
    print(f"ATAR dashboard → http://{bind}:{port}  (Ctrl+C to stop)")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
