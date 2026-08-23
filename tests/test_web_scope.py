import os
import tempfile
import threading
import urllib.request

from atar.web import build_dashboard_response, run_server
from atar.agent_bootstrap import AgentRegistry, seed_trust_root
from atar.store import VouchStore


def _seed_multi(home, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    reg = AgentRegistry()
    seed_trust_root("seed_agent")
    reg = AgentRegistry()
    reg.register("research")
    reg.register("market")
    reg.vouch("seed_agent", "research", score=0.9, scope="intelligence")
    reg.vouch("seed_agent", "research", score=0.8, scope="coding")
    reg.vouch("seed_agent", "market", score=0.8, scope="intelligence")
    return reg


def test_web_multi_scope_renders_all_scopes(tmp_path, monkeypatch):
    _seed_multi(str(tmp_path), monkeypatch)
    html = build_dashboard_response_multi(scopes=["intelligence", "coding"])
    assert "intelligence" in html
    assert "coding" in html
    assert "scope-sec" in html


def test_web_single_scope_filter(tmp_path, monkeypatch):
    _seed_multi(str(tmp_path), monkeypatch)
    html = build_dashboard_response(scope="coding")
    # coding scope: market has no coding vouch -> only seed_agent + research
    assert "research" in html
    # but market should NOT appear in the coding-only render
    assert "market" not in html


def test_server_serves_and_scope_query(tmp_path, monkeypatch):
    _seed_multi(str(tmp_path), monkeypatch)
    port = 8799
    srv = run_server(port=port, bind="127.0.0.1", _block=False)
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/?scope=coding", timeout=5) as r:
            body = r.read().decode("utf-8")
        assert "coding" in body
        # market has no coding vouch -> absent in coding scope
        assert "market" not in body
    finally:
        srv.shutdown()


# helper: reuse the multi-scope renderer the web module now exposes
from atar.web import build_dashboard_response_multi  # noqa: E402
