"""Live HTTP test for `atar serve` (the actual CLI command, not just the
imported run_server function). Starts the server as a real subprocess, makes
an HTTP GET, and asserts it serves a 200 with dashboard HTML. This is the one
piece of the dashboard pipeline never hit over real HTTP before."""

import os
import subprocess
import sys
import time
import urllib.request

import pytest


def test_serve_http_smoke(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    # bootstrap a tiny real network first
    from click.testing import CliRunner
    from atar.cli import cli

    r = CliRunner().invoke(cli, ["keygen", "--name", "seed"])
    assert r.exit_code == 0, r.output

    port = 8799
    proc = subprocess.Popen(
        [sys.executable, "-m", "atar.cli", "serve", "--port", str(port)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env={**os.environ, "ATAR_HOME": str(tmp_path)},
    )
    try:
        # wait for server to come up
        url = f"http://127.0.0.1:{port}/"
        html = None
        for _ in range(50):
            try:
                with urllib.request.urlopen(url, timeout=1) as resp:
                    assert resp.status == 200, f"status {resp.status}"
                    html = resp.read().decode("utf-8")
                break
            except Exception:
                time.sleep(0.1)
        assert html is not None, "server did not respond"
        # dashboard markers
        assert "<html" in html.lower()
        assert "ATAR" in html
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=5)
        except Exception:
            proc.kill()
