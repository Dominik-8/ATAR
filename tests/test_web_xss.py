import os, threading, urllib.request

from atar.web import run_server
from atar.store import VouchStore
from atar.vouch import create_vouch
from atar.identity import Identity, generate_identity, did_from_public
from atar.agent_bootstrap import AgentRegistry


def test_web_server_escapes_xss(tmp_path, monkeypatch):
    """Regression: the live dashboard server escapes agent fields (no XSS)."""
    home = str(tmp_path)
    monkeypatch.setenv("ATAR_HOME", home)

    import json as _json

    os.makedirs(os.path.join(home, "agents"), exist_ok=True)

    # seed + subject identities (real keys)
    seed = generate_identity()
    subj = generate_identity()
    evil_name = "<script>alert('xss')</script>"
    keys = {
        evil_name: {
            "private": seed.private_key.private_bytes_raw().hex(),
            "did": did_from_public(seed.public_key),
        },
        "bob": {
            "private": subj.private_key.private_bytes_raw().hex(),
            "did": did_from_public(subj.public_key),
        },
    }
    _json.dump(keys, open(os.path.join(home, "keys.json"), "w"))
    # registry so web._build_net resolves names + seed
    reg = AgentRegistry()
    reg._agents[evil_name] = {
        "did": did_from_public(seed.public_key),
        "private": seed.private_key.private_bytes_raw().hex(),
    }
    reg._agents["bob"] = {
        "did": did_from_public(subj.public_key),
        "private": subj.private_key.private_bytes_raw().hex(),
    }
    reg._agents["_seed"] = did_from_public(seed.public_key)
    reg._save()

    # a vouch from the seed to the subject
    v = create_vouch(seed, subj.public_key, score=0.9, scope="intelligence")
    VouchStore(os.path.join(home, "vouches.json")).add(v)

    server = run_server(port=0, _block=False)
    port = server.server_address[1]
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/") as resp:
            html = resp.read().decode()
    finally:
        server.shutdown()
        server.server_close()

    # the raw script tag must be escaped, not executed
    assert "<script>alert('xss')</script>" not in html
    assert "&lt;script&gt;" in html
