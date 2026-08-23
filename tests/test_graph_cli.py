from atar.identity import generate_identity, did_from_public
from atar.vouch import create_vouch
from atar.transparency import graph_from_vouches, TrustGraph
from atar.cli import cli
from click.testing import CliRunner


def _seed_graph():
    """Build a small demo trust network: root -> a -> b, root -> c."""
    root = generate_identity()
    a = generate_identity()
    b = generate_identity()
    c = generate_identity()
    vouches = [
        create_vouch(root, a.public_key, score=0.9, scope="intelligence"),
        create_vouch(a, b.public_key, score=0.8, scope="intelligence"),
        create_vouch(root, c.public_key, score=0.6, scope="intelligence"),
    ]
    return root, graph_from_vouches(vouches), [root, a, b, c]


def test_graph_cli_renders_trust_report(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    # create identities so DIDs are known locally
    root, g, agents = _seed_graph()
    root_did = did_from_public(root.public_key)
    # write vouches into ATAR_HOME so `graph` can load them
    import json, shutil
    from atar.transparency import canonical_vouch_id
    for v in g.all_vouches():
        safe_id = canonical_vouch_id(v).replace(":", "_")
        fn = tmp_path / f"vouch-{safe_id}.json"
        with open(fn, "w", encoding="utf-8") as f:
            json.dump(v, f)
    r = runner.invoke(cli, ["graph", "--seed", root_did, "--scope", "intelligence"])
    assert r.exit_code == 0
    assert root_did in r.output
    # transitive trust must surface the 2-hop agent
    assert did_from_public(agents[2].public_key) in r.output  # b (via a)
    assert "0.72" in r.output  # 0.9 * 0.8
