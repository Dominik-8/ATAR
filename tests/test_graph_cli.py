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
    root, g, agents = _seed_graph()
    root_did = did_from_public(root.public_key)
    # add vouches into the persistent store so `graph` can load them
    import json
    for v in g.all_vouches():
        fn = tmp_path / "v.json"
        with open(fn, "w", encoding="utf-8") as f:
            json.dump(v, f)
        runner.invoke(cli, ["add", str(fn)])
    r = runner.invoke(cli, ["graph", "--seed", root_did, "--scope", "intelligence"])
    assert r.exit_code == 0
    assert root_did in r.output
    # transitive trust must surface the 2-hop agent
    assert did_from_public(agents[2].public_key) in r.output  # b (via a)
    assert "0.72" in r.output  # 0.9 * 0.8


def test_graph_resolves_known_agent_names(tmp_path, monkeypatch):
    """The ranking names agents the operator knows (registry + keygen),
    like the dashboard does — raw DIDs alone are unreadable."""
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    r1 = runner.invoke(cli, ["keygen", "--name", "root"])
    r2 = runner.invoke(cli, ["keygen", "--name", "leaf"])
    root_did, leaf_did = r1.output.strip(), r2.output.strip()
    vf = tmp_path / "v.json"
    runner.invoke(cli, ["vouch", "--from", "root", "--for", leaf_did,
                        "--score", "0.9", "--scope", "coding", "--out", str(vf)])
    runner.invoke(cli, ["add", str(vf)])
    r = runner.invoke(cli, ["graph", "--seed", root_did, "--scope", "coding"])
    assert r.exit_code == 0
    assert "root did:key:" in r.output and "leaf did:key:" in r.output
