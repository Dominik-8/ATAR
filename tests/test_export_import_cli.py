import os
import json

from click.testing import CliRunner

from atar.cli import cli
from atar.store import VouchStore


def _seed(home, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", home)
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "seed_agent"])
    runner.invoke(cli, ["keygen", "--name", "bob"])
    keys = json.load(open(os.path.join(home, "keys.json")))
    bob = keys["bob"]["did"]
    runner.invoke(cli, ["vouch", "--from", "seed_agent", "--for", bob,
                        "--score", "0.9", "--scope", "intelligence",
                        "--out", os.path.join(home, "v.json")])
    runner.invoke(cli, ["add", os.path.join(home, "v.json")])


def test_export_writes_portable_file(tmp_path, monkeypatch):
    _seed(str(tmp_path), monkeypatch)
    out = tmp_path / "net.atpkg"
    r = CliRunner().invoke(cli, ["export", "--out", str(out)])
    assert r.exit_code == 0
    bundle = json.loads(out.read_text())
    assert "vouches" in bundle and "revocations" in bundle
    assert len(bundle["vouches"]) >= 1
    # private keys must NOT be in the default export
    assert "keys" not in bundle


def test_import_restores_network(tmp_path, monkeypatch):
    # source
    src = tmp_path / "src"
    src.mkdir()
    _seed(str(src), monkeypatch)
    pkg = tmp_path / "net.atpkg"
    CliRunner().invoke(cli, ["export", "--out", str(pkg)])
    # target (fresh home)
    dst = tmp_path / "dst"
    dst.mkdir()
    monkeypatch.setenv("ATAR_HOME", str(dst))
    r = CliRunner().invoke(cli, ["import", str(pkg)])
    assert r.exit_code == 0
    # the vouch count carried over
    store = VouchStore(os.path.join(str(dst), "vouches.json"))
    assert store.count() >= 1


def test_export_include_keys_bundles_identity(tmp_path, monkeypatch):
    _seed(str(tmp_path), monkeypatch)
    out = tmp_path / "net-keys.atpkg"
    r = CliRunner().invoke(cli, ["export", "--out", str(out), "--include-keys"])
    assert r.exit_code == 0
    bundle = json.loads(out.read_text())
    assert "keys" in bundle
    assert "seed_agent" in bundle["keys"]
