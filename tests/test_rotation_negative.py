"""Key rotation negative test: after `atar rotate`, the agent holds a NEW key.
The old key's vouches must be neutralized — otherwise rotation is pointless
(a leaked key could keep vouching). ATAR does this via `reissue --commit`,
which revokes the pre-rotation vouches. We test BOTH paths:

  1. rotate WITHOUT reissue -> pre-rotation vouches still verify (expected:
     the agent should reissue+commit; until then old vouches remain valid,
     which is the documented window).
  2. rotate + reissue --commit -> pre-rotation vouches become REVOKED.
"""

import json
import os

from click.testing import CliRunner

from atar.cli import cli


def _did(home, name):
    with open(os.path.join(home, "keys.json")) as _f:
        keys = json.load(_f)
    return keys[name]["did"]


def test_rotate_then_reissue_commit_revokes_old_vouch(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    runner.invoke(cli, ["keygen", "--name", "bob"])

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with open(os.path.join(tmp_path, "keys.json")) as _f:
        keys = json.load(_f)
    alice = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(keys["alice"]["private"])
    )
    bob = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["bob"]["private"]))

    from atar.identity import Identity
    from atar.vouch import create_vouch

    blob = create_vouch(
        Identity(private_key=alice, public_key=alice.public_key()),
        bob.public_key(),
        score=0.9,
        scope="core",
    )
    vpath = tmp_path / "v.json"
    vpath.write_text(json.dumps(blob, indent=2))
    runner.invoke(cli, ["add", str(vpath)])

    # rotate alice's key
    r = runner.invoke(
        cli, ["rotate", "--name", "alice", "--out", str(tmp_path / "rot.json")]
    )
    assert r.exit_code == 0, r.output

    # reissue + commit (revokes pre-rotation vouches)
    r = runner.invoke(cli, ["reissue", "--name", "alice", "--commit"])
    assert r.exit_code == 0, r.output

    # the pre-rotation vouch must now be REVOKED
    rv = runner.invoke(cli, ["verify", str(vpath)])
    assert rv.exit_code == 2, rv.output  # REVOKED = exit 2
    assert "REVOKED" in rv.output


def test_rotate_without_reissue_leaves_old_vouch_valid(tmp_path, monkeypatch):
    """Documented behavior: until you reissue+commit, pre-rotation vouches
    remain VALID (rotation alone does not retroactively kill old vouches —
    that's what reissue --commit is for). This test pins that contract so a
    future change can't silently break it."""
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()
    runner.invoke(cli, ["keygen", "--name", "alice"])
    runner.invoke(cli, ["keygen", "--name", "bob"])

    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

    with open(os.path.join(tmp_path, "keys.json")) as _f:
        keys = json.load(_f)
    alice = Ed25519PrivateKey.from_private_bytes(
        bytes.fromhex(keys["alice"]["private"])
    )
    bob = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(keys["bob"]["private"]))

    from atar.identity import Identity
    from atar.vouch import create_vouch

    blob = create_vouch(
        Identity(private_key=alice, public_key=alice.public_key()),
        bob.public_key(),
        score=0.9,
        scope="core",
    )
    vpath = tmp_path / "v.json"
    vpath.write_text(json.dumps(blob, indent=2))
    runner.invoke(cli, ["add", str(vpath)])

    # rotate only, no reissue
    r = runner.invoke(
        cli, ["rotate", "--name", "alice", "--out", str(tmp_path / "rot.json")]
    )
    assert r.exit_code == 0, r.output

    # old vouch is still VALID (rotation alone doesn't revoke it)
    rv = runner.invoke(cli, ["verify", str(vpath)])
    assert rv.exit_code == 0, rv.output
    assert "VALID" in rv.output
