"""README quickstart walk: the exact first-run flow must end with a card and
dashboard that actually contain the vouch.

Regression: the quickstart used to jump from `atar verify` straight to
`atar card`/`atar dashboard` without `atar add`, so a new user's first run
showed "0 vouches" everywhere. The README now includes the `atar add` step
and `atar vouch` prints a hint that the blob is not in the store yet.
"""

from __future__ import annotations

import json
import re

from click.testing import CliRunner

from atar.cli import cli


def test_readme_quickstart_end_to_end(tmp_path, monkeypatch):
    monkeypatch.setenv("ATAR_HOME", str(tmp_path))
    runner = CliRunner()

    assert runner.invoke(cli, ["keygen", "--name", "alice"]).exit_code == 0
    r_bob = runner.invoke(cli, ["keygen", "--name", "bob"])
    assert r_bob.exit_code == 0
    bob_did = next(
        line for line in r_bob.output.splitlines() if line.startswith("did:key:")
    )

    vouch_file = tmp_path / "bob-vouch.json"
    r = runner.invoke(
        cli,
        [
            "vouch",
            "--from",
            "alice",
            "--for",
            bob_did,
            "--score",
            "0.95",
            "--scope",
            "coding",
            "--out",
            str(vouch_file),
        ],
    )
    assert r.exit_code == 0
    # the hint that closes the discoverability gap
    assert "NOT in your local store" in r.output
    assert "atar add" in r.output

    r = runner.invoke(cli, ["verify", str(vouch_file)])
    assert r.exit_code == 0 and "VALID" in r.output

    r = runner.invoke(cli, ["add", str(vouch_file)])
    assert r.exit_code == 0

    card_file = tmp_path / "card.json"
    r = runner.invoke(cli, ["card", "--name", "bob", "--out", str(card_file)])
    assert r.exit_code == 0
    assert "1 vouch(es)" in r.output
    card = json.loads(card_file.read_text())
    r = runner.invoke(cli, ["verify-card", str(card_file)])
    assert r.exit_code == 0
    assert "valid vouches   : 1" in r.output
    assert card  # non-empty card

    dash_file = tmp_path / "dash.html"
    r = runner.invoke(
        cli,
        ["dashboard", "--seed", bob_did, "--scope", "coding", "--out", str(dash_file)],
    )
    assert r.exit_code == 0
    assert "1 vouches" in r.output
    html = dash_file.read_text()
    assert "did:key" in html


def test_readme_quickstart_lists_the_add_step():
    """The README quickstart must keep the `atar add` step between verify and
    card — without it the documented flow visibly produces empty output."""
    from pathlib import Path

    readme = Path(__file__).parent.parent / "README.md"
    quickstart = re.search(
        r"## Quickstart\n\n```bash\n(.*?)```", readme.read_text(), re.DOTALL
    )
    assert quickstart, "README quickstart block not found"
    body = quickstart.group(1)
    i_verify = body.index("atar verify")
    i_add = body.index("atar add")
    i_card = body.index("atar card")
    assert i_verify < i_add < i_card
