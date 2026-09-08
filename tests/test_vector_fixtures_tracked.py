"""Guard: no test vector may be git-ignored.

Generated-artifact patterns in .gitignore (vouch*.json, agent-card.json,
rotation.json, ...) twice swallowed same-named fixtures under
tests/vectors/ — the suite passed locally and failed on CI with
FileNotFoundError. The patterns are now root-scoped; this test fails
locally at add-time if any vector ever matches an ignore rule again.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

VECTORS = Path(__file__).parent / "vectors"


def test_no_vector_fixture_is_gitignored():
    fixtures = sorted(VECTORS.glob("*.json"))
    assert fixtures, "vector directory must not be empty"
    proc = subprocess.run(
        ["git", "check-ignore", "--no-index", "--stdin"],
        input="\n".join(str(f) for f in fixtures),
        capture_output=True, text=True, cwd=VECTORS.parent.parent,
    )
    # exit 1 means "nothing is ignored" - the only acceptable outcome.
    # --no-index: check ignore rules even for already-tracked files, so
    # staging a fixture with git add -f cannot mask the problem.
    assert proc.returncode == 1, (
        f"git-ignored test vectors: {proc.stdout.strip()}"
    )
