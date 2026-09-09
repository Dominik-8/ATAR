"""Guard: every `atar <cmd>` documented in README must actually exist as a
CLI command. Catches documentation drift (a renamed/removed command that
stays in the README — the exact "unprofessional" gap the project owner
wanted to avoid). Click auto-converts underscores to kebab-case
(auto_sync -> auto-sync), so we normalize both sides before comparing.
"""

import os
import re
from pathlib import Path

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _normalize(name: str) -> str:
    return name.replace("_", "-")


def test_readme_commands_exist_in_cli():
    from atar.cli import cli

    actual = {_normalize(c) for c in cli.commands}

    readme = Path(os.path.join(ROOT, "README.md")).read_text(encoding="utf-8")
    documented = {_normalize(c) for c in re.findall(r"`atar\s+([a-z][a-z-]+)", readme)}

    # every documented command must exist
    missing = documented - actual
    assert not missing, f"README documents commands not in CLI: {sorted(missing)}"


def test_cli_commands_documented_in_readme():
    from atar.cli import cli

    actual = {_normalize(c) for c in cli.commands}

    readme = Path(os.path.join(ROOT, "README.md")).read_text(encoding="utf-8")
    documented = {_normalize(c) for c in re.findall(r"`atar\s+([a-z][a-z-]+)", readme)}

    # every CLI command should be documented (no hidden/undocumented commands)
    undocumented = actual - documented
    # 'import-cmd' is registered as 'import' by Click; allow that alias
    undocumented = {c for c in undocumented if c != "import-cmd"}
    assert not undocumented, (
        f"CLI commands not documented in README: {sorted(undocumented)}"
    )
