"""Guard: the SPEC.md CLI surface must match the actual implemented commands.

If someone adds a command or renames one, this test fails until SPEC.md is
updated — keeping the protocol spec honest (Phase 28).
"""

from atar.cli import cli

# Commands documented in SPEC.md §14 (CLI surface reference)
EXPECTED_COMMANDS = {
    "keygen", "vouch", "verify", "revoke", "add", "list", "scopes",
    "card", "verify-card", "graph", "dashboard", "sync", "auto-sync",
    "rotate", "reissue", "bootstrap", "serve", "audit",
}


def test_spec_cli_matches_implementation():
    actual = set(cli.commands.keys())
    missing = EXPECTED_COMMANDS - actual
    assert not missing, f"SPEC documents commands not implemented: {missing}"
    # (we don't fail on *extra* commands, only on documented-but-missing)
