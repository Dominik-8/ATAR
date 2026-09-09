# Contributing to ATAR

Thanks for your interest in ATAR. This document explains how to contribute.

## Development setup

```bash
git clone https://github.com/Dominik-8/ATAR.git
cd ATAR
python -m venv .venv && source .venv/bin/activate   # or: uv venv
pip install -e ".[dev]"
pytest
```

## Running tests

```bash
pytest            # full suite
pytest tests/test_identity.py::test_x   # single test
```

All code must be covered by tests. We follow TDD: write the failing test
first, watch it fail, then implement.

## Continuous integration

Every push runs the pinned `ruff format` / `ruff check` gate and the full
test suite on Python 3.11 and 3.12, then builds the sdist and wheel,
installs both into clean environments, and smoke-tests the installed CLI
(keygen -> vouch -> verify). A change that breaks the packaged
distribution fails CI before it can reach a release.

## Branch & PR workflow

1. Fork and create a feature branch (`feat/...`, `fix/...`).
2. Keep commits focused and message them in imperative mood
   (`feat: add transitive trust depth cap`, `fix: reject malformed vouch`).
3. Ensure `pytest` is green before opening a PR.
4. Open a PR against `master` with a clear description of the change and its
   motivation.

## Code style

- Format with `ruff format` and lint with `ruff check` — both run in CI
  (ruff is pinned in the `dev` extra; rule set lives in `pyproject.toml`).
  `ruff check` must pass without new `noqa` exceptions.
- Type hints required on public functions.
- No new dependencies without discussion — ATAR deliberately stays minimal
  (cryptography, base58, click).

## Design principles

ATAR is the *trust layer* for agents. Keep it:
- **Serverless** — no central operator, no ledger.
- **Free** — no blockchain, no gas, no accounts.
- **Verifiable offline** — every claim must check without a network round-trip.

## Reporting security issues

See [SECURITY.md](SECURITY.md). Do **not** open public issues for
vulnerabilities.
