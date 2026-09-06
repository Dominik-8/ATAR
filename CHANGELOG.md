# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0a1] - 2026-09-06

### Added
- Ed25519 `did:agent:` identity (self-sovereign, offline-verifiable)
- Signed vouch blobs with canonical JSON serialization
- ATC Carrier (vouch tokens + agent cards)
- Transitive trust graph (web-of-trust)
- Revocation (signed, local/P2P)
- Freshness / TTL (passive decay)
- Key rotation (recovery without total loss)
- Decentralized sync (gossip)
- Multi-scope dashboard (CLI + live server)
- Reproducible network bootstrap (TOML)
- Portable export/import (.atpkg)
- Health monitoring (audit + watch)
- Signed capability claims (issue/verify-claim)
- 122 tests, CI green
- RFC Draft (draft-dbrueck-atar-00)
- PyPI release (`pip install atar-trust`)

[1.0.0a1]: https://github.com/Dominik-8/ATAR/releases/tag/v1.0.0a1
