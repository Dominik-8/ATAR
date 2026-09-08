# Security Policy

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x   | ✅        |

## Reporting a Vulnerability

ATAR is a security-critical protocol: its entire purpose is cryptographic
trust. If you discover a vulnerability (forgeable vouches, signature-bypass,
trust-graph manipulation), **do not open a public issue**.

Instead, report it privately:

- Open a
  [GitHub Security Advisory](https://github.com/Dominik-8/ATAR/security/advisories/new)
  (private, only visible to the maintainer).

We will acknowledge within 72 hours and aim to ship a fix within 14 days for
any verified issue that breaks vouch authenticity or trust computation.

## Scope notes (honest)

ATAR makes no Sybil-proof guarantee. Free, serverless identity means anyone can
mint unlimited agents. Security claims are limited to:
- Vouch signatures are unforgeable without the private key (Ed25519).
- Tampered vouch payloads are rejected.
- Transitive trust only flows through *valid* vouches.

Reputation emerges from the graph; it is not a protocol-level guarantee.
