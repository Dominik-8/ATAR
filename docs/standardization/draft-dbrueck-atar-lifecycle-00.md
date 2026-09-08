# DRAFT — IETF Internet-Draft skeleton (for review, NOT submitted)

> Working title: `draft-dbrueck-atar-lifecycle-00`
> Positioning: the **lifecycle** of agent trust attestations (revocation,
> TTL/freshness, rotation, disputes) as ATAR's contribution — the pieces the
> current landscape (ERC-8004, A2A, VC 2.0) leaves unspecified.
> Format note: skeleton in Markdown for review; convert to xml2rfc/kramdown
> before any datatracker submission. Supersedes the pre-realignment
> `legacy/draft-dbrueck-atar-00.txt` (which still documents the legacy `did:agent:`
> spelling).

---

```
Network Working Group                                   D. Brueck
Internet-Draft                                         Independent
Intended status: Experimental                       September 2026
Expires: March 2027


        Lifecycle Mechanics for Agent Trust Attestations
                   draft-dbrueck-atar-lifecycle-00

Abstract

   Agent identity and attestation formats are converging on standards
   (DID Core, did:key, W3C Verifiable Credentials 2.0, A2A Agent Cards).
   What remains unstandardized is the lifecycle: how an attestation of
   agent trustworthiness is revoked, how it decays, how it survives key
   compromise, and how third parties file negative signals — all without
   a central authority.  This document specifies those four mechanisms
   as implemented and tested in the open-source ATAR protocol, as input
   to standardization of the agent-trust lifecycle.
```

## Table of Contents (skeleton)

1. **Introduction** — scope: lifecycle only; identity/attestation/presentation
   formats are referenced (did:key, VC 2.0, A2A), not redefined. Relationship
   to ATAR (the open-source implementation and testbed).
2. **Conventions and Terminology** — attestation ("vouch"), issuer, subject,
   scope, content addressing (hash of canonical claim bytes), peer gossip.
3. **Revocation (active kill)**
   3.1 Revocation entry wire format (issuer-signed, content-addressed).
   3.2 Intake rules: signature verified at every path; issuer binding.
   3.3 Propagation: peer-to-peer merge, no CA/ledger.
4. **Freshness / TTL (passive decay)**
   4.1 Semantics: expiry forces issuer re-signing; honest reading (freshness
       signal, not re-earned trust).
   4.2 Verifier-side max-age; recommended default (180 days).
5. **Key Rotation (recovery)**
   5.1 Rotation statement signed by the old key.
   5.2 Re-issuance under the new key + retirement revocations by the old key.
6. **Disputes (negative signals)**
   6.1 Dispute entry wire format (signed by a non-issuer).
   6.2 Advisory semantics: never invalidates; verifiers surface.
   6.3 Weighting: only disputes from trusted identities discount trust
       (threshold 0.5 in the reference implementation); Sybil resistance
       rationale.
7. **Gossip Transport** — filesystem exchange; slim HTTP peer endpoint
   (GET/POST of attestations, revocations, disputes); content-addressed
   dedup; no central server.
8. **Score Semantics** — dimensionless issuer confidence, calibration
   anchors, evidence references.
9. **Security Considerations** — the honest threat model, incl. what stays
   out of scope (Sybil).
10. **IANA Considerations** — none.

## Open questions for review

- Venue fit: is an Independent Stream Experimental draft the right track, or
  does this belong in a WG-adjacent effort first?
- Should §6.3's threshold be normative or implementation-defined?
- Wire format: keep ATAR's canonical-JSON signing, or normatively require
  JCS (RFC 8785) everywhere to match the VC proof path?

## References (normative/informative placeholders)

- DID Core 1.1; did:key method; W3C Verifiable Credentials 2.0;
  RFC 8032 (Ed25519); RFC 8785 (JCS); A2A Agent Card specification;
  ERC-8004 (informative, contrasting approach).
- ATAR SPEC.md (the implemented reference) — https://github.com/Dominik-8/ATAR
