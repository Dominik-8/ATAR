# DRAFT - W3C community group intro post (for review, NOT submitted)

> Target: the W3C **Agent Identity Registry Protocol Community Group**
> (https://www.w3.org/community/agent-identity/, launched 2026-04-24;
> verified active 2026-09-09). Purpose: introduce ATAR and offer its
> lifecycle work as a contribution. Tone: collaborator, not competitor.
> Length: one screen.

---

**Title: ATAR - an open-source agent trust graph with a full lifecycle, built on did:key + W3C VCs**

Hi all - I'm Dominik, and I've been building ATAR (Agent Trust &
Attribution Root), an open-source trust layer for autonomous agents:
https://github.com/Dominik-8/ATAR

Rather than proposing yet another identity format, ATAR rides on the
standards this community is converging on: identity is plain `did:key`
(Ed25519), attestations ("vouches") export as W3C Verifiable Credentials
2.0 with `eddsa-jcs-2022` Data Integrity proofs, and agent presentation
is an A2A-compatible signed Agent Card carrying ATAR data as a declared
extension.

What I'd like to contribute to the group's work is the part ATAR has
focused on from day one - the **trust lifecycle**, which maps directly
onto the "revocation and credential lifecycle management" item in this
group's scope:

1. **Active revocation without a CA.** Issuer-signed, content-addressed
   revocation entries, verified at every intake path and propagated
   peer-to-peer - CRL/OCSP semantics with no central authority.
2. **Passive decay (TTL/freshness).** Attestations expire; issuers
   re-sign to keep them alive. Honest semantics: TTL bounds how long a
   *silent* issuer's vouches work - it is a freshness signal, not
   re-earned trust.
3. **Key rotation without total loss.** A rotation statement signed by
   the old key, re-issuance under the new key, retirement revocations by
   the old key - the trust graph survives a key compromise.
4. **Negative signals.** Signed third-party disputes against foreign
   attestations, advisory by design, weighted by the disputer's own
   standing in the graph so Sybil smears move nothing.

Everything above is implemented, specified, and tested (288 tests, CI
green) in the repo, with a threat model that states plainly what the
protocol does NOT solve (Sybil resistance stays out of scope).

I'm not asking the group to adopt a protocol. I'd like to learn where
the lifecycle problem is being discussed, align ATAR's wire formats with
whatever emerges, and offer the running code + spec as input. I have a
full Internet-Draft prepared on exactly these lifecycle mechanics
(draft-dbrueck-atar-lifecycle-00, aimed at the IETF independent stream)
and would welcome pointers on fit and venue - here or in the IETF-side
discussions this group coordinates with.

Happy to join a call or continue here - whatever suits the group.

- Dominik Brück, ATAR (https://github.com/Dominik-8/ATAR)

---

## Reviewer notes (not part of the post)

- Venue confirmed 2026-09-09: "Agent Identity Registry Protocol
  Community Group", https://www.w3.org/community/agent-identity/,
  launched 2026-04-24. Its published scope explicitly includes
  "Revocation and credential lifecycle management" (the hook used above)
  plus a DID method, a VC-based agent credential format, and trust
  negotiation - all adjacent to ATAR's realignment.
- The group coordinates with the W3C Credentials CG, DIF, the OpenID
  Foundation AIIM CG, and the IETF WIMSE WG. The last paragraph's
  "IETF-side discussions" phrase deliberately leaves this open; do not
  name WIMSE in the post unless Dominik wants that specificity.
- Numbers current as of 2026-09-09 (288 tests after the 1.0.0a2
  release); re-check before sending.
- The referenced IETF draft exists in reviewable form at
  docs/standardization/draft-dbrueck-atar-lifecycle-00.md (+ rendered
  .txt/.html). It is NOT submitted yet; the post says "prepared", which
  stays accurate.
- Keep the "collaborator, not competitor" framing - the
  honest-positioning rule from realignment A2 applies here too.
