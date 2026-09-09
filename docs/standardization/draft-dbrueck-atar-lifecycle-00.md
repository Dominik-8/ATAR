---
title: Lifecycle Mechanics for Agent Trust Attestations
abbrev: Agent Trust Lifecycle
docname: draft-dbrueck-atar-lifecycle-00
category: exp
submissiontype: independent
ipr: trust200902
area: General
workgroup: Independent Submission
keyword:
  - agent
  - trust
  - attestation
  - revocation
  - verifiable credentials
  - did:key
author:
  -
    ins: D. Brück
    name: Dominik Brück
    organization: Independent
normative:
  RFC2119:
  RFC8174:
  RFC8032:
informative:
  DIDKEY:
    target: https://w3c-ccg.github.io/did-key-spec/
    title: The did:key Method v0.9
    author:
      org: W3C Credentials Community Group
    date: 2026
  RFC7942:
  RFC8785:
  DIDCORE:
    target: https://www.w3.org/TR/did-core/
    title: Decentralized Identifiers (DIDs) v1.0
    author:
      org: W3C
    date: 2022-07
    seriesinfo:
      W3C: Recommendation
  VCDM:
    target: https://www.w3.org/TR/vc-data-model-2.0/
    title: Verifiable Credentials Data Model v2.0
    author:
      org: W3C
    date: 2025-05
    seriesinfo:
      W3C: Recommendation
  VCDIEDDSA:
    target: https://www.w3.org/TR/vc-di-eddsa/
    title: Data Integrity EdDSA Cryptosuites v1.0
    author:
      org: W3C
    date: 2025-05
    seriesinfo:
      W3C: Recommendation
  A2A:
    target: https://a2a-protocol.org/v1.0.0/specification/
    title: Agent2Agent (A2A) Protocol Specification v1.0
    author:
      org: Linux Foundation
    date: 2026
  ERC8004:
    target: https://eips.ethereum.org/EIPS/eip-8004
    title: "ERC-8004: Trustless Agents"
    author:
      -
        ins: M. De Rossi
        name: Marco De Rossi
      -
        ins: D. Crapis
        name: Davide Crapis
      -
        ins: J. Ellis
        name: Jordan Ellis
      -
        ins: E. Reppel
        name: Erik Reppel
    date: 2025-08
    seriesinfo:
      Ethereum: Improvement Proposal (Draft)
  ATARSPEC:
    target: https://github.com/Dominik-8/ATAR/blob/master/SPEC.md
    title: "ATAR: Agent Trust and Attribution Root, Protocol Specification v2.0"
    author:
      ins: D. Brück
      name: Dominik Brück
    date: 2026-09

--- abstract

Agent identity and attestation formats are converging on existing
standards: Decentralized Identifiers, the did:key method, W3C Verifiable
Credentials, and A2A Agent Cards. What remains unstandardized is the
lifecycle of such attestations: how an attestation of agent
trustworthiness is revoked, how it decays over time, how it survives
compromise of the issuer's key, and how third parties file negative
signals against it, all without a central authority. This document
specifies four lifecycle mechanisms (active revocation, passive expiry,
key rotation, and third-party disputes) together with the content
addressing and gossip transport that carry them and the score semantics
that keep attestation values comparable. The mechanisms are specified as
implemented and tested in the open-source ATAR protocol and are offered
as input to standardization of the agent trust lifecycle. This document
defines no new identity, attestation, or presentation format.

--- middle

# Introduction {#sec-introduction}

Autonomous agents increasingly act across organizational boundaries:
they negotiate, delegate, purchase, and sign for their operators. Before
one agent relies on another, it needs a basis for trusting that agent
for a particular capability. The formats for expressing that basis are
converging: Decentralized Identifiers [DIDCORE] and the did:key
method [DIDKEY] provide serverless, purely
cryptographic identities; W3C Verifiable Credentials [VCDM] provide
standard attestation envelopes; and A2A Agent Cards [A2A] provide a
standard presentation format an agent can hand to a stranger on first
contact. Ledger-based approaches such as ERC-8004 [ERC8004] anchor
reputation signals on-chain instead.

What none of these formats standardizes is what happens after an
attestation is issued. Attestations live in time. Issuers change their
minds and need to take an attestation back. Issuers go silent, and their
old attestations should stop working rather than accumulate forever.
Keys leak, and an identity should be able to recover without losing its
standing. Third parties observe fraud and need a way to warn others.
Without shared semantics for these events, every agent trust system
answers them differently, and most leave them unspecified entirely.

This document specifies those four lifecycle mechanisms:

* Revocation ([](#sec-revocation)): an active, issuer-signed kill of an
  attestation, verified at every intake path and propagated
  peer-to-peer.
* Freshness / TTL ([](#sec-freshness)): passive decay that expires
  attestations unless the issuer periodically re-signs them.
* Key rotation ([](#sec-rotation)): continuity of identity across a key
  compromise, with re-issuance under the new key and retirement of the
  old one.
* Disputes ([](#sec-disputes)): signed negative signals by third
  parties, advisory by design and weighted by the disputer's own
  standing.

The mechanisms rest on three supporting pieces specified here as well:
content addressing ([](#sec-content-addressing)) for deduplication, a
gossip transport ([](#sec-gossip)) for propagation without any central
authority, and score semantics ([](#sec-scores)) that keep attestation
values comparable between issuers. A reference algorithm for transitive
trust computation is described informatively in
[](#sec-trust-computation).

## Relationship to ATAR

The mechanisms are specified as implemented and tested in ATAR (Agent
Trust and Attribution Root) [ATARSPEC], an open-source reference
implementation released under the MIT license. The wire formats in this
document are the running formats of that implementation; see
[](#sec-implementation-status). The intent of this document is input to
standardization, not a demand for adoption: where a choice is
implementation-defined rather than essential to interoperability, this
document says so.

## Scope

This document deliberately defines no new identity format (it uses
did:key), no new credential envelope (it references W3C Verifiable
Credentials informatively), no presentation format (it references A2A
Agent Cards informatively), and no ledger or central registry. Sybil
resistance is out of scope; [](#sec-security) explains why and what the
protocol does instead.

# Conventions and Terminology {#sec-terminology}

{::boilerplate bcp14-tagged}

The following terms are used throughout this document:

Agent
: An autonomous software entity that acts on behalf of an operator.

Identity
: The did:key identifier of an agent. The identifier is derived solely
  from an Ed25519 public key; possession of the corresponding private
  key is possession of the identity.

Attestation (vouch)
: A signed statement by an issuer agent endorsing a subject agent for a
  capability scope with a score. The terms "attestation" and "vouch" are
  used interchangeably; the wire format field values use "vouch".

Issuer
: The agent that creates and signs an attestation.

Subject
: The agent an attestation is about.

Scope
: A free-form capability area (for example "coding" or "research").
  Trust is always scoped: an agent is trusted for a capability, not
  universally.

Score
: A dimensionless confidence value in the interval `[0.0, 1.0]`; see
  [](#sec-scores).

Evidence
: Optional references (URIs or free-form pointers) to the observations
  behind a score, signed as part of the attestation.

Content address
: A deterministic identifier computed from the canonical bytes of an
  object; see [](#sec-content-addressing).

Revocation entry
: A signed statement by an issuer withdrawing one of its attestations.

Dispute entry
: A signed statement by a non-issuer warning against an attestation of
  another issuer.

Rotation statement
: A statement signed by an old key binding it to its successor key.

Trust graph
: The directed graph whose nodes are identities and whose edges are
  valid attestations.

Seed
: The identity from which a verifier starts trust computation, usually
  the verifier's own identity or a trusted root.

Peer
: Another operator's store with which attestations, revocations, and
  disputes are exchanged.

Gossip
: Peer-to-peer exchange of content-addressed objects without any central
  coordinator.

# Attestation Model {#sec-model}

The lifecycle mechanisms of this document operate on attestations of the
following shape. This section specifies only what the lifecycle
mechanisms depend on; [ATARSPEC] is the authoritative full
specification.

## Identity {#sec-identity}

An agent identity is an Ed25519 keypair as specified in {{RFC8032}}. The
identifier is a did:key DID [DIDKEY] derived solely from the public key:

~~~
did:key:z<base58btc( 0xED 0x01 || public_key_raw_bytes )>
~~~

where 0xED 0x01 is the unsigned varint multicodec prefix for
"ed25519-pub", "z" is the multibase prefix for base58btc (Bitcoin
alphabet, no padding), and public_key_raw_bytes is the 32-byte Ed25519
public key. There is no registration, no resolution step, and no server:
any verifier reconstructs the public key from the identifier and checks
signatures offline.

## Vouch {#sec-vouch}

A vouch binds an issuer, a subject, a scope, and a score:

~~~ json
{
  "payload": {
    "type": "vouch",
    "issuer": "did:key:...",
    "subject": "did:key:...",
    "score": 0.95,
    "scope": "coding",
    "claim": null,
    "ts": 1690000000
  },
  "signature": "<hex(ed25519(canonical_payload_bytes))>"
}
~~~

The payload fields are:

type
: The string "vouch".

issuer
: The did:key of the issuer. It MUST identify the key that produced
  "signature".

subject
: The did:key of the subject.

score
: A floating point value in `[0.0, 1.0]`; semantics in [](#sec-scores).

scope
: A free-form string naming a capability area.

claim
: Optional free text, used only for self-vouches (issuer equal to
  subject); null otherwise.

evidence
: Optional list of references (URIs or free-form pointers) to the
  observations behind the score ([](#sec-scores)). When present it is
  part of the signed payload and of the content address.

ts
: Creation time as a Unix epoch timestamp in seconds. It is the input
  to freshness evaluation ([](#sec-freshness)) and is excluded from the
  content address ([](#sec-content-addressing)).

The signature is the lowercase hexadecimal encoding of the Ed25519
signature over the canonical serialization of the payload
([](#sec-canonicalization)).

## Canonical serialization {#sec-canonicalization}

For signing and verifying, the payload is serialized deterministically
as a JSON object with keys sorted lexicographically and no insignificant
whitespace, equivalent to:

~~~ python
json.dumps(payload, sort_keys=True, separators=(",", ":"))
~~~

The result is UTF-8 encoded. This guarantees byte-identical input for
signer and verifier. Note that this canonical form is deliberately
minimal (sorted keys, compact separators); it is not JSON
Canonicalization Scheme {{RFC8785}}. JCS appears in this protocol family
only in the Verifiable Credentials bridge ([](#sec-vc-bridge)).
Implementations of this document MUST NOT substitute JCS (or any other
canonicalization) for the native form: the signed bytes and the content
addresses would change. See [](#sec-open-issues) for the trade-off.

## Content addressing {#sec-content-addressing}

Every vouch has a deterministic content address:

~~~
vouch_id = "vouch:" + hex( sha256( canon(payload - "ts") ) )
~~~

The "ts" field is excluded from the hash: a vouch is identified by its
claim (issuer, subject, scope, score, claim, evidence), not by when it
was signed. Two vouches making the same claim at different times
collapse to one content address, so re-issues and repeated exchanges
deduplicate instead of duplicating the graph. Content addressing lets
peers gossip and deduplicate without an operator or a registry.

## Verification {#sec-verification}

A verifier checks a vouch as follows:

1. Parse "payload" and "signature".
2. Assert "issuer" is a decodable did:key identifier.
3. Reconstruct the issuer public key from the identifier.
4. Compute the canonical bytes of "payload"
   ([](#sec-canonicalization)).
5. Verify the signature against those bytes with {{RFC8032}}.
6. If any step fails, the vouch is INVALID.

A vouch is trust-valid only if, additionally, it is not on the local
revocation list ([](#sec-revocation)) and not expired under the active
maximum age ([](#sec-freshness)).

## Interop bridge: W3C Verifiable Credentials (informative) {#sec-vc-bridge}

For interop with standard credential tooling, any vouch can be exported
as a W3C Verifiable Credential [VCDM] with a Data Integrity proof using
the "eddsa-jcs-2022" cryptosuite [VCDIEDDSA] (JCS {{RFC8785}}
canonicalization, SHA-256, Ed25519). The mapping is direct: issuer to
"issuer", subject to "credentialSubject.id", scope and score to namespaced
claims, "ts" to "validFrom". Export re-signs: the VC proof is a fresh
signature by the issuer over the VC, so exporting requires the issuer's
key, and there is no lossless conversion from an externally produced VC
back into a native vouch. Revocation ([](#sec-revocation)) and expiry
([](#sec-freshness)) deliberately stay on the native side: the VC proves
the signed attestation, while current trust state comes from the native
store. This bridge is informative for this document; the lifecycle
semantics are identical whether a consumer reads the native form or the
exported VC.

# Revocation (Active Kill) {#sec-revocation}

A vouch may be revoked by its issuer. Revocation is modeled on CRL and
OCSP semantics but is local and peer-propagated: there is no certificate
authority, no responder, and no ledger.

## Revocation entry {#sec-revocation-format}

~~~ json
{
  "vid": "<canonical vouch id>",
  "revoked_by": "did:key:...",
  "ts": 1690000000,
  "signature": "<base64(ed25519 over \"vid|revoked_by|ts\")>"
}
~~~

* "vid" is the content address of the revoked vouch
  ([](#sec-content-addressing)).
* "revoked_by" is the identifier of the revoking party. A revocation
  only applies to a vouch when "revoked_by" equals the vouch's "issuer";
  see [](#sec-revocation-evaluation).
* "ts" is the revocation time as a Unix epoch timestamp in seconds.
* The signature input is the UTF-8 encoding of the concatenation of
  "vid", the vertical bar character, "revoked_by", the vertical bar
  character, and the decimal ASCII representation of "ts". The signature
  is Ed25519 over that input, base64-encoded.

## Intake rules {#sec-revocation-intake}

The signature of every revocation entry MUST be verified against the
public key of "revoked_by" at every intake path: gossip exchange
([](#sec-gossip)), import, store load, and the HTTP peer profile
([](#sec-http-peer)). An entry whose signature does not verify MUST be
dropped, exactly like a forged vouch. Because the identifier embeds the
raw Ed25519 key ([](#sec-identity)), any peer can verify any entry
standalone.

Revocation entries are deduplicated by "vid": there is at most one
effective revocation per vouch, and repeated delivery of the same
revocation is harmless.

## Evaluation semantics {#sec-revocation-evaluation}

A revocation applies to a vouch only when "revoked_by" equals the
vouch's "issuer". A well-formed entry signed by anyone else is inert: it
may sit in a list, but it revokes nothing. Where the vouch is known,
non-issuer entries SHOULD be rejected at intake; wherever they came
from, they never apply at evaluation.

A revoked vouch is treated as REVOKED even when its original signature
is still cryptographically valid. Revocation state participates in every
trust decision ([](#sec-verification)): revoked vouches are excluded
from trust computation ([](#sec-trust-computation)), and vouches revoked
by their issuer are never admitted to a store, whatever transport they
arrive on (defense in depth).

Revocation lists are gossip-synchronized like vouches
([](#sec-gossip)), so a revocation made by one peer reaches all peers
that sync with it. As with all gossip state, a revocation is visible to
a verifier only as of the verifier's last synchronization; see
[](#sec-security).

# Freshness / TTL (Passive Decay) {#sec-freshness}

Revocation kills trust actively. Freshness lets stale trust decay: a
vouch older than the active maximum age is EXPIRED and rejected. This
forces periodic re-vouching, so the graph stays alive instead of
accumulating zombie trust.

~~~
is_fresh(vouch, ttl) := (now - vouch.payload.ts) <= ttl
~~~

The default recommendation is a time-to-live of 180 days. A verifier MAY
set a stricter maximum age. Absence of a maximum age means trust never
expires except by revocation.

Expiry is enforced at evaluation time (verification, trust computation,
audit), never at insertion time: expiry is relative to the current time,
so a vouch admitted today may expire tomorrow and insertion-time
rejection cannot work.

Honest semantics: TTL forces the issuer to re-sign, which is a freshness
signal ("the issuer still stands behind this"), not the subject
re-earning trust. An issuer can re-sign mechanically. TTL bounds how
long a silent issuer's vouches keep working; it does not by itself
create new evidence of trustworthiness. Re-signing refreshes the
freshness of the claim, not its evidence ([](#sec-scores)).

A future-dated "ts" is treated as fresh: an issuer can postpone its own
vouch's expiry and gains nothing by doing so visibly. Verifiers MAY
reject timestamps beyond local clock skew.

# Key Rotation (Recovery without Total Loss) {#sec-rotation}

When a key leaks, an agent rotates instead of starting from zero.

## Rotation statement {#sec-rotation-statement}

~~~ json
{
  "type": "rotation",
  "old_did": "did:key:...",
  "new_did": "did:key:...",
  "ts": 1690000000,
  "signature": "<hex(ed25519 over canonical rotation payload)>"
}
~~~

The old key signs the statement "I am now new_did": the signature input
is the canonical serialization ([](#sec-canonicalization)) of the
payload fields ("type", "old_did", "new_did", "ts"), and the signature
MUST verify against the public key embedded in "old_did". Verifiers
confirm continuity by checking exactly that binding.

## Re-issuance and retirement {#sec-rotation-reissue}

After rotation, the agent re-signs its outgoing vouches under the new
key, preserving "score", "scope", and "subject" and stamping a fresh
"ts". On commit, the re-issued vouches are written to the store and the
old-key vouches are revoked: the retirement revocations are signed with
the old key, because [](#sec-revocation) requires "revoked_by" to be the
vouch's issuer and only the old key can sign for the old identifier.
The old private key is retained locally for exactly this purpose and is
deleted after the commit completes.

The effect is that the trust the agent extends to others carries
forward, and the old key is fully retired: the trust graph survives a
key compromise. Vouches issued by others to the old identifier remain
bound to the old identifier; the rotation statement is what lets
verifiers bind the old and new identities together.

# Disputes (Negative Signals) {#sec-disputes}

Revocation belongs to the issuer. Everyone else gets the dispute: a
signed warning against a foreign vouch, gossiped like any other object.

## Dispute entry {#sec-dispute-format}

~~~ json
{
  "vid": "<canonical vouch id>",
  "disputed_by": "did:key:...",
  "reason": "<free text>",
  "ts": 1690000000,
  "signature": "<base64(ed25519 over \"vid|disputed_by|reason|ts\")>"
}
~~~

The signature input is the UTF-8 encoding of the concatenation of "vid",
"disputed_by", "reason", and "ts", separated by vertical bar characters,
with "ts" in decimal ASCII. Disputes are content-addressed by the triple
("vid", "disputed_by", "reason") and deduplicated on that key.

## Intake rules {#sec-dispute-intake}

Signatures are verified at every intake path, exactly as for revocations
([](#sec-revocation-intake)); a forged dispute never enters a list.
"disputed_by" MUST NOT be the vouch's issuer: the issuer's negative
signal is revocation ([](#sec-revocation)). Where the vouch is known,
issuer-signed disputes are rejected at intake.

## Advisory semantics and weighting {#sec-dispute-semantics}

A dispute never invalidates a vouch. Verification of a disputed vouch
still reports VALID, with the disputes on record noted; listings surface
them. Disputes influence trust only through weighting in trust
computation:

1. Pass 1 computes transitive trust ([](#sec-trust-computation))
   ignoring disputes.
2. Pass 2 excludes any vouch carrying a valid dispute from a disputer
   whose pass-1 trust is at least the dispute threshold.

The dispute threshold is implementation-defined; the reference
implementation uses 0.5 and this document RECOMMENDS 0.5. The rationale
is Sybil resistance: a warning counts only from inside the trusted
graph, so an attacker minting fresh identities to file disputes cannot
move anyone's score. See [](#sec-security) and
[](#sec-open-issues).

# Gossip Transport {#sec-gossip}

Peers exchange vouches, revocations, and disputes between their local
stores. There is no server and no coordinator: every peer is equal.

## Exchange model {#sec-gossip-model}

Peers exchange full sets and deduplicate by content address, so
synchronization is idempotent and order-independent. Vouches are added
if valid and new; vouches revoked by their issuer are never admitted.
Revocation entries are merged after signature verification and issuer
binding ([](#sec-revocation)). Disputes merge likewise
([](#sec-disputes)). All trust decisions stay in the store; the
transport is deliberately dumb. Because objects are self-authenticating,
the integrity of the exchange does not depend on channel security; the
cost of a best-effort transport is that state is current only as of the
last synchronization ([](#sec-security)).

## Filesystem exchange {#sec-gossip-fs}

The base transport is a one-shot exchange between two local store
directories, plus a scheduled mode that reads a peer list
("atar_peers.json") so cron jobs or agent hooks can synchronize
periodically. Filesystem exchange requires a shared disk; exchanges
between separate operators use the HTTP peer profile.

## HTTP peer profile {#sec-http-peer}

Any peer can expose its local store over a slim HTTP endpoint, still
content-addressed and still serverless in the trust sense (there is no
central coordinator or registry). The endpoint speaks JSON only:

| Route | Semantics |
|---|---|
| GET / | peer info: `{"protocol": "atar-peer/1.0", "vouches": n, "revocations": m, "disputes": k}` |
| GET /vouches | the peer's full vouch set |
| POST /vouches | one vouch blob or `{"vouches": [...]}` -> `{"added", "duplicates", "rejected"}` |
| GET /revocations | the peer's full revocation list |
| POST /revocations | one entry or `{"revocations": [...]}` -> `{"added", "duplicates", "rejected"}` |
| GET /disputes | the peer's full dispute list |
| POST /disputes | one entry or `{"disputes": [...]}` -> `{"added", "duplicates", "rejected"}` |

Malformed remote entries are skipped, never fatal: a peer (or anything
answering on that port) cannot crash a synchronization with junk data.
Intake rules are identical to filesystem exchange: vouch signatures are
verified, issuer-revoked vouches are never admitted, revocation entries
are signature-verified and issuer-bound when the vouch is known, and
disputes are signature-verified. The endpoint binds to the loopback
address by default; exposing it to a network is the operator's explicit
choice.

# Score Semantics {#sec-scores}

A score is a dimensionless confidence in the interval `[0.0, 1.0]`: the
issuer's subjective probability that the subject will perform reliably
in the scope, as observed by the issuer. It is not a measurement with
physical units and never aggregates across scopes: scores compare only
within a scope and are only as meaningful as the issuer behind them,
which is why trust is computed transitively
([](#sec-trust-computation)): an unknown issuer's 0.99 contributes
nothing.

Calibration anchors are recommended, not enforced:

| Score | Meaning |
|---|---|
| 1.0 | The issuer stakes its own reputation without reservation (for example its own subagent, or a long flawless track record). |
| 0.8 | Repeatedly observed good performance; the reference default for a single successfully observed task. |
| 0.5 | Neutral: no negative evidence, no strong positive evidence. |
| 0.2 | Weak or indirect evidence only. |
| 0.0 | No confidence; do not vouch at all (a 0-scored vouch adds no trust). |

Scores SHOULD carry their basis in the "evidence" list: URIs or pointers
to the tasks, reviews, logs, or documents the score rests on. Evidence
lets a verifier re-check the basis instead of trusting the number
blindly, and makes scores comparable across operators. Evidence is
signed with the vouch and joins its content address
([](#sec-content-addressing)): it cannot be edited after the fact.

TTL interaction: re-signing refreshes the freshness of the claim, not
its evidence ([](#sec-freshness)). Honest re-vouching after new
observations SHOULD reference the new evidence; mechanical re-signing
keeps the old evidence and only resets the clock.

# Transitive Trust Computation (informative) {#sec-trust-computation}

The lifecycle mechanisms above define which attestations are valid at a
point in time. How a verifier aggregates them into a trust value is a
consumer choice; this section describes the reference algorithm for
completeness.

Given a seed identifier and a scope:

* The seed starts at trust 1.0.
* For each valid, unrevoked, unexpired vouch from issuer to subject with
  score s, the subject's trust is increased by
  issuer_trust * s * decay^depth.
* Propagation is bounded: depth at most 8, and contributions below 1e-9
  are cut off.
* The result is the fixed point over all paths up to that bound, not a
  first-visit traversal. The score therefore depends only on the set of
  valid edges: equivalent edge sets yield identical scores regardless of
  insertion order, and adding a valid vouch can never lower an existing
  score (monotonicity).
* Only cryptographically valid vouches are admitted, so a forgery cannot
  inject fake trust.
* When a dispute list is present, the two-pass procedure of
  [](#sec-dispute-semantics) applies.

# Implementation Status {#sec-implementation-status}

This section records the status of implementations of this specification
at the time of publication, in the sense of {{RFC7942}}, and is to be
removed prior to publication as an RFC.

The mechanisms in this document are implemented in ATAR (Agent Trust and
Attribution Root), the reference implementation from which this document
was distilled. ATAR is open source under the MIT license, published as
the Python package "atar-trust" (version 1.0.0a2 at the time of
writing), with an automated test suite of 288 tests covering the wire
formats, intake rules, and evaluation semantics specified here.
Implementation and specification: [ATARSPEC].

# Security Considerations {#sec-security}

Forgery.
: Attestations, revocations, disputes, and rotation statements are
  Ed25519-signed and self-authenticating; forgery requires the issuer's
  private key. Any modification of signed payload bytes invalidates the
  signature.

Forged revocations and disputes.
: Every entry's signature is verified at every intake path
  ([](#sec-revocation-intake), [](#sec-dispute-intake)); forged entries
  are dropped on arrival, not merely ignored at evaluation.

Cross-key revocation.
: A revocation applies only when "revoked_by" equals the vouch's issuer
  ([](#sec-revocation-evaluation)). An attacker cannot revoke anyone
  else's vouch with their own key; such entries are inert.

Stale trust.
: Freshness ([](#sec-freshness)) forces periodic re-signing by the
  issuer. A future-dated timestamp can postpone a vouch's own expiry; an
  issuer gains nothing by doing so visibly, and verifiers MAY reject
  timestamps beyond local clock skew.

Key compromise.
: Revocation plus rotation ([](#sec-rotation)) allow recovery without
  total loss. The rotation statement is signed by the compromised key,
  so a key thief can also produce one; operators should therefore treat
  rotation statements with the same out-of-band confirmation habits used
  for key changes generally.

Replay.
: All objects are content-addressed and deduplicated; replaying an old
  object is idempotent and harmless. Replaying a revoked vouch does not
  un-revoke it: revocation state is separate data that merges
  monotonically (a vouch once revoked stays revoked).

Gossip availability.
: Revocation, expiry, and dispute state propagate best-effort. A
  verifier is current only as of its last synchronization, so a
  partitioned or stale peer set can serve out-of-date revocation state.
  Deployments that need fresher revocation data should synchronize more
  often or against more peers. The transport provides no
  confidentiality; all objects are public to the peer set by design.

Dispute spam and Sybil smears.
: Disputes from identities below the dispute threshold are stored and
  displayed but move no scores ([](#sec-dispute-semantics)). An attacker
  minting fresh identities gains no influence over the trusted graph.

Sybil attacks.
: Out of scope. Identity is free, so anyone can mint agents and
  self-vouch. Self-vouches contribute nothing to others (trust flows
  only from an already-trusted issuer), and real trust requires real
  agents vouching. The protocol provides the mechanism; reputation
  emerges from the graph, not from the protocol. Deployments needing
  admission control must layer it on top.

Canonicalization sensitivity.
: Signatures and content addresses depend on the exact canonical form of
  [](#sec-canonicalization). Implementations MUST use the specified
  serialization for signing input and content addresses, independent of
  however they represent the payload internally. JSON parser
  differentials (number formatting, Unicode escaping, duplicate keys)
  are a classic interop hazard; the canonical form is deliberately
  restricted (sorted keys, compact separators, ASCII-safe output) to
  minimize it, and the open issue of moving the native format to JCS is
  recorded in [](#sec-open-issues).

Privacy.
: Attestations, revocations, and disputes are exchanged with every peer
  an operator synchronizes with and should be considered public.
  Evidence references may reveal which tasks or documents an issuer
  relied on; issuers should treat evidence URIs as public information.

# IANA Considerations

This document has no IANA actions.

--- back

# Open Issues {#sec-open-issues}

The following points are deliberately left open for review and are the
questions the author intends to ask the community:

1. Canonicalization. The native wire format uses the minimal canonical
   JSON of [](#sec-canonicalization), while the Verifiable Credentials
   bridge uses JCS {{RFC8785}}. Requiring JCS everywhere would align the
   two paths and match credential tooling, at the cost of churning
   deployed content addresses. Input welcome.
2. Dispute threshold. The dispute weighting threshold
   ([](#sec-dispute-semantics)) is implementation-defined with a
   RECOMMENDED value of 0.5. Should a value be normative for
   interoperability, or is per-verifier policy the right model?
3. Revocation liveness. Gossip is best-effort, so revocation freshness
   is bounded by synchronization cadence ([](#sec-security)). Is a
   recommended synchronization cadence or a liveness signaling mechanism
   worth standardizing?
4. Venue. This revision is offered as an Independent Submission with
   intended status Experimental. If a working-group-adjacent effort (for
   example in the agent identity space) wants this work, the author is
   happy to retarget.
