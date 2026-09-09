"""W3C Verifiable Credentials bridge for ATAR vouches (SPEC §3.1).

The lean native vouch format stays ATAR's internal representation; this module
is the interop bridge *out*: any VC tooling can check an exported ATAR vouch.

Mapping (vouch payload -> VC):
    issuer   -> ``issuer``                (canonicalized to did:key, SPEC §2.1)
    subject  -> ``credentialSubject.id``
    scope    -> ``credentialSubject["atar:scope"]``
    score    -> ``credentialSubject["atar:score"]``
    claim    -> ``credentialSubject["atar:claim"]`` (omitted when None)
    evidence -> ``credentialSubject["atar:evidence"]`` (omitted when None)
    ts       -> ``validFrom`` (ISO 8601 UTC)

Proof: W3C Data Integrity with the ``eddsa-jcs-2022`` cryptosuite —
JCS (RFC 8785) canonicalization, SHA-256, Ed25519. The signing input is
``sha256(jcs(proofOptions)) || sha256(jcs(credential))`` per the Data
Integrity spec; ``proofValue`` is the multibase (base58btc) signature.

Revocation and TTL deliberately stay ATAR-side (SPEC §6/§7): the VC proves
the signed attestation; current trust state comes from the ATAR store.
"""

from __future__ import annotations

import hashlib
import time
from datetime import datetime, timezone

import base58
from cryptography.exceptions import InvalidSignature

from .identity import normalize_did, public_key_from_did
from .jcs import canonicalize

VC_CONTEXT_V2 = "https://www.w3.org/ns/credentials/v2"
# Inline term definitions so the credential needs no network fetch: these IRIs
# are identifiers, not documents a verifier must download.
ATAR_TERMS_CONTEXT = {"atar": "https://github.com/Dominik-8/ATAR/ns#"}
VC_TYPE_VOUCH = "ATARVouch"
CRYPTOSUITE = "eddsa-jcs-2022"


def _iso(ts: int) -> str:
    return datetime.fromtimestamp(int(ts), tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%SZ"
    )


def _from_iso(text: str) -> int:
    return int(
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
        .replace(tzinfo=timezone.utc)
        .timestamp()
    )


def vouch_to_credential(vouch: dict) -> dict:
    """Map a native ATAR vouch to an unsigned Verifiable Credential.

    Identifiers are canonicalized to ``did:key`` (SPEC §2.1) so the exported
    credential speaks the standard spelling even for pre-realignment vouches.
    """
    payload = vouch["payload"]
    subject: dict = {
        "id": normalize_did(payload["subject"]),
        "atar:scope": payload["scope"],
        "atar:score": float(payload["score"]),
    }
    if payload.get("claim") is not None:
        subject["atar:claim"] = payload["claim"]
    if payload.get("evidence") is not None:
        subject["atar:evidence"] = payload["evidence"]
    return {
        "@context": [VC_CONTEXT_V2, ATAR_TERMS_CONTEXT],
        "type": ["VerifiableCredential", VC_TYPE_VOUCH],
        "issuer": normalize_did(payload["issuer"]),
        "validFrom": _iso(payload["ts"]),
        "credentialSubject": subject,
    }


def sign_credential(credential: dict, identity) -> dict:
    """Attach a Data Integrity proof (eddsa-jcs-2022) signed by ``identity``.

    ``identity`` may be an ``Identity`` or a bare ``Ed25519PrivateKey``; its
    public key must match ``credential["issuer"]`` (alias-aware).
    """
    from .identity import did_from_public

    pub = (
        identity.public_key()
        if callable(getattr(identity, "public_key", None))
        else identity.public_key
    )
    if normalize_did(credential["issuer"]) != did_from_public(pub):
        raise ValueError("signing key does not match credential issuer")
    vm = credential["issuer"] + "#" + credential["issuer"].split(":")[2]
    proof = {
        "type": "DataIntegrityProof",
        "cryptosuite": CRYPTOSUITE,
        "created": _iso(int(time.time())),
        "verificationMethod": vm,
        "proofPurpose": "assertionMethod",
    }
    data = (
        hashlib.sha256(canonicalize(proof)).digest()
        + hashlib.sha256(canonicalize(credential)).digest()
    )
    proof["proofValue"] = "z" + base58.b58encode(identity.sign(data)).decode()
    out = dict(credential)
    out["proof"] = proof
    return out


def verify_credential(vc: dict) -> bool:
    """True iff the VC's Data Integrity proof verifies against its issuer.

    Fully offline: the key comes from the issuer's did:key; contexts are
    treated as identifiers and never fetched.
    """
    try:
        if not isinstance(vc, dict):
            return False
        if VC_CONTEXT_V2 not in vc.get("@context", []):
            return False
        types = vc.get("type", [])
        if "VerifiableCredential" not in types:
            return False
        issuer = vc["issuer"]
        proof = vc["proof"]
        if (
            proof.get("type") != "DataIntegrityProof"
            or proof.get("cryptosuite") != CRYPTOSUITE
        ):
            return False
        vm = proof["verificationMethod"]
        if not isinstance(vm, str) or not vm.startswith(issuer + "#"):
            return False  # proof must bind to the issuer's own key
        pub = public_key_from_did(issuer)
        sig = (
            base58.b58decode(proof["proofValue"][1:])
            if proof["proofValue"].startswith("z")
            else None
        )
        if sig is None:
            return False
        proof_options = {k: v for k, v in proof.items() if k != "proofValue"}
        credential = {k: v for k, v in vc.items() if k != "proof"}
        data = (
            hashlib.sha256(canonicalize(proof_options)).digest()
            + hashlib.sha256(canonicalize(credential)).digest()
        )
        pub.verify(sig, data)
        return True
    except (InvalidSignature, ValueError, KeyError, TypeError, AttributeError):
        return False


def credential_to_vouch_payload(vc: dict) -> dict:
    """Extract the ATAR vouch payload a credential carries (for display and
    cross-checking). Not a native vouch — the native signature signs different
    bytes, so importing a VC into the store goes through re-issuance, not
    conversion."""
    subj = vc["credentialSubject"]
    return {
        "type": "vouch",
        "issuer": vc["issuer"],
        "subject": subj["id"],
        "score": float(subj["atar:score"]),
        "scope": subj["atar:scope"],
        "claim": subj.get("atar:claim"),
        "ts": _from_iso(vc["validFrom"]),
    }
