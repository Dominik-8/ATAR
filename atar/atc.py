"""ATC — Agent Trust Carrier.

The wire format that lets an agent present its verifiable identity + vouches
*inline* on first contact, over any existing transport (HTTP header,
A2A extension, MCP metadata). ATAR does not replace MCP/A2A — it rides on
top of them as a carrier.

Two primitives:
  * ``vouch_to_token`` / ``vouch_from_token`` — a vouch blob encoded as a
    header-safe string (base64url of canonical JSON).
  * ``make_agent_card`` / ``verify_agent_card`` — a self-describing JSON
    "business card" an agent sends: its DID, a name, and the vouches it
    wants to present. The receiver verifies each vouch offline.
"""

from __future__ import annotations

import base64
import json

from .vouch import verify_vouch


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def vouch_to_token(vouch: dict) -> str:
    """Encode a vouch blob as a header-safe token string."""
    raw = json.dumps(vouch, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return _b64url_encode(raw)


def vouch_from_token(token: str) -> dict:
    """Decode a token back into a vouch blob (dict)."""
    return json.loads(_b64url_decode(token))


def verify_token(token: str) -> bool:
    """Verify a vouch token's signature. Returns True/False."""
    try:
        return verify_vouch(vouch_from_token(token))
    except (ValueError, KeyError):
        return False


def make_agent_card(did: str, name: str, vouches: list[dict], *, extra: dict | None = None) -> dict:
    """Build an agent card carrying the agent's DID, name and vouch tokens.

    ``vouches`` is a list of vouch *blobs* (dicts); they are encoded to tokens
    here so the card is transport-ready.
    """
    card = {
        "schema": "atar-agent-card/1.0",
        "did": did,
        "name": name,
        "atar": {
            "vouches": [vouch_to_token(v) for v in vouches],
        },
    }
    if extra:
        card.update(extra)
    return card


def verify_agent_card(card: dict) -> dict:
    """Verify every vouch in an agent card offline.

    Returns a report:
        {
          "did": <card did>,
          "name": <card name>,
          "valid_vouches": [list of decoded vouch blobs that verified],
          "invalid_vouches": [list of tokens that failed],
        }
    """
    valid, invalid = [], []
    for tok in card.get("atar", {}).get("vouches", []):
        if verify_token(tok):
            valid.append(vouch_from_token(tok))
        else:
            invalid.append(tok)
    return {
        "did": card.get("did"),
        "name": card.get("name"),
        "valid_vouches": valid,
        "invalid_vouches": invalid,
    }
