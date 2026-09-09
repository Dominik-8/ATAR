from atar.atc import (
    make_agent_card,
    verify_agent_card,
    verify_token,
    vouch_from_token,
    vouch_to_token,
)
from atar.identity import did_from_public, generate_identity
from atar.vouch import create_vouch


def test_vouch_token_roundtrip():
    issuer = generate_identity()
    subject = generate_identity()
    v = create_vouch(issuer, subject.public_key, score=0.7, scope="research")
    tok = vouch_to_token(v)
    # token is a header-safe string
    assert isinstance(tok, str)
    assert vouch_from_token(tok) == v


def test_verify_token_valid_and_invalid():
    issuer = generate_identity()
    subject = generate_identity()
    v = create_vouch(issuer, subject.public_key, score=0.7, scope="research")
    tok = vouch_to_token(v)
    assert verify_token(tok) is True
    # tamper the token
    bad = tok[:-4] + ("AAAA" if tok[-4:] != "AAAA" else "BBBB")
    assert verify_token(bad) is False


def test_agent_card_carries_verifiable_vouches():
    alice = generate_identity()
    bob = generate_identity()
    carol = generate_identity()
    # alice vouches for bob, bob vouches for carol
    v_ab = create_vouch(alice, bob.public_key, score=0.9, scope="coding")
    v_bc = create_vouch(bob, carol.public_key, score=0.8, scope="coding")
    card = make_agent_card(
        did=did_from_public(carol.public_key),
        name="carol",
        vouches=[v_ab, v_bc],
    )
    result = verify_agent_card(card)
    assert result["did"] == did_from_public(carol.public_key)
    assert result["name"] == "carol"
    assert len(result["valid_vouches"]) == 2
    assert len(result["invalid_vouches"]) == 0


def test_agent_card_detects_invalid_vouch():
    alice = generate_identity()
    bob = generate_identity()
    v = create_vouch(alice, bob.public_key, score=0.9, scope="coding")
    card = make_agent_card(did_from_public(bob.public_key), "bob", [v])
    # tamper the stored vouch token inside the card's trust extension
    from atar.atc import _trust_params

    params = _trust_params(card)
    tok = params["vouches"][0]
    bad = tok[:-4] + ("ZZZZ" if tok[-4:] != "ZZZZ" else "YYYY")
    params["vouches"][0] = bad
    result = verify_agent_card(card)
    assert len(result["valid_vouches"]) == 0
    assert len(result["invalid_vouches"]) == 1
