from atar.identity import generate_identity, did_from_public
from atar.vouch import create_vouch, verify_vouch, vouch_from_self


def test_vouch_is_verifiable():
    issuer = generate_identity()
    subject = generate_identity()
    v = create_vouch(issuer, subject.public_key, score=0.9, scope="coding")
    assert verify_vouch(v) is True
    assert v["payload"]["subject"] == did_from_public(subject.public_key)
    assert v["payload"]["issuer"] == did_from_public(issuer.public_key)
    assert v["payload"]["score"] == 0.9
    assert v["payload"]["scope"] == "coding"


def test_vouch_fails_with_wrong_key():
    issuer = generate_identity()
    subject = generate_identity()
    attacker = generate_identity()
    v = create_vouch(issuer, subject.public_key, score=1.0, scope="coding")
    # tamper the issuer did so signature no longer matches
    v["payload"]["issuer"] = did_from_public(attacker.public_key)
    assert verify_vouch(v) is False


def test_self_vouch_is_a_claim_not_endorsement():
    agent = generate_identity()
    v = vouch_from_self(agent, claim="I am a coding agent", scope="coding")
    assert verify_vouch(v) is True
    assert v["payload"]["issuer"] == v["payload"]["subject"]
