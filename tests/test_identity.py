from atar.identity import generate_identity, did_from_public


def test_generate_identity_returns_keypair():
    ident = generate_identity()
    assert ident is not None
    assert hasattr(ident, "private_key") and hasattr(ident, "public_key")
    assert did_from_public(ident.public_key).startswith("did:agent:")
