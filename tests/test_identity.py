from atar.identity import generate_identity, did_from_public


def test_generate_identity_returns_keypair():
    ident = generate_identity()
    assert ident is not None
    assert hasattr(ident, "private_key") and hasattr(ident, "public_key")
    assert did_from_public(ident.public_key).startswith("did:key:z6Mk")


def test_sign_and_verify():
    ident = generate_identity()
    msg = b"hello agent"
    sig = ident.sign(msg)
    # Ed25519 verify raises InvalidSignature on mismatch; no raise = valid
    ident.public_key.verify(sig, msg)
    # and a tampered message must raise
    import pytest
    from cryptography.exceptions import InvalidSignature

    with pytest.raises(InvalidSignature):
        ident.public_key.verify(sig, b"tampered")
