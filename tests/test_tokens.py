import pytest

from src.core.security.tokens import TokenError, create_access_token, decode_token


def test_roundtrip_subject():
    token = create_access_token("user-123")
    claims = decode_token(token)
    assert claims["sub"] == "user-123"
    assert claims["type"] == "access"


def test_token_has_expiry():
    claims = decode_token(create_access_token("user-123"))
    assert claims["exp"] > claims["iat"]


def test_tampered_token_rejected():
    token = create_access_token("user-123")
    with pytest.raises(TokenError):
        decode_token(token + "tampered")
