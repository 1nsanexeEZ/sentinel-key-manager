import pytest

from src.core.security.tokens import (
    TokenError,
    create_access_token,
    decode_token,
)


def test_roundtrip_subject():
    issued = create_access_token("user-123")
    claims = decode_token(issued.token)
    assert claims["sub"] == "user-123"
    assert claims["type"] == "access"


def test_issued_token_carries_jti():
    issued = create_access_token("user-123")
    claims = decode_token(issued.token)
    assert claims["jti"] == issued.jti
    assert issued.expires_in > 0


def test_token_has_expiry():
    claims = decode_token(create_access_token("user-123").token)
    assert claims["exp"] > claims["iat"]


def test_tampered_token_rejected():
    issued = create_access_token("user-123")
    with pytest.raises(TokenError):
        decode_token(issued.token + "tampered")


def test_jti_is_unique_per_token():
    assert create_access_token("user-123").jti != create_access_token("user-123").jti
