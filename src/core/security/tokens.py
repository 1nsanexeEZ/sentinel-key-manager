from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from jose import JWTError, jwt

from src.core.config import get_settings

settings = get_settings()


class TokenError(Exception):
    """Raised when a token is invalid, expired or tampered with."""


@dataclass(frozen=True)
class IssuedToken:
    token: str
    jti: str
    expires_in: int  # seconds


def create_access_token(subject: str) -> IssuedToken:
    now = datetime.now(timezone.utc)
    ttl = settings.access_token_expire_minutes * 60
    expire = now + timedelta(seconds=ttl)
    jti = uuid4().hex
    payload = {
        "sub": subject,
        "jti": jti,
        "iat": int(now.timestamp()),
        "exp": int(expire.timestamp()),
        "type": "access",
    }
    token = jwt.encode(payload, settings.secret_key, algorithm=settings.jwt_algorithm)
    return IssuedToken(token=token, jti=jti, expires_in=ttl)


def decode_token(token: str) -> dict:
    try:
        return jwt.decode(
            token,
            settings.secret_key,
            algorithms=[settings.jwt_algorithm],
        )
    except JWTError as exc:
        raise TokenError(str(exc)) from exc
