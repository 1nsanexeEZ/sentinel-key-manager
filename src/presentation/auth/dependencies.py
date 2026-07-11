from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.application.auth.service import AuthService
from src.core.security.tokens import TokenError, decode_token
from src.infrastructure.database import get_session
from src.infrastructure.leases import LeaseStore
from src.infrastructure.models.user import User
from src.infrastructure.redis import get_redis
from src.infrastructure.repositories.user_repository import UserRepository

_bearer = HTTPBearer(auto_error=True)


def get_user_repository(
    session: AsyncSession = Depends(get_session),
) -> UserRepository:
    return UserRepository(session)


def get_lease_store() -> LeaseStore:
    return LeaseStore(get_redis())


def get_auth_service(
    users: UserRepository = Depends(get_user_repository),
    leases: LeaseStore = Depends(get_lease_store),
) -> AuthService:
    return AuthService(users, leases)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    users: UserRepository = Depends(get_user_repository),
    leases: LeaseStore = Depends(get_lease_store),
) -> User:
    unauthorized = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="invalid or expired token",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        claims = decode_token(credentials.credentials)
    except TokenError:
        raise unauthorized

    user_id = claims.get("sub")
    jti = claims.get("jti")
    if user_id is None or jti is None:
        raise unauthorized

    # a revoked (or expired-and-swept) token has no lease
    if not await leases.exists(jti):
        raise unauthorized

    user = await users.get_by_id(user_id)
    if user is None or not user.is_active:
        raise unauthorized
    return user


async def get_current_jti(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
) -> str:
    try:
        claims = decode_token(credentials.credentials)
    except TokenError:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired token",
            headers={"WWW-Authenticate": "Bearer"},
        )
    jti = claims.get("jti")
    if not jti:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid or expired token",
        )
    return jti
