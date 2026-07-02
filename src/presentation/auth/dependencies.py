from fastapi import Depends, HTTPException, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from sqlalchemy.ext.asyncio import AsyncSession

from src.application.auth.service import AuthService
from src.core.security.tokens import TokenError, decode_token
from src.infrastructure.database import get_session
from src.infrastructure.models.user import User
from src.infrastructure.repositories.user_repository import UserRepository

_bearer = HTTPBearer(auto_error=True)


def get_user_repository(
    session: AsyncSession = Depends(get_session),
) -> UserRepository:
    return UserRepository(session)


def get_auth_service(
    users: UserRepository = Depends(get_user_repository),
) -> AuthService:
    return AuthService(users)


async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(_bearer),
    users: UserRepository = Depends(get_user_repository),
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
    if user_id is None:
        raise unauthorized

    user = await users.get_by_id(user_id)
    if user is None or not user.is_active:
        raise unauthorized
    return user
