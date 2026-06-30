from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.application.auth.service import AuthService
from src.infrastructure.database import get_session
from src.infrastructure.repositories.user_repository import UserRepository


def get_auth_service(
    session: AsyncSession = Depends(get_session),
) -> AuthService:
    return AuthService(UserRepository(session))
