from fastapi import Depends
from sqlalchemy.ext.asyncio import AsyncSession

from src.application.secrets.service import SecretService
from src.infrastructure.database import get_session
from src.infrastructure.repositories.secret_repository import SecretRepository


def get_secret_service(
    session: AsyncSession = Depends(get_session),
) -> SecretService:
    return SecretService(SecretRepository(session))
