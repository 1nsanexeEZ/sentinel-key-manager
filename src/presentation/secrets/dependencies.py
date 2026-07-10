from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.application.secrets.service import SecretService
from src.domain.rbac import Capability, is_allowed
from src.infrastructure.database import get_session
from src.infrastructure.models.user import User
from src.infrastructure.repositories.policy_repository import PolicyRepository
from src.infrastructure.repositories.secret_repository import SecretRepository
from src.presentation.auth.dependencies import get_current_user

ADMIN_ROLE = "admin"


def get_secret_service(
    session: AsyncSession = Depends(get_session),
) -> SecretService:
    return SecretService(SecretRepository(session))


def require(
    capability: Capability,
) -> Callable[..., Coroutine[Any, Any, User]]:
    async def checker(
        request: Request,
        user: User = Depends(get_current_user),
        session: AsyncSession = Depends(get_session),
    ) -> User:
        if user.role == ADMIN_ROLE:
            return user
        path = request.path_params.get("path", "")
        policies = await PolicyRepository(session).list_for_role(user.role)
        if not is_allowed(policies, path, capability):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="not permitted for this path",
            )
        return user

    return checker
