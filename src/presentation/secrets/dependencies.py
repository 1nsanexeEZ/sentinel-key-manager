from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.application.audit.service import AuditService
from src.application.secrets.service import SecretService
from src.domain.rbac import Capability, is_allowed
from src.infrastructure.crypto.keyring import Keyring
from src.infrastructure.crypto.seal import seal_state
from src.infrastructure.database import get_session
from src.infrastructure.models.user import User
from src.infrastructure.repositories.key_repository import KeyRepository
from src.infrastructure.repositories.policy_repository import PolicyRepository
from src.infrastructure.repositories.secret_repository import SecretRepository
from src.infrastructure.repositories.secret_version_repository import (
    SecretVersionRepository,
)
from src.presentation.auth.dependencies import get_current_user

ADMIN_ROLE = "admin"


def get_secret_service(
    session: AsyncSession = Depends(get_session),
) -> SecretService:
    if seal_state.sealed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="service is sealed",
        )
    keyring = Keyring(KeyRepository(session), seal_state.root_key())
    return SecretService(
        SecretRepository(session),
        SecretVersionRepository(session),
        keyring,
    )


def get_audit_service(
    session: AsyncSession = Depends(get_session),
) -> AuditService:
    return AuditService(session)


def client_ip(request: Request) -> str | None:
    return request.client.host if request.client else None


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
            await AuditService(session).record(
                action=capability.value,
                result="denied",
                actor_id=user.id,
                resource=path,
                client_ip=client_ip(request),
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="not permitted for this path",
            )
        return user

    return checker
