from fastapi import APIRouter, Depends, HTTPException, Request, Response, status

from src.application.audit.service import AuditService
from src.application.secrets.exceptions import SecretNotFound
from src.application.secrets.service import SecretService
from src.domain.rbac import Capability
from src.infrastructure.models.user import User
from src.presentation.auth.dependencies import get_current_user
from src.presentation.secrets.dependencies import (
    client_ip,
    get_audit_service,
    get_secret_service,
    require,
)
from src.presentation.secrets.schemas import (
    SecretListResponse,
    SecretResponse,
    SecretWriteRequest,
)

router = APIRouter(prefix="/secrets", tags=["secrets"])


@router.get("", response_model=SecretListResponse)
async def list_secrets(
    prefix: str | None = None,
    service: SecretService = Depends(get_secret_service),
    _: User = Depends(get_current_user),
) -> SecretListResponse:
    return SecretListResponse(paths=await service.list_secrets(prefix))


@router.put("/{path:path}", response_model=SecretResponse)
async def set_secret(
    path: str,
    payload: SecretWriteRequest,
    request: Request,
    service: SecretService = Depends(get_secret_service),
    audit: AuditService = Depends(get_audit_service),
    user: User = Depends(require(Capability.WRITE)),
) -> SecretResponse:
    await service.set_secret(path, payload.value, user.id)
    await audit.record(
        action="write",
        result="success",
        actor_id=user.id,
        resource=path,
        client_ip=client_ip(request),
    )
    return SecretResponse(path=path, value=payload.value)


@router.get("/{path:path}", response_model=SecretResponse)
async def get_secret(
    path: str,
    request: Request,
    version: int | None = None,
    service: SecretService = Depends(get_secret_service),
    audit: AuditService = Depends(get_audit_service),
    user: User = Depends(require(Capability.READ)),
) -> SecretResponse:
    try:
        value = await service.get_secret(path, version)
    except SecretNotFound:
        await audit.record(
            action="read",
            result="not_found",
            actor_id=user.id,
            resource=path,
            client_ip=client_ip(request),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="secret not found",
        )
    await audit.record(
        action="read",
        result="success",
        actor_id=user.id,
        resource=path,
        client_ip=client_ip(request),
    )
    return SecretResponse(path=path, value=value)


@router.delete("/{path:path}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret(
    path: str,
    request: Request,
    service: SecretService = Depends(get_secret_service),
    audit: AuditService = Depends(get_audit_service),
    user: User = Depends(require(Capability.DELETE)),
) -> Response:
    try:
        await service.delete_secret(path)
    except SecretNotFound:
        await audit.record(
            action="delete",
            result="not_found",
            actor_id=user.id,
            resource=path,
            client_ip=client_ip(request),
        )
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="secret not found",
        )
    await audit.record(
        action="delete",
        result="success",
        actor_id=user.id,
        resource=path,
        client_ip=client_ip(request),
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.post("/{path:path}", response_model=SecretResponse)
async def rollback_secret(
    path: str,
    request: Request,
    to: int,
    service: SecretService = Depends(get_secret_service),
    audit: AuditService = Depends(get_audit_service),
    user: User = Depends(require(Capability.WRITE)),
) -> SecretResponse:
    try:
        value = await service.rollback(path, to)
    except SecretNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="secret or version not found",
        )
    await audit.record(
        action="rollback",
        result="success",
        actor_id=user.id,
        resource=f"{path}@{to}",
        client_ip=client_ip(request),
    )
    return SecretResponse(path=path, value=value)
