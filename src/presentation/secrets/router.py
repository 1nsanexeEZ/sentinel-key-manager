from fastapi import APIRouter, Depends, HTTPException, Response, status

from src.application.secrets.exceptions import SecretNotFound
from src.application.secrets.service import SecretService
from src.domain.rbac import Capability
from src.infrastructure.models.user import User
from src.presentation.auth.dependencies import get_current_user
from src.presentation.secrets.dependencies import get_secret_service, require
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
    service: SecretService = Depends(get_secret_service),
    user: User = Depends(require(Capability.WRITE)),
) -> SecretResponse:
    secret = await service.set_secret(path, payload.value, user.id)
    return SecretResponse(path=secret.path, value=secret.value)


@router.get("/{path:path}", response_model=SecretResponse)
async def get_secret(
    path: str,
    service: SecretService = Depends(get_secret_service),
    _: User = Depends(require(Capability.READ)),
) -> SecretResponse:
    try:
        secret = await service.get_secret(path)
    except SecretNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="secret not found",
        )
    return SecretResponse(path=secret.path, value=secret.value)


@router.delete("/{path:path}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_secret(
    path: str,
    service: SecretService = Depends(get_secret_service),
    _: User = Depends(require(Capability.DELETE)),
) -> Response:
    try:
        await service.delete_secret(path)
    except SecretNotFound:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="secret not found",
        )
    return Response(status_code=status.HTTP_204_NO_CONTENT)
