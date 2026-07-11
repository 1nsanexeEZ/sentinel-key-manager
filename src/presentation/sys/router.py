from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

import base64

from src.application.audit.anomaly_service import AnomalyService
from src.application.audit.service import AuditService
from src.application.dynamic_secrets.service import DynamicSecretService
from src.application.keys.service import KeyRotationService
from src.core.config import get_settings
from src.core.crypto.envelope import unwrap_kek
from src.infrastructure.crypto.keyring import KeyringError, decode_root_key
from src.infrastructure.crypto.seal import seal_state
from src.infrastructure.crypto.shamir_unseal import unseal_coordinator
from src.infrastructure.database import get_session
from src.infrastructure.dynamic_db import DynamicDbProvider
from src.infrastructure.models.user import User
from src.infrastructure.repositories.dynamic_credential_repository import (
    DynamicCredentialRepository,
)
from src.infrastructure.repositories.key_repository import KeyRepository
from src.presentation.auth.dependencies import get_current_user
from src.presentation.rate_limit import rate_limit
from src.presentation.sys.schemas import (
    AlertItem,
    AlertsResponse,
    AuditVerifyResponse,
    DynamicCredentialResponse,
    RotateResponse,
    SealStatusResponse,
    UnsealProgressResponse,
    UnsealRequest,
    UnsealShareRequest,
)

ADMIN_ROLE = "admin"

router = APIRouter(prefix="/sys", tags=["sys"])


@router.get("/seal-status", response_model=SealStatusResponse)
async def seal_status() -> SealStatusResponse:
    return SealStatusResponse(sealed=seal_state.sealed)


@router.post(
    "/unseal",
    response_model=SealStatusResponse,
    dependencies=[Depends(rate_limit("unseal", limit=5, window=60))],
)
async def unseal(
    payload: UnsealRequest,
    session: AsyncSession = Depends(get_session),
) -> SealStatusResponse:
    try:
        root_key = decode_root_key(payload.key)
    except KeyringError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    # if a KEK already exists, the key must be able to decrypt it
    active = await KeyRepository(session).get_active()
    if active is not None:
        try:
            unwrap_kek(root_key, active.encrypted_kek)
        except Exception:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="invalid unseal key",
            )

    seal_state.unseal(root_key)
    return SealStatusResponse(sealed=False)


async def _root_key_matches_kek(session: AsyncSession, root_key: bytes) -> bool:
    active = await KeyRepository(session).get_active()
    if active is None:
        return True
    try:
        unwrap_kek(root_key, active.encrypted_kek)
    except Exception:
        return False
    return True


@router.post(
    "/unseal-share",
    response_model=UnsealProgressResponse,
    dependencies=[Depends(rate_limit("unseal", limit=5, window=60))],
)
async def unseal_share(
    payload: UnsealShareRequest,
    session: AsyncSession = Depends(get_session),
) -> UnsealProgressResponse:
    try:
        share = base64.b64decode(payload.share)
    except (ValueError, TypeError):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="share is not valid base64",
        )

    try:
        root_key = unseal_coordinator.submit(share)
    except ValueError as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(exc),
        )

    if root_key is None:
        return UnsealProgressResponse(
            sealed=True,
            provided=unseal_coordinator.provided,
            threshold=unseal_coordinator.threshold,
        )

    if not await _root_key_matches_kek(session, root_key):
        unseal_coordinator.reset()
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="reconstructed key is invalid",
        )

    seal_state.unseal(root_key)
    unseal_coordinator.reset()
    return UnsealProgressResponse(
        sealed=False,
        provided=0,
        threshold=unseal_coordinator.threshold,
    )


@router.post("/seal", response_model=SealStatusResponse)
async def seal(_: User = Depends(get_current_user)) -> SealStatusResponse:
    seal_state.seal()
    unseal_coordinator.reset()
    return SealStatusResponse(sealed=True)


@router.post("/rotate-key", response_model=RotateResponse)
async def rotate_key(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> RotateResponse:
    if user.role != ADMIN_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin role required",
        )
    if seal_state.sealed:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="service is sealed",
        )
    service = KeyRotationService(KeyRepository(session), seal_state.root_key())
    new_version = await service.rotate()
    return RotateResponse(active_version=new_version)


@router.get("/audit/verify", response_model=AuditVerifyResponse)
async def verify_audit(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> AuditVerifyResponse:
    if user.role != ADMIN_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin role required",
        )
    check = await AuditService(session).verify()
    return AuditVerifyResponse(
        valid=check.valid,
        checked=check.checked,
        broken_at=check.broken_at,
    )


@router.post("/db-creds", response_model=DynamicCredentialResponse)
async def issue_db_creds(
    ttl: int = 3600,
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> DynamicCredentialResponse:
    if user.role != ADMIN_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin role required",
        )
    dsn = get_settings().dynamic_db_dsn
    if not dsn:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="dynamic db secrets are not configured",
        )
    service = DynamicSecretService(
        DynamicDbProvider(dsn),
        DynamicCredentialRepository(session),
    )
    credential = await service.issue(ttl)
    return DynamicCredentialResponse(
        username=credential.username,
        password=credential.password,
        expires_at=credential.expires_at,
    )


@router.get("/alerts", response_model=AlertsResponse)
async def alerts(
    session: AsyncSession = Depends(get_session),
    user: User = Depends(get_current_user),
) -> AlertsResponse:
    if user.role != ADMIN_ROLE:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin role required",
        )
    found = await AnomalyService(session).scan()
    return AlertsResponse(
        alerts=[
            AlertItem(kind=a.kind, actor_id=a.actor_id, count=a.count) for a in found
        ]
    )
