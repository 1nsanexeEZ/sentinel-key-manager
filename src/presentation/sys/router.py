from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession

from src.core.crypto.envelope import unwrap_kek
from src.infrastructure.crypto.keyring import KeyringError, decode_root_key
from src.infrastructure.crypto.seal import seal_state
from src.infrastructure.database import get_session
from src.infrastructure.models.user import User
from src.infrastructure.repositories.key_repository import KeyRepository
from src.presentation.auth.dependencies import get_current_user
from src.presentation.sys.schemas import SealStatusResponse, UnsealRequest

router = APIRouter(prefix="/sys", tags=["sys"])


@router.get("/seal-status", response_model=SealStatusResponse)
async def seal_status() -> SealStatusResponse:
    return SealStatusResponse(sealed=seal_state.sealed)


@router.post("/unseal", response_model=SealStatusResponse)
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


@router.post("/seal", response_model=SealStatusResponse)
async def seal(_: User = Depends(get_current_user)) -> SealStatusResponse:
    seal_state.seal()
    return SealStatusResponse(sealed=True)
