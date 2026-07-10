from fastapi import APIRouter, Depends, HTTPException, Response, status

from src.application.auth.exceptions import InvalidCredentials, UserAlreadyExists
from src.application.auth.service import AuthService
from src.infrastructure.leases import LeaseStore
from src.infrastructure.models.user import User
from src.presentation.auth.dependencies import (
    get_auth_service,
    get_current_jti,
    get_current_user,
    get_lease_store,
)
from src.presentation.auth.schemas import (
    LoginRequest,
    RegisterRequest,
    TokenResponse,
    UserResponse,
)

router = APIRouter(prefix="/auth", tags=["auth"])


@router.post(
    "/register",
    response_model=UserResponse,
    status_code=status.HTTP_201_CREATED,
)
async def register(
    payload: RegisterRequest,
    service: AuthService = Depends(get_auth_service),
) -> UserResponse:
    try:
        user = await service.register(payload.username, payload.password)
    except UserAlreadyExists:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="username already taken",
        )
    return UserResponse.model_validate(user)


@router.post("/login", response_model=TokenResponse)
async def login(
    payload: LoginRequest,
    service: AuthService = Depends(get_auth_service),
) -> TokenResponse:
    try:
        token = await service.authenticate(payload.username, payload.password)
    except InvalidCredentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="invalid username or password",
        )
    return TokenResponse(access_token=token)


@router.get("/me", response_model=UserResponse)
async def me(current_user: User = Depends(get_current_user)) -> UserResponse:
    return UserResponse.model_validate(current_user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
async def logout(
    _: User = Depends(get_current_user),
    jti: str = Depends(get_current_jti),
    leases: LeaseStore = Depends(get_lease_store),
) -> Response:
    await leases.revoke(jti)
    return Response(status_code=status.HTTP_204_NO_CONTENT)
