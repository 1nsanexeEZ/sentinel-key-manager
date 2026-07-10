from pydantic import BaseModel


class UnsealRequest(BaseModel):
    key: str  # base64-encoded 32-byte root key


class SealStatusResponse(BaseModel):
    sealed: bool


class RotateResponse(BaseModel):
    active_version: int


class AuditVerifyResponse(BaseModel):
    valid: bool
    checked: int
    broken_at: int | None
