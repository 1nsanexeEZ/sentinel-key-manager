from datetime import datetime

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


class UnsealShareRequest(BaseModel):
    share: str  # base64-encoded Shamir share


class UnsealProgressResponse(BaseModel):
    sealed: bool
    provided: int
    threshold: int


class DynamicCredentialResponse(BaseModel):
    username: str
    password: str
    expires_at: datetime


class AlertItem(BaseModel):
    kind: str
    actor_id: str | None
    count: int


class AlertsResponse(BaseModel):
    alerts: list[AlertItem]
