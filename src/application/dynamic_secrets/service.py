import secrets
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from uuid import uuid4

from src.infrastructure.dynamic_db import DynamicDbProvider
from src.infrastructure.repositories.dynamic_credential_repository import (
    DynamicCredentialRepository,
)


@dataclass(frozen=True)
class IssuedCredential:
    username: str
    password: str
    expires_at: datetime


class DynamicSecretService:
    def __init__(
        self,
        provider: DynamicDbProvider,
        repo: DynamicCredentialRepository,
    ) -> None:
        self._provider = provider
        self._repo = repo

    async def issue(self, ttl_seconds: int) -> IssuedCredential:
        username = f"sentinel_dyn_{uuid4().hex[:12]}"
        password = secrets.token_urlsafe(24)
        expires_at = datetime.now(timezone.utc) + timedelta(seconds=ttl_seconds)
        await self._provider.create_login_role(username, password, expires_at)
        await self._repo.add(username, expires_at)
        return IssuedCredential(username, password, expires_at)

    async def revoke_expired(self) -> int:
        now = datetime.now(timezone.utc)
        expired = await self._repo.list_expired(now)
        for record in expired:
            await self._provider.drop_role(record.username)
            await self._repo.mark_revoked(record.username)
        return len(expired)
