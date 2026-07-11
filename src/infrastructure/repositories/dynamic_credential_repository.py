from datetime import datetime

from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.models.dynamic_credential import DynamicCredential


class DynamicCredentialRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def add(self, username: str, expires_at: datetime) -> DynamicCredential:
        record = DynamicCredential(username=username, expires_at=expires_at)
        self._session.add(record)
        await self._session.commit()
        await self._session.refresh(record)
        return record

    async def list_expired(self, now: datetime) -> list[DynamicCredential]:
        result = await self._session.execute(
            select(DynamicCredential).where(
                DynamicCredential.revoked.is_(False),
                DynamicCredential.expires_at < now,
            )
        )
        return list(result.scalars().all())

    async def mark_revoked(self, username: str) -> None:
        await self._session.execute(
            update(DynamicCredential)
            .where(DynamicCredential.username == username)
            .values(revoked=True)
        )
        await self._session.commit()
