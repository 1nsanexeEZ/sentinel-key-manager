from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.models.encryption_key import EncryptionKey


class KeyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_active(self) -> EncryptionKey | None:
        result = await self._session.execute(
            select(EncryptionKey).where(EncryptionKey.is_active.is_(True))
        )
        return result.scalar_one_or_none()

    async def get_by_version(self, version: int) -> EncryptionKey | None:
        result = await self._session.execute(
            select(EncryptionKey).where(EncryptionKey.version == version)
        )
        return result.scalar_one_or_none()

    async def max_version(self) -> int:
        result = await self._session.execute(select(EncryptionKey.version))
        versions = result.scalars().all()
        return max(versions, default=0)

    async def add(
        self,
        version: int,
        encrypted_kek: bytes,
        is_active: bool,
    ) -> EncryptionKey:
        key = EncryptionKey(
            version=version,
            encrypted_kek=encrypted_kek,
            is_active=is_active,
        )
        self._session.add(key)
        await self._session.commit()
        await self._session.refresh(key)
        return key

    async def set_active_version(self, version: int) -> None:
        await self._session.execute(update(EncryptionKey).values(is_active=False))
        await self._session.execute(
            update(EncryptionKey)
            .where(EncryptionKey.version == version)
            .values(is_active=True)
        )
        await self._session.commit()
