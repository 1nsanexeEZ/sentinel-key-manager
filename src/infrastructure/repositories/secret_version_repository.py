import uuid

from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.models.secret_version import SecretVersion


class SecretVersionRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def next_version(self, secret_id: uuid.UUID) -> int:
        result = await self._session.execute(
            select(func.max(SecretVersion.version)).where(
                SecretVersion.secret_id == secret_id
            )
        )
        return (result.scalar() or 0) + 1

    async def add(
        self,
        secret_id: uuid.UUID,
        version: int,
        ciphertext: bytes,
        encrypted_dek: bytes,
        key_version: int,
    ) -> SecretVersion:
        record = SecretVersion(
            secret_id=secret_id,
            version=version,
            ciphertext=ciphertext,
            encrypted_dek=encrypted_dek,
            key_version=key_version,
        )
        self._session.add(record)
        await self._session.commit()
        await self._session.refresh(record)
        return record

    async def get(
        self,
        secret_id: uuid.UUID,
        version: int,
    ) -> SecretVersion | None:
        result = await self._session.execute(
            select(SecretVersion).where(
                SecretVersion.secret_id == secret_id,
                SecretVersion.version == version,
            )
        )
        return result.scalar_one_or_none()

    async def list_versions(self, secret_id: uuid.UUID) -> list[int]:
        result = await self._session.execute(
            select(SecretVersion.version)
            .where(SecretVersion.secret_id == secret_id)
            .order_by(SecretVersion.version)
        )
        return list(result.scalars().all())
