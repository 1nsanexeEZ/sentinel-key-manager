import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.models.secret import Secret


class SecretRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def get_by_path(self, path: str) -> Secret | None:
        result = await self._session.execute(
            select(Secret).where(Secret.path == path)
        )
        return result.scalar_one_or_none()

    async def list_paths(self, prefix: str | None = None) -> list[str]:
        stmt = select(Secret.path).order_by(Secret.path)
        if prefix:
            stmt = stmt.where(Secret.path.startswith(prefix))
        result = await self._session.execute(stmt)
        return list(result.scalars().all())

    async def upsert(
        self,
        path: str,
        ciphertext: bytes,
        encrypted_dek: bytes,
        key_version: int,
        created_by: uuid.UUID | None,
    ) -> Secret:
        secret = await self.get_by_path(path)
        if secret is None:
            secret = Secret(
                path=path,
                ciphertext=ciphertext,
                encrypted_dek=encrypted_dek,
                key_version=key_version,
                created_by=created_by,
            )
            self._session.add(secret)
        else:
            secret.ciphertext = ciphertext
            secret.encrypted_dek = encrypted_dek
            secret.key_version = key_version
        await self._session.commit()
        await self._session.refresh(secret)
        return secret

    async def delete(self, path: str) -> bool:
        secret = await self.get_by_path(path)
        if secret is None:
            return False
        await self._session.delete(secret)
        await self._session.commit()
        return True
