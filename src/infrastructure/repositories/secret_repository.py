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
        value: str,
        created_by: uuid.UUID | None,
    ) -> Secret:
        secret = await self.get_by_path(path)
        if secret is None:
            secret = Secret(path=path, value=value, created_by=created_by)
            self._session.add(secret)
        else:
            secret.value = value
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
