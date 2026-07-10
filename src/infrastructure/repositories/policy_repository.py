from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.models.policy import Policy


class PolicyRepository:
    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def list_for_role(self, role: str) -> list[Policy]:
        result = await self._session.execute(
            select(Policy).where(Policy.role == role)
        )
        return list(result.scalars().all())
