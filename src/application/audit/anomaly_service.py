from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.anomaly import Alert, ObservedEvent, detect
from src.infrastructure.models.audit import AuditRecord


class AnomalyService:
    def __init__(self, session: AsyncSession, scan_limit: int = 500) -> None:
        self._session = session
        self._scan_limit = scan_limit

    async def scan(self) -> list[Alert]:
        result = await self._session.execute(
            select(AuditRecord)
            .order_by(AuditRecord.id.desc())
            .limit(self._scan_limit)
        )
        events = [
            ObservedEvent(
                actor_id=str(r.actor_id) if r.actor_id else None,
                action=r.action,
                result=r.result,
            )
            for r in result.scalars().all()
        ]
        return detect(events)
