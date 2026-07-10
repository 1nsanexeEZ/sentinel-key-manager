import uuid

from sqlalchemy.ext.asyncio import AsyncSession

from src.infrastructure.models.audit import AuditRecord


class AuditService:
    """Writes immutable audit records. Secret values are never logged."""

    def __init__(self, session: AsyncSession) -> None:
        self._session = session

    async def record(
        self,
        *,
        action: str,
        result: str,
        actor_id: uuid.UUID | None = None,
        resource: str | None = None,
        client_ip: str | None = None,
    ) -> None:
        self._session.add(
            AuditRecord(
                actor_id=actor_id,
                action=action,
                resource=resource,
                result=result,
                client_ip=client_ip,
            )
        )
        await self._session.commit()
