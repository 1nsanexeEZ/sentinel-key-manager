import uuid

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from src.domain.audit_chain import AuditEvent, ChainCheck, compute_hash, verify_chain
from src.infrastructure.models.audit import AuditRecord
from src.infrastructure.nats import publish_audit_event


class AuditService:
    """Writes immutable, hash-chained audit records. Secret values are never
    logged; altering any past record breaks the chain and is detectable."""

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
        prev_hash = await self._last_hash()
        event = AuditEvent(
            actor_id=str(actor_id) if actor_id else None,
            action=action,
            resource=resource,
            result=result,
            client_ip=client_ip,
        )
        record_hash = compute_hash(prev_hash, event)
        self._session.add(
            AuditRecord(
                actor_id=actor_id,
                action=action,
                resource=resource,
                result=result,
                client_ip=client_ip,
                prev_hash=prev_hash,
                record_hash=record_hash,
            )
        )
        await self._session.commit()
        await publish_audit_event(
            {
                "actor_id": str(actor_id) if actor_id else None,
                "action": action,
                "resource": resource,
                "result": result,
                "client_ip": client_ip,
                "record_hash": record_hash,
            }
        )

    async def _last_hash(self) -> str:
        result = await self._session.execute(
            select(AuditRecord.record_hash)
            .order_by(AuditRecord.id.desc())
            .limit(1)
        )
        return result.scalar_one_or_none() or ""

    async def verify(self) -> ChainCheck:
        result = await self._session.execute(
            select(AuditRecord).order_by(AuditRecord.id.asc())
        )
        rows = []
        for record in result.scalars().all():
            event = AuditEvent(
                actor_id=str(record.actor_id) if record.actor_id else None,
                action=record.action,
                resource=record.resource,
                result=record.result,
                client_ip=record.client_ip,
            )
            rows.append((record.id, event, record.prev_hash, record.record_hash))
        return verify_chain(rows)
