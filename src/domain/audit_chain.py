import hashlib
from dataclasses import dataclass


@dataclass(frozen=True)
class AuditEvent:
    actor_id: str | None
    action: str
    resource: str | None
    result: str
    client_ip: str | None


def _canonical(event: AuditEvent) -> str:
    # order-fixed, unambiguous separator so the hash is reproducible
    return "\x1f".join(
        (
            event.actor_id or "",
            event.action,
            event.resource or "",
            event.result,
            event.client_ip or "",
        )
    )


def compute_hash(prev_hash: str, event: AuditEvent) -> str:
    return hashlib.sha256((prev_hash + _canonical(event)).encode()).hexdigest()


@dataclass(frozen=True)
class ChainCheck:
    valid: bool
    checked: int
    broken_at: int | None


def verify_chain(records: list[tuple[int, AuditEvent, str, str]]) -> ChainCheck:
    """records: (id, event, prev_hash, record_hash) ordered by id ascending."""
    prev = ""
    for index, (record_id, event, stored_prev, stored_hash) in enumerate(records):
        if stored_prev != prev:
            return ChainCheck(False, index, record_id)
        if compute_hash(prev, event) != stored_hash:
            return ChainCheck(False, index, record_id)
        prev = stored_hash
    return ChainCheck(True, len(records), None)
