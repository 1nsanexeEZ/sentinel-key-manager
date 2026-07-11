import json
from typing import Any

import nats
from nats.aio.client import Client

from src.core.config import get_settings

_client: Client | None = None


async def _get_client() -> Client:
    global _client
    if _client is None or not _client.is_connected:
        _client = await nats.connect(get_settings().nats_url)
    return _client


async def publish_audit_event(payload: dict[str, Any]) -> None:
    """Best-effort publish. The DB audit log is the source of truth, so a NATS
    outage must never fail the originating request."""
    settings = get_settings()
    if not settings.nats_enabled:
        return
    try:
        client = await _get_client()
        await client.publish(
            settings.audit_nats_subject,
            json.dumps(payload).encode(),
        )
    except Exception:
        return
