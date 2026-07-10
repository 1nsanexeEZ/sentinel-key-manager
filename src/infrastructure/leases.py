from redis.asyncio import Redis

_PREFIX = "lease:"


class LeaseStore:
    """Tracks live access tokens in Redis by their jti, with a TTL matching the
    token expiry. A token is only valid while its lease exists, which is what
    makes revocation (deleting the lease) possible."""

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def create(self, jti: str, subject: str, ttl: int) -> None:
        await self._redis.set(f"{_PREFIX}{jti}", subject, ex=ttl)

    async def exists(self, jti: str) -> bool:
        return bool(await self._redis.exists(f"{_PREFIX}{jti}"))

    async def revoke(self, jti: str) -> None:
        await self._redis.delete(f"{_PREFIX}{jti}")
