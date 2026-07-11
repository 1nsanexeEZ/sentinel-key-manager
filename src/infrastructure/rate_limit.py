from redis.asyncio import Redis

_PREFIX = "ratelimit:"


class RateLimiter:
    """Fixed-window counter in Redis: at most `limit` hits per `window` seconds
    for a given key. The first hit in a window sets the expiry."""

    def __init__(self, redis: Redis) -> None:
        self._redis = redis

    async def hit(self, key: str, limit: int, window: int) -> bool:
        full_key = f"{_PREFIX}{key}"
        count = await self._redis.incr(full_key)
        if count == 1:
            await self._redis.expire(full_key, window)
        return count <= limit
