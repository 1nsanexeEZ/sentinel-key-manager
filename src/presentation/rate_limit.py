from collections.abc import Callable, Coroutine
from typing import Any

from fastapi import HTTPException, Request, status

from src.infrastructure.rate_limit import RateLimiter
from src.infrastructure.redis import get_redis


def rate_limit(
    bucket: str,
    limit: int,
    window: int,
) -> Callable[..., Coroutine[Any, Any, None]]:
    async def dependency(request: Request) -> None:
        ip = request.client.host if request.client else "unknown"
        limiter = RateLimiter(get_redis())
        if not await limiter.hit(f"{bucket}:{ip}", limit, window):
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail="too many requests",
            )

    return dependency
