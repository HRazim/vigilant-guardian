"""
Vigilant Guardian — Rate Limiting middleware (section 8.2).

Redis-backed, 100 req/min par utilisateur.
"""

from __future__ import annotations

import time

from fastapi import HTTPException, Request, status
from starlette.middleware.base import BaseHTTPMiddleware, RequestResponseEndpoint
from starlette.responses import Response

import redis.asyncio as aioredis

from src.config.settings import settings
from src.config.logging import get_logger

logger = get_logger(__name__)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """Middleware de rate limiting Redis (sliding window)."""

    def __init__(self, app, max_requests: int | None = None):  # type: ignore[no-untyped-def]
        super().__init__(app)
        self.max_requests = max_requests or settings.api_rate_limit
        self.window_seconds = 60
        self.redis: aioredis.Redis | None = None

    async def _get_redis(self) -> aioredis.Redis:
        if self.redis is None:
            self.redis = aioredis.from_url(
                settings.redis_url, decode_responses=True
            )
        return self.redis

    def _get_client_key(self, request: Request) -> str:
        """Identifie le client par IP ou header Authorization."""
        auth = request.headers.get("Authorization", "")
        if auth.startswith("Bearer "):
            # Identifier par token (hash partiel)
            return f"ratelimit:{hash(auth)}"
        forwarded = request.headers.get("X-Forwarded-For", "")
        ip = forwarded.split(",")[0].strip() if forwarded else (
            request.client.host if request.client else "unknown"
        )
        return f"ratelimit:{ip}"

    async def dispatch(
        self, request: Request, call_next: RequestResponseEndpoint
    ) -> Response:
        # Bypass pour les routes de santé
        if request.url.path in ("/health", "/docs", "/redoc", "/openapi.json"):
            return await call_next(request)

        try:
            r = await self._get_redis()
            key = self._get_client_key(request)
            now = time.time()
            window_start = now - self.window_seconds

            pipe = r.pipeline()
            pipe.zremrangebyscore(key, 0, window_start)
            pipe.zadd(key, {str(now): now})
            pipe.zcard(key)
            pipe.expire(key, self.window_seconds)
            results = await pipe.execute()

            request_count = results[2]

            if request_count > self.max_requests:
                logger.warning(
                    "rate_limit_exceeded",
                    client_key=key,
                    count=request_count,
                )
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit dépassé : {self.max_requests} req/min",
                )

            response = await call_next(request)
            response.headers["X-RateLimit-Limit"] = str(self.max_requests)
            response.headers["X-RateLimit-Remaining"] = str(
                max(0, self.max_requests - request_count)
            )
            return response

        except HTTPException:
            raise
        except Exception as exc:
            # En cas d'erreur Redis, laisser passer (fail-open)
            logger.error("rate_limit_redis_error", error=str(exc))
            return await call_next(request)
