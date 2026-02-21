"""
Vigilant Guardian — Rate Limiter utility (section 8.2).

Utilisé en interne par les collecteurs pour respecter les rate limits
des APIs externes (section 7.1).
"""

from __future__ import annotations

import asyncio
import time
from dataclasses import dataclass, field


@dataclass
class InMemoryRateLimiter:
    """Rate limiter in-memory pour les collecteurs."""

    max_requests: int
    window_seconds: float
    _timestamps: list[float] = field(default_factory=list)

    async def acquire(self) -> None:
        """Attend si nécessaire pour respecter le rate limit."""
        now = time.monotonic()
        # Nettoyer les timestamps hors fenêtre
        self._timestamps = [
            t for t in self._timestamps
            if now - t < self.window_seconds
        ]

        if len(self._timestamps) >= self.max_requests:
            oldest = self._timestamps[0]
            wait_time = self.window_seconds - (now - oldest)
            if wait_time > 0:
                await asyncio.sleep(wait_time)

        self._timestamps.append(time.monotonic())


# Rate limiters pré-configurés (section 7.1)
nvd_limiter = InMemoryRateLimiter(max_requests=5, window_seconds=30)
github_limiter = InMemoryRateLimiter(max_requests=5000, window_seconds=3600)
reddit_limiter = InMemoryRateLimiter(max_requests=60, window_seconds=60)
