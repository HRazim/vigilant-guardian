"""
Vigilant Guardian — Twitter/X Collector (section 7.1).

Recherche de tweets liés à la cybersécurité via l'API v2.
Fréquence : toutes les 60 min.
Rate limit : 500k tweets/mois (Basic tier).
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from src.collectors.base import BaseCollector, RawSignalData
from src.config.logging import get_logger

logger = get_logger(__name__)

SECURITY_QUERIES = [
    "(vulnerability OR CVE OR 0day OR zero-day) -is:retweet lang:en",
    "(exploit OR RCE OR remote code execution) -is:retweet lang:en",
]


class TwitterCollector(BaseCollector):
    """Collecteur Twitter/X via API v2 (section 7.1)."""

    API_BASE = "https://api.twitter.com/2"

    def _get_headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self.config.twitter_bearer_token}",
        }

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=5, max=30),
    )
    async def _search_recent(
        self,
        client: httpx.AsyncClient,
        query: str,
        since: datetime,
    ) -> list[dict]:
        """Recherche les tweets récents via l'endpoint /search/recent."""
        params = {
            "query": query,
            "max_results": 50,
            "start_time": since.strftime("%Y-%m-%dT%H:%M:%SZ"),
            "tweet.fields": "created_at,author_id,public_metrics,entities",
        }
        resp = await client.get(
            f"{self.API_BASE}/tweets/search/recent",
            params=params,
            headers=self._get_headers(),
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("data", [])

    async def collect(self, since: datetime) -> list[RawSignalData]:
        """Collecte les tweets de cybersécurité."""
        signals: list[RawSignalData] = []

        if not self.config.twitter_bearer_token:
            self.logger.warning("twitter_bearer_token_missing")
            return signals

        async with httpx.AsyncClient() as client:
            for query in SECURITY_QUERIES:
                try:
                    tweets = await self._search_recent(client, query, since)
                    for tweet in tweets:
                        tweet_id = tweet.get("id", "")
                        signals.append(RawSignalData(
                            source="twitter",
                            source_id=f"tweet-{tweet_id}",
                            content=tweet.get("text", ""),
                            metadata={
                                "author_id": tweet.get("author_id", ""),
                                "created_at": tweet.get("created_at", ""),
                                "metrics": tweet.get("public_metrics", {}),
                                "entities": tweet.get("entities", {}),
                                "url": f"https://twitter.com/i/status/{tweet_id}",
                            },
                        ))
                except httpx.HTTPStatusError as exc:
                    if exc.response.status_code == 429:
                        self.logger.warning("twitter_rate_limit_hit")
                        break
                    self.logger.error("twitter_api_error", status=exc.response.status_code)
                except Exception as exc:
                    self.logger.error("twitter_search_error", error=str(exc))

        self.logger.info("twitter_collection_complete", count=len(signals))
        return signals
