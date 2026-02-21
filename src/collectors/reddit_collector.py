"""
Vigilant Guardian — Reddit Collector (section 7.1).

Surveille les subreddits de cybersécurité pour les signaux faibles.
Fréquence : toutes les 60 min.
Rate limit : 60 req/min.
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from src.collectors.base import BaseCollector, RawSignalData
from src.config.logging import get_logger

logger = get_logger(__name__)

SECURITY_SUBREDDITS = [
    "netsec",
    "cybersecurity",
    "hacking",
    "InfoSecNews",
    "AskNetsec",
]


class RedditCollector(BaseCollector):
    """Collecteur Reddit via OAuth2 API (section 7.1)."""

    AUTH_URL = "https://www.reddit.com/api/v1/access_token"
    API_BASE = "https://oauth.reddit.com"

    async def _get_token(self, client: httpx.AsyncClient) -> str | None:
        """Obtient un access token Reddit via OAuth2 client credentials."""
        if not self.config.reddit_client_id or not self.config.reddit_client_secret:
            self.logger.warning("reddit_credentials_missing")
            return None

        resp = await client.post(
            self.AUTH_URL,
            data={"grant_type": "client_credentials"},
            auth=(self.config.reddit_client_id, self.config.reddit_client_secret),
            headers={"User-Agent": "VigilantGuardian/0.1 (security research)"},
            timeout=10,
        )
        resp.raise_for_status()
        return resp.json().get("access_token")

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
    )
    async def _fetch_subreddit(
        self,
        client: httpx.AsyncClient,
        subreddit: str,
        token: str,
        since: datetime,
    ) -> list[dict]:
        """Récupère les posts récents d'un subreddit."""
        headers = {
            "Authorization": f"Bearer {token}",
            "User-Agent": "VigilantGuardian/0.1 (security research)",
        }
        resp = await client.get(
            f"{self.API_BASE}/r/{subreddit}/new",
            params={"limit": 50, "t": "day"},
            headers=headers,
            timeout=15,
        )
        resp.raise_for_status()
        data = resp.json()

        since_ts = since.timestamp()
        posts = []
        for child in data.get("data", {}).get("children", []):
            post = child.get("data", {})
            if post.get("created_utc", 0) >= since_ts:
                posts.append(post)

        return posts

    async def collect(self, since: datetime) -> list[RawSignalData]:
        """Collecte les posts sécurité depuis les subreddits surveillés."""
        signals: list[RawSignalData] = []

        async with httpx.AsyncClient() as client:
            token = await self._get_token(client)
            if not token:
                return signals

            for subreddit in SECURITY_SUBREDDITS:
                try:
                    posts = await self._fetch_subreddit(client, subreddit, token, since)
                    for post in posts:
                        post_id = post.get("id", "")
                        title = post.get("title", "")
                        body = post.get("selftext", "")[:2000]

                        signals.append(RawSignalData(
                            source="reddit",
                            source_id=f"reddit-{post_id}",
                            content=f"{title}\n{body}",
                            metadata={
                                "subreddit": subreddit,
                                "url": f"https://reddit.com{post.get('permalink', '')}",
                                "score": post.get("score", 0),
                                "num_comments": post.get("num_comments", 0),
                                "author": post.get("author", ""),
                                "created_utc": post.get("created_utc", 0),
                                "flair": post.get("link_flair_text", ""),
                            },
                        ))
                except Exception as exc:
                    self.logger.error(
                        "reddit_subreddit_error",
                        subreddit=subreddit,
                        error=str(exc),
                    )

        self.logger.info("reddit_collection_complete", count=len(signals))
        return signals
