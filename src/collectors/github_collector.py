"""
Vigilant Guardian — GitHub Collector (section 7.1).

Collecte les issues et commits liés à la sécurité via l'API GitHub.
Fréquence : toutes les 30 min.
Rate limit : 5000 req/h (auth token).
"""

from __future__ import annotations

from datetime import datetime, timezone

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from src.collectors.base import BaseCollector, RawSignalData
from src.config.logging import get_logger

logger = get_logger(__name__)

# Repos clés à surveiller pour les signaux de sécurité
SECURITY_REPOS = [
    "advisories",  # GitHub Security Advisories
]

# Requêtes de recherche pour trouver des issues/commits liés à la sécurité
SECURITY_QUERIES = [
    "vulnerability fix",
    "CVE-",
    "security patch",
    "use-after-free",
    "buffer overflow",
    "remote code execution",
    "privilege escalation",
]


class GitHubCollector(BaseCollector):
    """Collecteur GitHub issues + commits (section 7.1)."""

    API_BASE = "https://api.github.com"

    def _get_headers(self) -> dict:
        headers = {
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }
        if self.config.github_token:
            headers["Authorization"] = f"Bearer {self.config.github_token}"
        return headers

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=15),
    )
    async def _search_issues(
        self,
        client: httpx.AsyncClient,
        query: str,
        since: datetime,
    ) -> list[dict]:
        """Recherche des issues GitHub liées à la sécurité."""
        params = {
            "q": f"{query} is:issue created:>{since.strftime('%Y-%m-%dT%H:%M:%S')}",
            "sort": "created",
            "order": "desc",
            "per_page": 30,
        }
        resp = await client.get(
            f"{self.API_BASE}/search/issues",
            params=params,
            headers=self._get_headers(),
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("items", [])

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=15),
    )
    async def _search_commits(
        self,
        client: httpx.AsyncClient,
        query: str,
        since: datetime,
    ) -> list[dict]:
        """Recherche des commits liés à la sécurité."""
        params = {
            "q": f"{query} committer-date:>{since.strftime('%Y-%m-%dT%H:%M:%S')}",
            "sort": "committer-date",
            "order": "desc",
            "per_page": 20,
        }
        resp = await client.get(
            f"{self.API_BASE}/search/commits",
            params=params,
            headers={**self._get_headers(), "Accept": "application/vnd.github.cloak-preview+json"},
            timeout=20,
        )
        resp.raise_for_status()
        data = resp.json()
        return data.get("items", [])

    async def collect(self, since: datetime) -> list[RawSignalData]:
        """Collecte issues + commits liés à la sécurité depuis GitHub."""
        signals: list[RawSignalData] = []
        seen_ids: set[str] = set()

        async with httpx.AsyncClient() as client:
            for query in SECURITY_QUERIES[:3]:  # Limiter pour le prototype
                # Issues
                try:
                    issues = await self._search_issues(client, query, since)
                    for issue in issues:
                        uid = f"issue-{issue['id']}"
                        if uid in seen_ids:
                            continue
                        seen_ids.add(uid)

                        signals.append(RawSignalData(
                            source="github",
                            source_id=uid,
                            content=f"{issue.get('title', '')} {issue.get('body', '')[:1000]}",
                            metadata={
                                "type": "issue",
                                "url": issue.get("html_url", ""),
                                "repo": issue.get("repository_url", "").split("/")[-1] if issue.get("repository_url") else "",
                                "labels": [l["name"] for l in issue.get("labels", [])],
                                "created_at": issue.get("created_at", ""),
                                "state": issue.get("state", ""),
                            },
                        ))
                except Exception as exc:
                    self.logger.error("github_issue_search_error", query=query, error=str(exc))

                # Commits
                try:
                    commits = await self._search_commits(client, query, since)
                    for commit in commits:
                        sha = commit.get("sha", "")[:12]
                        uid = f"commit-{sha}"
                        if uid in seen_ids:
                            continue
                        seen_ids.add(uid)

                        commit_data = commit.get("commit", {})
                        signals.append(RawSignalData(
                            source="github",
                            source_id=uid,
                            content=commit_data.get("message", "")[:2000],
                            metadata={
                                "type": "commit",
                                "sha": commit.get("sha", ""),
                                "url": commit.get("html_url", ""),
                                "repo": commit.get("repository", {}).get("full_name", ""),
                                "author": commit_data.get("author", {}).get("name", ""),
                                "date": commit_data.get("author", {}).get("date", ""),
                            },
                        ))
                except Exception as exc:
                    self.logger.error("github_commit_search_error", query=query, error=str(exc))

        self.logger.info("github_collection_complete", count=len(signals))
        return signals
