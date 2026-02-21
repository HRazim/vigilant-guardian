"""
Vigilant Guardian — Mailing List Collector (section 7.1).

Scrape les archives HTTP des mailing lists de sécurité.
Fréquence : quotidien.
Rate limit : respecter robots.txt, 1 req/2s.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
from bs4 import BeautifulSoup
from tenacity import retry, stop_after_attempt, wait_fixed

from src.collectors.base import BaseCollector, RawSignalData
from src.config.logging import get_logger

logger = get_logger(__name__)

# Archives publiques de mailing lists de sécurité
MAILING_LIST_ARCHIVES = [
    {
        "name": "oss-security",
        "url": "https://www.openwall.com/lists/oss-security/",
        "type": "openwall",
    },
    {
        "name": "fulldisclosure",
        "url": "https://seclists.org/fulldisclosure/",
        "type": "seclists",
    },
    {
        "name": "bugtraq",
        "url": "https://seclists.org/bugtraq/",
        "type": "seclists",
    },
]


class MailingListCollector(BaseCollector):
    """Collecteur Mailing Lists via archives HTTP (section 7.1)."""

    @retry(stop=stop_after_attempt(2), wait=wait_fixed(3))
    async def _fetch_page(self, client: httpx.AsyncClient, url: str) -> str:
        """Fetch une page en respectant le rate limit (1 req/2s)."""
        resp = await client.get(
            url,
            headers={"User-Agent": "VigilantGuardian/0.1 (security research)"},
            timeout=20,
            follow_redirects=True,
        )
        resp.raise_for_status()
        await asyncio.sleep(2)  # 1 req/2s (section 7.1)
        return resp.text

    def _parse_openwall(self, html: str, list_name: str) -> list[RawSignalData]:
        """Parse les messages depuis les archives Openwall."""
        soup = BeautifulSoup(html, "html.parser")
        signals: list[RawSignalData] = []

        # Les messages Openwall sont dans des <a> avec href vers le message
        for link in soup.select("a[href*='/']")[:20]:
            title = link.get_text(strip=True)
            if len(title) < 10:
                continue

            href = link.get("href", "")
            msg_id = href.strip("/").replace("/", "-")

            signals.append(RawSignalData(
                source="mailinglist",
                source_id=f"ml-{list_name}-{msg_id}",
                content=title,
                metadata={
                    "list": list_name,
                    "url": href if href.startswith("http") else f"https://www.openwall.com/lists/{list_name}/{href}",
                },
            ))

        return signals

    def _parse_seclists(self, html: str, list_name: str) -> list[RawSignalData]:
        """Parse les messages depuis les archives SecLists."""
        soup = BeautifulSoup(html, "html.parser")
        signals: list[RawSignalData] = []

        for item in soup.select("li a")[:20]:
            title = item.get_text(strip=True)
            if len(title) < 10:
                continue

            href = item.get("href", "")
            msg_id = href.strip("/").replace("/", "-")

            signals.append(RawSignalData(
                source="mailinglist",
                source_id=f"ml-{list_name}-{msg_id}",
                content=title,
                metadata={
                    "list": list_name,
                    "url": href if href.startswith("http") else f"https://seclists.org/{list_name}/{href}",
                },
            ))

        return signals

    async def collect(self, since: datetime) -> list[RawSignalData]:
        """Collecte depuis les archives de mailing lists."""
        signals: list[RawSignalData] = []

        async with httpx.AsyncClient() as client:
            for ml in MAILING_LIST_ARCHIVES:
                try:
                    html = await self._fetch_page(client, ml["url"])

                    if ml["type"] == "openwall":
                        parsed = self._parse_openwall(html, ml["name"])
                    elif ml["type"] == "seclists":
                        parsed = self._parse_seclists(html, ml["name"])
                    else:
                        parsed = []

                    signals.extend(parsed)
                    self.logger.info(
                        "ml_archive_fetched",
                        list=ml["name"],
                        count=len(parsed),
                    )
                except Exception as exc:
                    self.logger.error(
                        "ml_archive_error",
                        list=ml["name"],
                        error=str(exc),
                    )

        self.logger.info("mailinglist_collection_complete", count=len(signals))
        return signals
