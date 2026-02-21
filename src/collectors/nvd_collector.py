"""
Vigilant Guardian — NVD Collector (section 7.1.1).

Collecteur NVD/CVE via l'API officielle 2.0.
Fréquence : toutes les 15 min.
Rate limit : 5 req/30s (avec API key).
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone

import httpx
from tenacity import retry, stop_after_attempt, wait_exponential

from src.collectors.base import BaseCollector, RawSignalData
from src.config.logging import get_logger

logger = get_logger(__name__)


class NVDCollector(BaseCollector):
    """Collecteur NVD/CVE via API officielle 2.0."""

    BASE_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=4, max=30),
    )
    async def _fetch_page(
        self,
        client: httpx.AsyncClient,
        params: dict,
        headers: dict,
    ) -> dict:
        """Fetch une page avec retry exponentiel et respect du rate limit."""
        resp = await client.get(self.BASE_URL, params=params, headers=headers, timeout=30)
        resp.raise_for_status()
        # Respecter le rate limit NVD : 5 req/30s → ~6s entre requêtes
        await asyncio.sleep(6)
        return resp.json()

    async def collect(self, since: datetime) -> list[RawSignalData]:
        """
        Collecte les CVE modifiées depuis `since` (section 7.1.1).

        Gère la pagination NVD (resultsPerPage=100).
        """
        signals: list[RawSignalData] = []
        start_index = 0
        page_size = 100

        params = {
            "lastModStartDate": since.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "lastModEndDate": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            ),
            "resultsPerPage": page_size,
        }
        headers: dict[str, str] = {}
        if self.config.nvd_api_key:
            headers["apiKey"] = self.config.nvd_api_key

        async with httpx.AsyncClient() as client:
            while True:
                params["startIndex"] = start_index
                self.logger.info(
                    "nvd_fetch_page",
                    start_index=start_index,
                    since=since.isoformat(),
                )

                try:
                    data = await self._fetch_page(client, params, headers)
                except httpx.HTTPStatusError as exc:
                    self.logger.error(
                        "nvd_api_error",
                        status=exc.response.status_code,
                        detail=exc.response.text[:200],
                    )
                    break

                vulnerabilities = data.get("vulnerabilities", [])
                if not vulnerabilities:
                    break

                for vuln_wrapper in vulnerabilities:
                    cve = vuln_wrapper.get("cve", {})
                    cve_id = cve.get("id", "")
                    descriptions = cve.get("descriptions", [])
                    # Préférer la description en anglais
                    content = next(
                        (d["value"] for d in descriptions if d.get("lang") == "en"),
                        descriptions[0]["value"] if descriptions else "",
                    )

                    if not content:
                        continue

                    # Extraction des métriques CVSS
                    metrics = cve.get("metrics", {})
                    cvss_v31 = metrics.get("cvssMetricV31", [{}])
                    cvss_data = cvss_v31[0] if cvss_v31 else {}

                    signal = RawSignalData(
                        source="nvd",
                        source_id=cve_id,
                        content=content,
                        metadata={
                            "cve_id": cve_id,
                            "published": cve.get("published", ""),
                            "last_modified": cve.get("lastModified", ""),
                            "cvss_v31": cvss_data,
                            "references": cve.get("references", []),
                            "weaknesses": cve.get("weaknesses", []),
                        },
                    )
                    signals.append(signal)

                total_results = data.get("totalResults", 0)
                start_index += page_size
                if start_index >= total_results:
                    break

        self.logger.info("nvd_collection_complete", count=len(signals))
        return signals
