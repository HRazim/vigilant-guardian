"""
Vigilant Guardian — Tests unitaires des collecteurs (section 7.1).

Utilise le mocking des APIs externes pour tester sans appels réseau.
Commande : poetry run pytest tests/unit/test_collectors.py -v
"""

from __future__ import annotations

from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch, MagicMock

import pytest


class TestNVDCollector:
    """Tests du collecteur NVD (section 7.1.1)."""

    @pytest.mark.asyncio
    async def test_collect_parses_nvd_response(self):
        """Vérifie le parsing de la réponse NVD API 2.0."""
        from src.collectors.nvd_collector import NVDCollector

        mock_response = {
            "totalResults": 1,
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-12345",
                        "published": "2024-03-15T10:00:00",
                        "lastModified": "2024-03-15T12:00:00",
                        "descriptions": [
                            {"lang": "en", "value": "A critical use-after-free vulnerability in Apache"}
                        ],
                        "references": [{"url": "https://nvd.nist.gov/vuln/detail/CVE-2024-12345"}],
                        "weaknesses": [{"description": [{"value": "CWE-416"}]}],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
                        },
                    }
                }
            ],
        }

        collector = NVDCollector()

        with patch("httpx.AsyncClient") as MockClient:
            mock_client_instance = AsyncMock()
            mock_resp = AsyncMock()
            mock_resp.json.return_value = mock_response
            mock_resp.raise_for_status = MagicMock()
            mock_client_instance.get.return_value = mock_resp
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock()
            MockClient.return_value = mock_client_instance

            since = datetime(2024, 3, 15, tzinfo=timezone.utc)
            signals = await collector.collect(since)

            assert len(signals) == 1
            assert signals[0].source == "nvd"
            assert signals[0].source_id == "CVE-2024-12345"
            assert "use-after-free" in signals[0].content.lower()
            assert signals[0].metadata["cve_id"] == "CVE-2024-12345"

    @pytest.mark.asyncio
    async def test_collect_handles_empty_response(self):
        """Vérifie la gestion d'une réponse NVD vide."""
        from src.collectors.nvd_collector import NVDCollector

        collector = NVDCollector()

        with patch("httpx.AsyncClient") as MockClient:
            mock_client_instance = AsyncMock()
            mock_resp = AsyncMock()
            mock_resp.json.return_value = {"totalResults": 0, "vulnerabilities": []}
            mock_resp.raise_for_status = MagicMock()
            mock_client_instance.get.return_value = mock_resp
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock()
            MockClient.return_value = mock_client_instance

            since = datetime(2024, 3, 15, tzinfo=timezone.utc)
            signals = await collector.collect(since)
            assert signals == []


class TestGitHubCollector:
    """Tests du collecteur GitHub (section 7.1)."""

    @pytest.mark.asyncio
    async def test_collect_parses_issues(self):
        """Vérifie le parsing des issues GitHub."""
        from src.collectors.github_collector import GitHubCollector

        mock_issues_response = {
            "items": [
                {
                    "id": 12345,
                    "title": "Security: Use-after-free in HTTP parser",
                    "body": "A critical vulnerability was found...",
                    "html_url": "https://github.com/test/repo/issues/1",
                    "repository_url": "https://api.github.com/repos/test/repo",
                    "labels": [{"name": "security"}],
                    "created_at": "2024-03-15T10:00:00Z",
                    "state": "open",
                }
            ]
        }

        collector = GitHubCollector()

        with patch("httpx.AsyncClient") as MockClient:
            mock_client_instance = AsyncMock()
            mock_resp = AsyncMock()
            mock_resp.json.return_value = mock_issues_response
            mock_resp.raise_for_status = MagicMock()
            mock_client_instance.get.return_value = mock_resp
            mock_client_instance.__aenter__ = AsyncMock(return_value=mock_client_instance)
            mock_client_instance.__aexit__ = AsyncMock()
            MockClient.return_value = mock_client_instance

            since = datetime(2024, 3, 15, tzinfo=timezone.utc)
            signals = await collector.collect(since)

            assert len(signals) >= 1
            assert signals[0].source == "github"
            assert "use-after-free" in signals[0].content.lower()


class TestBaseCollector:
    """Tests de la classe abstraite BaseCollector."""

    def test_normalize_creates_raw_signal_data(self):
        from src.collectors.base import BaseCollector

        # On ne peut pas instancier directement, mais on peut tester via sous-classe
        class ConcreteCollector(BaseCollector):
            async def collect(self, since):
                return []

        collector = ConcreteCollector()
        raw = {"id": "test-123", "description": "Test vulnerability"}
        signal = collector.normalize(raw, source="test")

        assert signal.source == "test"
        assert signal.source_id == "test-123"
        assert "test vulnerability" in signal.content.lower()
