"""
Vigilant Guardian — Test Fixtures.
"""

from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

import pytest
import pytest_asyncio
from httpx import ASGITransport, AsyncClient

from src.api.main import app


@pytest.fixture(scope="session")
def event_loop():
    """Fournit un event loop pour toute la session de tests."""
    loop = asyncio.new_event_loop()
    yield loop
    loop.close()


@pytest_asyncio.fixture
async def client():
    """Client HTTP async pour tester l'API FastAPI."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as ac:
        yield ac


@pytest.fixture
def sample_raw_signal_data():
    """Données de test pour un signal brut NVD."""
    return {
        "source": "nvd",
        "source_id": "CVE-2024-12345",
        "content": (
            "A use-after-free vulnerability in Apache HTTP Server 2.4.51 "
            "allows remote attackers to execute arbitrary code via crafted "
            "HTTP/2 requests."
        ),
        "metadata": {
            "cve_id": "CVE-2024-12345",
            "published": "2024-03-15T10:00:00",
            "cvss_v31": {"baseScore": 9.8, "baseSeverity": "CRITICAL"},
        },
    }


@pytest.fixture
def sample_entities():
    """Entités extraites de test."""
    return [
        {"type": "cve_id", "value": "CVE-2024-12345"},
        {"type": "software", "value": "Apache HTTP Server"},
        {"type": "version", "value": "2.4.51"},
        {"type": "vendor", "value": "Apache"},
        {"type": "cwe_id", "value": "CWE-416"},
    ]


@pytest.fixture
def sample_llm_output():
    """Sortie LLM de test (conforme section 7.3.1)."""
    return {
        "vulnerability_type": "CWE-416 (Use After Free)",
        "attack_vector": (
            "Remote attacker sends crafted HTTP/2 requests to trigger "
            "use-after-free in memory management. No authentication required."
        ),
        "business_impact": {
            "confidentiality": "HIGH",
            "integrity": "HIGH",
            "availability": "HIGH",
        },
        "defensive_measures": [
            "Update Apache HTTP Server to version 2.4.52 or later",
            "Apply vendor patch immediately",
            "Enable ModSecurity WAF with HTTP/2 ruleset",
            "Monitor for anomalous HTTP/2 traffic patterns",
            "Consider disabling HTTP/2 as temporary mitigation",
        ],
        "confidence_score": 0.92,
        "related_cwe": ["CWE-416", "CWE-787"],
        "related_attack": ["T1190", "T1210"],
    }
