"""
Vigilant Guardian — RAG Knowledge Base Ingestion (section 6.2, 7.3.2).

Ingère les bases de connaissances dans ChromaDB :
- cwe_database       : 930+ types CWE
- mitre_attack       : Techniques ATT&CK
- cve_archive        : CVE 2015-2025
- defensive_patterns : OWASP, NIST

Usage : python -m knowledge_base.ingest
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import chromadb

from src.config.settings import settings
from src.config.logging import setup_logging, get_logger

logger = get_logger(__name__)

KB_ROOT = Path(__file__).parent


def get_chroma_client() -> chromadb.HttpClient:
    """Connexion au serveur ChromaDB."""
    return chromadb.HttpClient(
        host=settings.chroma_host,
        port=settings.chroma_port,
    )


def ingest_cwe(client: chromadb.HttpClient) -> int:
    """Ingère les fichiers CWE dans la collection cwe_database."""
    collection = client.get_or_create_collection("cwe_database")
    cwe_dir = KB_ROOT / "cwe"
    count = 0

    if not cwe_dir.exists():
        logger.warning("cwe_directory_not_found", path=str(cwe_dir))
        return 0

    for filepath in sorted(cwe_dir.glob("*.md")):
        content = filepath.read_text(encoding="utf-8")
        cwe_id = filepath.stem.upper()

        collection.upsert(
            ids=[cwe_id],
            documents=[content],
            metadatas=[{
                "cwe_id": cwe_id,
                "source": "cwe_database",
                "severity": "unknown",
                "category": "general",
            }],
        )
        count += 1

    logger.info("cwe_ingestion_complete", count=count)
    return count


def ingest_mitre_attack(client: chromadb.HttpClient) -> int:
    """Ingère les techniques ATT&CK dans la collection mitre_attack."""
    collection = client.get_or_create_collection("mitre_attack")
    attack_dir = KB_ROOT / "mitre_attack"
    count = 0

    if not attack_dir.exists():
        logger.warning("mitre_attack_directory_not_found", path=str(attack_dir))
        return 0

    for filepath in sorted(attack_dir.glob("*.md")):
        content = filepath.read_text(encoding="utf-8")
        technique_id = filepath.stem.upper()

        collection.upsert(
            ids=[technique_id],
            documents=[content],
            metadatas=[{
                "technique_id": technique_id,
                "source": "mitre_attack",
                "tactic": "unknown",
                "platform": "general",
            }],
        )
        count += 1

    logger.info("mitre_attack_ingestion_complete", count=count)
    return count


def ingest_owasp(client: chromadb.HttpClient) -> int:
    """Ingère les patterns défensifs OWASP/NIST dans defensive_patterns."""
    collection = client.get_or_create_collection("defensive_patterns")
    owasp_dir = KB_ROOT / "owasp"
    count = 0

    if not owasp_dir.exists():
        logger.warning("owasp_directory_not_found", path=str(owasp_dir))
        return 0

    for filepath in sorted(owasp_dir.glob("*.md")):
        content = filepath.read_text(encoding="utf-8")
        doc_id = f"owasp-{filepath.stem}"

        collection.upsert(
            ids=[doc_id],
            documents=[content],
            metadatas=[{
                "source": "owasp",
                "category": filepath.stem,
                "last_updated": "2026-01",
            }],
        )
        count += 1

    logger.info("owasp_ingestion_complete", count=count)
    return count


def run_ingestion() -> dict:
    """Exécute l'ingestion complète de la knowledge base."""
    setup_logging()
    logger.info("starting_knowledge_base_ingestion")

    client = get_chroma_client()

    results = {
        "cwe": ingest_cwe(client),
        "mitre_attack": ingest_mitre_attack(client),
        "owasp": ingest_owasp(client),
    }

    logger.info("knowledge_base_ingestion_complete", results=results)
    return results


if __name__ == "__main__":
    run_ingestion()
