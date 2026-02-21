"""
Vigilant Guardian — RAG Engine (section 7.3.2).

Moteur RAG récupérant le contexte pertinent depuis ChromaDB
avant chaque appel LLM :
1. Query : embedding du signal → recherche de similarité
2. Retrieval : top-5 par collection, filtrés par score > 0.7
3. Augmentation : résultats formatés pour le prompt
4. Generation : le LLM produit sa réponse contextualisée
"""

from __future__ import annotations

import chromadb
from chromadb.config import Settings as ChromaSettings

from src.config.settings import settings
from src.config.logging import get_logger

logger = get_logger(__name__)

# 4 collections vectorielles (section 6.2)
COLLECTIONS = [
    "cwe_database",        # 930+ types CWE
    "mitre_attack",        # Techniques/tactiques ATT&CK
    "cve_archive",         # CVE 2015-2025
    "defensive_patterns",  # OWASP, NIST
]

_client = None


def _get_chroma_client() -> chromadb.HttpClient:
    """Initialise le client ChromaDB (lazy)."""
    global _client
    if _client is None:
        auth_kwargs = {}
        if settings.chroma_token:
            auth_kwargs = {
                "chroma_client_auth_provider": "chromadb.auth.token_authn.TokenAuthClientProvider",
                "chroma_client_auth_credentials": settings.chroma_token,
            }

        _client = chromadb.HttpClient(
            host=settings.chroma_host,
            port=settings.chroma_port,
            settings=ChromaSettings(
                anonymized_telemetry=False,
                **auth_kwargs,
            ),
        )
    return _client


async def retrieve_context(
    query_text: str,
    entities: list[dict],
    n_results: int = 5,
    min_score: float = 0.7,
) -> str:
    """
    Récupère le contexte RAG depuis les 4 collections ChromaDB (section 7.3.2).

    Args:
        query_text: texte du signal à analyser.
        entities: entités extraites (pour filtrage par metadata).
        n_results: nombre max de résultats par collection (default 5).
        min_score: score de similarité minimum (default 0.7).

    Returns:
        Contexte formaté pour injection dans le prompt LLM.
    """
    context_parts: list[str] = []

    try:
        client = _get_chroma_client()

        # Construire les filtres metadata à partir des entités
        cwe_ids = [e["value"] for e in entities if e.get("type") == "cwe_id"]

        for collection_name in COLLECTIONS:
            try:
                collection = client.get_or_create_collection(name=collection_name)

                # Requête de similarité
                where_filter = None
                if collection_name == "cwe_database" and cwe_ids:
                    where_filter = {"cwe_id": {"$in": cwe_ids}}

                results = collection.query(
                    query_texts=[query_text],
                    n_results=n_results,
                    where=where_filter,
                    include=["documents", "distances", "metadatas"],
                )

                documents = results.get("documents", [[]])[0]
                distances = results.get("distances", [[]])[0]
                metadatas = results.get("metadatas", [[]])[0]

                for doc, dist, meta in zip(documents, distances, metadatas):
                    # ChromaDB renvoie des distances (plus petit = plus proche)
                    # Convertir en score de similarité
                    score = 1.0 - (dist / 2.0) if dist is not None else 0.0
                    if score >= min_score:
                        source_info = meta.get("source", collection_name) if meta else collection_name
                        context_parts.append(
                            f"[{collection_name}] (score={score:.2f}) {doc[:500]}"
                        )

            except Exception as exc:
                logger.warning(
                    "rag_collection_error",
                    collection=collection_name,
                    error=str(exc),
                )

    except Exception as exc:
        logger.error("rag_engine_error", error=str(exc))

    if not context_parts:
        return "Aucun contexte RAG disponible."

    context = "\n\n".join(context_parts)
    logger.info(
        "rag_context_retrieved",
        n_results=len(context_parts),
        total_chars=len(context),
    )
    return context
