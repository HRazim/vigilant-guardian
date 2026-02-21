"""
Vigilant Guardian — Tâches Celery d'analyse (sections 7.2, 7.3, 7.4).

Pipeline : Signals non traités → NLP → Clustering → RAG + LLM → Scoring → Alert
"""

from __future__ import annotations

import asyncio
from celery.utils.log import get_task_logger

from src.workers.celery_app import celery_app

logger = get_task_logger(__name__)


def _run_async(coro):
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


@celery_app.task(
    bind=True,
    name="src.workers.tasks_analyze.run_analysis_pipeline",
    max_retries=2,
    default_retry_delay=300,
)
def run_analysis_pipeline(self):
    """
    Pipeline d'analyse complet (sections 7.2 → 7.4).

    1. Récupérer les signaux non traités (processed=False)
    2. Normalisation + Embedding (Sentence-BERT)
    3. Déduplication sémantique
    4. Extraction d'entités (spaCy)
    5. Clustering HDBSCAN
    6. Pour chaque nouveau cluster :
       a. Enrichissement RAG (ChromaDB)
       b. Raisonnement LLM (prompt structuré)
       c. Filtrage guardrails
       d. Scoring multi-critères
       e. Création alerte
    """
    logger.info("Starting analysis pipeline")

    try:
        async def _pipeline():
            from sqlalchemy import select, update
            from src.models.base import AsyncSessionLocal
            from src.models.signal import RawSignal, ProcessedSignal
            from src.models.alert import Alert
            from src.analysis.normalizer import normalize_text
            from src.analysis.embedder import compute_embeddings
            from src.analysis.deduplicator import deduplicate
            from src.analysis.entity_extractor import extract_entities
            from src.analysis.clusterer import cluster_signals
            from src.intelligence.rag_engine import retrieve_context
            from src.intelligence.llm_client import generate_insight
            from src.intelligence.guardrails import filter_output
            from src.intelligence.scorer import compute_priority_score

            async with AsyncSessionLocal() as session:
                # 1. Récupérer signaux non traités
                result = await session.execute(
                    select(RawSignal)
                    .where(RawSignal.processed == False)  # noqa: E712
                    .limit(500)
                )
                raw_signals = result.scalars().all()

                if not raw_signals:
                    logger.info("No unprocessed signals found")
                    return {"processed": 0, "alerts_created": 0}

                logger.info(f"Processing {len(raw_signals)} signals")

                # 2. Normalisation
                texts = [normalize_text(s.content) for s in raw_signals]

                # 3. Embedding
                embeddings = compute_embeddings(texts)

                # 4. Déduplication
                unique_indices = deduplicate(embeddings, threshold=0.92)
                unique_signals = [raw_signals[i] for i in unique_indices]
                unique_embeddings = [embeddings[i] for i in unique_indices]
                unique_texts = [texts[i] for i in unique_indices]

                # 5. Extraction d'entités
                all_entities = extract_entities(unique_texts)

                # 6. Clustering HDBSCAN
                cluster_labels = cluster_signals(
                    unique_embeddings, min_cluster_size=5, min_samples=2
                )

                # 7. Stocker ProcessedSignal
                for i, sig in enumerate(unique_signals):
                    processed = ProcessedSignal(
                        raw_signal_id=sig.id,
                        entities=all_entities[i],
                        cluster_id=int(cluster_labels[i]) if cluster_labels[i] >= 0 else None,
                        embedding_ref=f"faiss:{sig.id}",
                    )
                    session.add(processed)
                    sig.processed = True

                # 8. Générer alertes pour nouveaux clusters
                alerts_created = 0
                seen_clusters = set()

                for i, label in enumerate(cluster_labels):
                    if label < 0 or label in seen_clusters:
                        continue
                    seen_clusters.add(label)

                    # Signaux du cluster
                    cluster_texts = [
                        unique_texts[j]
                        for j, l in enumerate(cluster_labels)
                        if l == label
                    ]
                    cluster_entities = [
                        e for j, ents in enumerate(all_entities)
                        for e in ents if cluster_labels[j] == label
                    ]

                    # RAG enrichissement
                    rag_context = await retrieve_context(
                        cluster_texts[0], cluster_entities
                    )

                    # LLM reasoning
                    insight = await generate_insight(
                        signal_content="\n".join(cluster_texts[:5]),
                        entities=cluster_entities,
                        rag_context=rag_context,
                    )

                    if insight is None:
                        continue

                    # Guardrails (section 8.1)
                    filtered = filter_output(insight)
                    if filtered is None:
                        logger.warning(f"Cluster {label} rejected by guardrails")
                        continue

                    # Scoring (section 7.4)
                    score, category = compute_priority_score({
                        "entities": cluster_entities,
                        "insight": filtered,
                        "signal_count": len(cluster_texts),
                    })

                    # Déterminer le statut (section 8.1 étape 3)
                    status = "pending_review" if category in ("CRITICAL", "HIGH") else "active"

                    alert = Alert(
                        cluster_id=int(label),
                        title=filtered.get("vulnerability_type", "Unknown vulnerability"),
                        vulnerability_type=filtered.get("vulnerability_type"),
                        attack_vector=filtered.get("attack_vector"),
                        business_impact=filtered.get("business_impact"),
                        defensive_measures=filtered.get("defensive_measures", []),
                        confidence_score=filtered.get("confidence_score"),
                        priority_score=score,
                        category=category,
                        justification=filtered.get("justification", ""),
                        llm_model_used=filtered.get("model_used", "unknown"),
                        status=status,
                    )
                    session.add(alert)
                    alerts_created += 1

                await session.commit()

                logger.info(
                    f"Pipeline complete: {len(unique_signals)} processed, "
                    f"{alerts_created} alerts created"
                )
                return {
                    "processed": len(unique_signals),
                    "alerts_created": alerts_created,
                }

        return _run_async(_pipeline())

    except Exception as exc:
        logger.error(f"Analysis pipeline failed: {exc}")
        raise self.retry(exc=exc)
