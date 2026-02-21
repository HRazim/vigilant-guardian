"""
Vigilant Guardian — Clusterer HDBSCAN (section 7.2.1).

HDBSCAN (min_cluster_size=5, min_samples=2) regroupe les signaux
par vulnérabilité/technologie similaire.
Pas besoin de spécifier k, gère le bruit (section 3.1).
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from src.config.logging import get_logger

logger = get_logger(__name__)


def cluster_signals(
    embeddings: list[NDArray[np.float32]],
    min_cluster_size: int = 5,
    min_samples: int = 2,
) -> list[int]:
    """
    Regroupe les signaux par similarité sémantique (section 7.2.1).

    Args:
        embeddings: embeddings normalisés des signaux.
        min_cluster_size: taille minimale d'un cluster (default 5).
        min_samples: échantillons min pour un core point (default 2).

    Returns:
        Liste de labels de cluster (-1 = bruit/non-classé).
    """
    if not embeddings or len(embeddings) < min_cluster_size:
        logger.info(
            "insufficient_data_for_clustering",
            count=len(embeddings),
            min_required=min_cluster_size,
        )
        return [-1] * len(embeddings)

    import hdbscan

    matrix = np.stack(embeddings)

    clusterer = hdbscan.HDBSCAN(
        min_cluster_size=min_cluster_size,
        min_samples=min_samples,
        metric="euclidean",
        cluster_selection_method="eom",
        prediction_data=False,
    )

    labels = clusterer.fit_predict(matrix)

    n_clusters = len(set(labels)) - (1 if -1 in labels else 0)
    n_noise = list(labels).count(-1)

    logger.info(
        "clustering_complete",
        total_signals=len(embeddings),
        n_clusters=n_clusters,
        n_noise=n_noise,
    )

    return labels.tolist()
