"""
Vigilant Guardian — Deduplicator (section 7.2.1).

Déduplication sémantique : cosine similarity > 0.92 entre embeddings
= doublon.  Hash sémantique stocké pour lookup rapide.
"""

from __future__ import annotations

import hashlib

import numpy as np
from numpy.typing import NDArray

from src.config.logging import get_logger

logger = get_logger(__name__)


def deduplicate(
    embeddings: list[NDArray[np.float32]],
    threshold: float = 0.92,
) -> list[int]:
    """
    Retourne les indices des signaux uniques (non-doublons).

    Args:
        embeddings: liste d'embeddings normalisés.
        threshold: seuil de similarité (default 0.92, section 7.2.1).

    Returns:
        Liste d'indices des signaux uniques.
    """
    if not embeddings:
        return []

    n = len(embeddings)
    if n == 1:
        return [0]

    matrix = np.stack(embeddings)
    sim_matrix = matrix @ matrix.T

    is_duplicate = [False] * n

    for i in range(n):
        if is_duplicate[i]:
            continue
        for j in range(i + 1, n):
            if is_duplicate[j]:
                continue
            if sim_matrix[i, j] > threshold:
                is_duplicate[j] = True

    unique_indices = [i for i in range(n) if not is_duplicate[i]]
    logger.info(
        "deduplication_complete",
        total=n,
        unique=len(unique_indices),
        removed=n - len(unique_indices),
    )
    return unique_indices


def compute_semantic_hash(embedding: NDArray[np.float32]) -> str:
    """Calcule un hash sémantique pour lookup rapide en DB."""
    bits = (embedding > 0).astype(np.uint8)
    bit_string = bits.tobytes()
    return hashlib.sha256(bit_string).hexdigest()
