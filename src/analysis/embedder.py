"""
Vigilant Guardian — Embedder (section 7.2.1).

Sentence-BERT (all-MiniLM-L6-v2) génère des vecteurs 384 dimensions
indexés dans FAISS (IndexFlatIP).
"""

from __future__ import annotations

import numpy as np
from numpy.typing import NDArray

from src.config.logging import get_logger

logger = get_logger(__name__)

# Chargement paresseux du modèle (80 MB — section 3.1)
_model = None


def _get_model():
    """Charge le modèle Sentence-BERT au premier appel."""
    global _model
    if _model is None:
        from sentence_transformers import SentenceTransformer

        logger.info("loading_sentence_bert", model="all-MiniLM-L6-v2")
        _model = SentenceTransformer("all-MiniLM-L6-v2")
        logger.info("sentence_bert_loaded")
    return _model


def compute_embeddings(texts: list[str]) -> list[NDArray[np.float32]]:
    """
    Calcule les embeddings 384D pour une liste de textes.

    Args:
        texts: textes normalisés.

    Returns:
        Liste de vecteurs numpy float32 de dimension 384.
    """
    if not texts:
        return []

    model = _get_model()
    embeddings = model.encode(
        texts,
        batch_size=64,
        show_progress_bar=False,
        normalize_embeddings=True,  # Pour cosine similarity via dot product
    )
    return [np.array(emb, dtype=np.float32) for emb in embeddings]


def compute_single_embedding(text: str) -> NDArray[np.float32]:
    """Calcule l'embedding d'un seul texte."""
    model = _get_model()
    embedding = model.encode(
        text,
        show_progress_bar=False,
        normalize_embeddings=True,
    )
    return np.array(embedding, dtype=np.float32)
