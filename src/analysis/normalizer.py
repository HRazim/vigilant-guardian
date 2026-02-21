"""
Vigilant Guardian — Normalizer (section 7.2.1).

Pipeline NLP étape 1 : unification des formats.
- HTML strip
- Unicode normalize
- Lowercase
- Suppression URLs/mentions
"""

from __future__ import annotations

import re
import unicodedata
from html import unescape


# Patterns compilés
_URL_PATTERN = re.compile(r"https?://\S+|www\.\S+")
_MENTION_PATTERN = re.compile(r"@\w+")
_MULTIPLE_SPACES = re.compile(r"\s+")
_HTML_TAG_PATTERN = re.compile(r"<[^>]+>")


def normalize_text(text: str) -> str:
    """
    Normalise un texte brut pour le pipeline NLP (section 7.2.1).

    Étapes :
    1. Décoder les entités HTML
    2. Supprimer les balises HTML
    3. Normaliser l'unicode (NFKD)
    4. Supprimer les URLs
    5. Supprimer les @mentions
    6. Mettre en minuscules
    7. Fusionner les espaces multiples
    """
    if not text:
        return ""

    # 1. HTML unescape
    text = unescape(text)

    # 2. Strip HTML tags
    text = _HTML_TAG_PATTERN.sub(" ", text)

    # 3. Unicode normalize
    text = unicodedata.normalize("NFKD", text)

    # 4. Remove URLs
    text = _URL_PATTERN.sub(" ", text)

    # 5. Remove @mentions
    text = _MENTION_PATTERN.sub(" ", text)

    # 6. Lowercase
    text = text.lower()

    # 7. Collapse whitespace
    text = _MULTIPLE_SPACES.sub(" ", text).strip()

    return text
