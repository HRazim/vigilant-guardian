"""
Vigilant Guardian — Entity Extractor (section 7.2.1).

spaCy avec modèle en_core_web_lg + patterns custom pour extraire :
SOFTWARE, VERSION, CWE_ID, CVE_ID, VENDOR.
"""

from __future__ import annotations

import re

from src.config.logging import get_logger

logger = get_logger(__name__)

# Chargement paresseux du modèle spaCy
_nlp = None

# Patterns regex pour les entités spécialisées cybersécurité
_CVE_PATTERN = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CWE_PATTERN = re.compile(r"CWE-\d{1,4}", re.IGNORECASE)
_VERSION_PATTERN = re.compile(
    r"\b\d+\.\d+(?:\.\d+)*(?:[-_.]\w+)?\b"
)
_KNOWN_VENDORS = {
    "apache", "microsoft", "google", "linux", "cisco", "oracle",
    "mozilla", "apple", "adobe", "vmware", "fortinet", "palo alto",
    "nginx", "openssl", "openssh", "wordpress", "drupal", "joomla",
    "kubernetes", "docker", "jenkins", "gitlab", "redis", "postgresql",
    "mysql", "mongodb", "elastic", "splunk", "crowdstrike",
}


def _get_nlp():
    """Charge le modèle spaCy au premier appel."""
    global _nlp
    if _nlp is None:
        import spacy

        logger.info("loading_spacy_model", model="en_core_web_lg")
        try:
            _nlp = spacy.load("en_core_web_lg")
        except OSError:
            logger.warning("spacy_lg_not_found, falling back to en_core_web_sm")
            try:
                _nlp = spacy.load("en_core_web_sm")
            except OSError:
                logger.error("no_spacy_model_available")
                _nlp = None
    return _nlp


def extract_entities(texts: list[str]) -> list[list[dict]]:
    """
    Extrait les entités de chaque texte (section 7.2.1).

    Types extraits :
    - CVE_ID   : via regex CVE-YYYY-NNNNN
    - CWE_ID   : via regex CWE-NNN
    - SOFTWARE  : via spaCy NER (ORG, PRODUCT) + vendors connus
    - VERSION   : via regex version numbers
    - VENDOR    : via dictionnaire de vendors connus

    Returns:
        Liste de listes d'entités [{"type": "...", "value": "..."}].
    """
    nlp = _get_nlp()
    all_entities: list[list[dict]] = []

    for text in texts:
        entities: list[dict] = []
        seen: set[str] = set()

        # 1. CVE IDs
        for match in _CVE_PATTERN.finditer(text):
            val = match.group().upper()
            if val not in seen:
                entities.append({"type": "cve_id", "value": val})
                seen.add(val)

        # 2. CWE IDs
        for match in _CWE_PATTERN.finditer(text):
            val = match.group().upper()
            if val not in seen:
                entities.append({"type": "cwe_id", "value": val})
                seen.add(val)

        # 3. Versions
        for match in _VERSION_PATTERN.finditer(text):
            val = match.group()
            if val not in seen and len(val) > 2:
                entities.append({"type": "version", "value": val})
                seen.add(val)

        # 4. Vendors (dictionnaire)
        text_lower = text.lower()
        for vendor in _KNOWN_VENDORS:
            if vendor in text_lower and vendor not in seen:
                entities.append({"type": "vendor", "value": vendor.title()})
                seen.add(vendor)

        # 5. spaCy NER (SOFTWARE via ORG/PRODUCT)
        if nlp is not None:
            doc = nlp(text[:5000])  # Limiter pour performance
            for ent in doc.ents:
                if ent.label_ in ("ORG", "PRODUCT") and ent.text not in seen:
                    entities.append({"type": "software", "value": ent.text})
                    seen.add(ent.text)

        all_entities.append(entities)

    return all_entities
