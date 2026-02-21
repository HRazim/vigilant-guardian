"""
Vigilant Guardian — Scorer multi-critères (section 7.4).

Algorithme combinant 5 facteurs pondérés :
- 0.30 × exposure_score    (Internet-facing?)
- 0.25 × popularity_score  (Logiciel répandu?)
- 0.20 × exploitability    (Complexité exploitation)
- 0.15 × patch_availability (Correctif disponible?)
- 0.10 × community_activity (Discussions actives?)

Catégories :
- CRITICAL : score ≥ 80
- HIGH     : score ≥ 60
- MEDIUM   : score ≥ 40
- LOW      : score < 40
"""

from __future__ import annotations

from src.config.logging import get_logger

logger = get_logger(__name__)

# Vendors de logiciels largement déployés
HIGH_POPULARITY_VENDORS = {
    "apache", "microsoft", "google", "linux", "cisco", "oracle",
    "mozilla", "apple", "adobe", "vmware", "nginx", "openssl",
    "wordpress", "kubernetes", "docker", "redis", "postgresql",
}

# Mots-clés indiquant une exposition Internet
EXPOSURE_KEYWORDS = {
    "remote", "internet-facing", "web server", "public endpoint",
    "cloud", "api", "http", "https", "exposed", "external",
    "rce", "remote code execution", "unauthenticated",
}

# Mots-clés indiquant haute exploitabilité
EXPLOITABILITY_KEYWORDS = {
    "trivial", "no authentication", "unauthenticated", "public exploit",
    "poc available", "actively exploited", "in the wild",
    "zero-click", "wormable", "pre-auth",
}


def exposure_score(signal_data: dict) -> float:
    """Évalue l'exposition Internet (0.0 - 1.0)."""
    insight = signal_data.get("insight", {})
    entities = signal_data.get("entities", [])

    text = (
        str(insight.get("attack_vector", ""))
        + " "
        + str(insight.get("vulnerability_type", ""))
    ).lower()

    matches = sum(1 for kw in EXPOSURE_KEYWORDS if kw in text)
    score = min(1.0, matches / 3)

    # Bonus si impact availability HIGH
    impact = insight.get("business_impact", {})
    if isinstance(impact, dict) and impact.get("availability") == "HIGH":
        score = min(1.0, score + 0.2)

    return score


def popularity_score(signal_data: dict) -> float:
    """Évalue la popularité du logiciel affecté (0.0 - 1.0)."""
    entities = signal_data.get("entities", [])

    vendors_found = [
        e["value"].lower()
        for e in entities
        if e.get("type") in ("vendor", "software")
    ]

    if any(v in HIGH_POPULARITY_VENDORS for v in vendors_found):
        return 0.9
    if vendors_found:
        return 0.5
    return 0.2


def exploitability_score(signal_data: dict) -> float:
    """Évalue la complexité d'exploitation (0.0 - 1.0, plus haut = plus facile)."""
    insight = signal_data.get("insight", {})
    text = (
        str(insight.get("attack_vector", ""))
        + " "
        + str(insight.get("vulnerability_type", ""))
    ).lower()

    matches = sum(1 for kw in EXPLOITABILITY_KEYWORDS if kw in text)
    base_score = min(1.0, matches / 2)

    # CVSS comme indicateur supplémentaire si disponible
    confidence = insight.get("confidence_score", 0.5)
    if isinstance(confidence, (int, float)):
        base_score = (base_score + float(confidence)) / 2

    return base_score


def patch_availability(signal_data: dict) -> float:
    """Évalue l'absence de correctif (0.0 - 1.0, plus haut = pas de patch)."""
    insight = signal_data.get("insight", {})
    measures = insight.get("defensive_measures", [])
    text = " ".join(str(m) for m in measures).lower()

    # Si des mesures mentionnent un patch → risque réduit
    patch_indicators = ["patch", "update", "upgrade", "fixed in", "hotfix"]
    has_patch = any(kw in text for kw in patch_indicators)

    # Indicateurs d'absence de patch
    no_patch_indicators = ["no patch", "unpatched", "0day", "zero-day", "no fix"]
    no_patch = any(kw in text for kw in no_patch_indicators)

    if no_patch:
        return 0.95
    if has_patch:
        return 0.2
    return 0.5  # Inconnu


def community_activity(signal_data: dict) -> float:
    """Évalue l'activité communautaire (0.0 - 1.0)."""
    signal_count = signal_data.get("signal_count", 1)

    if signal_count >= 20:
        return 1.0
    if signal_count >= 10:
        return 0.8
    if signal_count >= 5:
        return 0.6
    if signal_count >= 3:
        return 0.4
    return 0.2


def compute_priority_score(signal_data: dict) -> tuple[int, str]:
    """
    Algorithme multi-critères (section 7.4).

    Retourne (score 0-100, catégorie).
    """
    score = (
        0.30 * exposure_score(signal_data)
        + 0.25 * popularity_score(signal_data)
        + 0.20 * exploitability_score(signal_data)
        + 0.15 * patch_availability(signal_data)
        + 0.10 * community_activity(signal_data)
    )

    normalized = int(score * 100)
    normalized = max(0, min(100, normalized))

    category = (
        "CRITICAL" if normalized >= 80
        else "HIGH" if normalized >= 60
        else "MEDIUM" if normalized >= 40
        else "LOW"
    )

    logger.info(
        "score_computed",
        score=normalized,
        category=category,
        breakdown={
            "exposure": round(exposure_score(signal_data), 2),
            "popularity": round(popularity_score(signal_data), 2),
            "exploitability": round(exploitability_score(signal_data), 2),
            "patch_availability": round(patch_availability(signal_data), 2),
            "community_activity": round(community_activity(signal_data), 2),
        },
    )

    return normalized, category
