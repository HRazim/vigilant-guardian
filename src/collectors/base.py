"""
Vigilant Guardian — BaseCollector (section 7.1).

Classe abstraite définissant le contrat pour tous les collecteurs :
- collect()   : récupère les données depuis la source
- normalize() : uniformise le format en RawSignal
- store()     : persiste dans PostgreSQL (raw_signals)
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime

from src.config.settings import settings
from src.config.logging import get_logger


@dataclass
class RawSignalData:
    """Structure de données intermédiaire pour un signal brut."""
    source: str
    source_id: str
    content: str
    metadata: dict = field(default_factory=dict)


class BaseCollector(ABC):
    """
    Classe abstraite pour tous les collecteurs (section 7.1).

    Sous-classes concrètes :
    - NVDCollector       (NVD API 2.0, 15 min)
    - GitHubCollector    (REST API v3 + GraphQL, 30 min)
    - RedditCollector    (OAuth2 API, 60 min)
    - TwitterCollector   (API v2 Basic, 60 min)
    - MailingListCollector (Archives HTTP / Scrapy, quotidien)
    """

    def __init__(self) -> None:
        self.config = settings
        self.logger = get_logger(self.__class__.__name__)

    @abstractmethod
    async def collect(self, since: datetime) -> list[RawSignalData]:
        """
        Récupère les signaux bruts depuis la source externe.

        Args:
            since: ne collecter que les données postérieures à cette date.

        Returns:
            Liste de RawSignalData normalisés.
        """
        ...

    def normalize(self, raw_data: dict, source: str) -> RawSignalData:
        """
        Transforme les données brutes de la source en RawSignalData.

        Cette implémentation par défaut peut être overridée par les
        sous-classes pour un traitement spécifique.
        """
        return RawSignalData(
            source=source,
            source_id=str(raw_data.get("id", "")),
            content=str(raw_data.get("content", raw_data.get("description", ""))),
            metadata=raw_data,
        )
