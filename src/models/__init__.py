"""
Vigilant Guardian — Registre des modèles SQLAlchemy.

Importer ce module garantit que tous les modèles sont enregistrés
auprès de Base.metadata, ce qui est requis par Alembic pour
l'autogénération des migrations.
"""

from src.models.base import Base, AsyncSessionLocal, engine, get_session
from src.models.user import User
from src.models.signal import RawSignal, ProcessedSignal
from src.models.alert import Alert
from src.models.audit import AuditLog

__all__ = [
    "Base",
    "AsyncSessionLocal",
    "engine",
    "get_session",
    "User",
    "RawSignal",
    "ProcessedSignal",
    "Alert",
    "AuditLog",
]
