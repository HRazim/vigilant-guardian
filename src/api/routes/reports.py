"""
Vigilant Guardian — Routes Reports (section 9.2 Semaine 8).

Génération de rapports automatisés (Markdown + PDF via WeasyPrint).
Stub initial — implémentation complète en Semaine 8.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from src.api.dependencies import get_current_user
from src.models.user import User

router = APIRouter()


@router.get("/")
async def list_reports(
    _user: Annotated[User, Depends(get_current_user)],
):
    """Liste les rapports disponibles (stub)."""
    return {"message": "Reports endpoint — implémentation Semaine 8", "reports": []}
