"""
Vigilant Guardian — Route Dashboard (section 2.1).

Statistiques agrégées pour le frontend Next.js.
"""

from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_current_user
from src.api.schemas import DashboardStats
from src.models.alert import Alert
from src.models.signal import RawSignal
from src.models.user import User

router = APIRouter()


@router.get("/stats", response_model=DashboardStats)
async def get_stats(
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
):
    """Renvoie les compteurs pour le dashboard principal."""
    total_signals = await db.scalar(select(func.count(RawSignal.id)))
    total_alerts = await db.scalar(select(func.count(Alert.id)))

    def _count_category(cat: str):
        return select(func.count(Alert.id)).where(Alert.category == cat)

    critical = await db.scalar(_count_category("CRITICAL"))
    high = await db.scalar(_count_category("HIGH"))
    medium = await db.scalar(_count_category("MEDIUM"))
    low = await db.scalar(_count_category("LOW"))
    pending = await db.scalar(
        select(func.count(Alert.id)).where(Alert.status == "pending_review")
    )

    return DashboardStats(
        total_signals=total_signals or 0,
        total_alerts=total_alerts or 0,
        critical_count=critical or 0,
        high_count=high or 0,
        medium_count=medium or 0,
        low_count=low or 0,
        pending_review=pending or 0,
    )
