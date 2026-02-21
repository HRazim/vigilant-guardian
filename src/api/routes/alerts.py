"""
Vigilant Guardian — Routes Alerts (section 2.3, 8.1).

CRUD des alertes avec validation humaine pour CRITICAL/HIGH.
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select
from sqlalchemy.ext.asyncio import AsyncSession

from src.api.dependencies import get_db, get_current_user, require_role
from src.api.schemas import (
    AlertCategory,
    AlertStatus,
    ScoredAlertCreate,
    ScoredAlertRead,
)
from src.models.alert import Alert
from src.models.audit import AuditLog
from src.models.user import User

router = APIRouter()


@router.get("/", response_model=list[ScoredAlertRead])
async def list_alerts(
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
    category: AlertCategory | None = None,
    status: AlertStatus | None = None,
    limit: int = Query(default=50, le=200),
    offset: int = Query(default=0, ge=0),
):
    """Liste les alertes avec filtres optionnels."""
    query = select(Alert).order_by(Alert.created_at.desc())
    if category:
        query = query.where(Alert.category == category.value)
    if status:
        query = query.where(Alert.status == status.value)
    query = query.limit(limit).offset(offset)

    result = await db.execute(query)
    return result.scalars().all()


@router.get("/{alert_id}", response_model=ScoredAlertRead)
async def get_alert(
    alert_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    _user: Annotated[User, Depends(get_current_user)],
):
    """Récupère le détail d'une alerte."""
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte non trouvée")
    return alert


@router.post("/{alert_id}/review", response_model=ScoredAlertRead)
async def review_alert(
    alert_id: uuid.UUID,
    db: Annotated[AsyncSession, Depends(get_db)],
    current_user: Annotated[User, Depends(require_role("admin", "analyst"))],
    action: str = Query(description="approve ou dismiss"),
):
    """
    Validation humaine d'une alerte (section 8.1, étape 3).

    Les alertes CRITICAL/HIGH nécessitent une approbation analyste
    avant diffusion.
    """
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alerte non trouvée")

    if action == "approve":
        alert.status = AlertStatus.REVIEWED.value
    elif action == "dismiss":
        alert.status = AlertStatus.DISMISSED.value
    else:
        raise HTTPException(status_code=400, detail="Action invalide : approve ou dismiss")

    alert.reviewed_by = current_user.id
    alert.reviewed_at = datetime.now(timezone.utc)

    # Audit log (section 8.2)
    db.add(AuditLog(
        user_id=current_user.id,
        action=f"alert_{action}",
        entity_type="alert",
        entity_id=alert.id,
        details={"category": alert.category, "priority_score": alert.priority_score},
    ))
    await db.commit()
    await db.refresh(alert)
    return alert
