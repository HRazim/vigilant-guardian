"""
Vigilant Guardian — Modèle Alert (section 6.1).

Score multi-critères 0-100, catégories CRITICAL/HIGH/MEDIUM/LOW
(section 7.4).  Les alertes CRITICAL/HIGH nécessitent une validation
humaine (section 8.1, étape 3).
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from decimal import Decimal

from sqlalchemy import (
    CheckConstraint,
    ForeignKey,
    Index,
    Integer,
    Numeric,
    String,
    Text,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class Alert(Base):
    """Alerte défensive générée par le pipeline IA."""

    __tablename__ = "alerts"
    __table_args__ = (
        CheckConstraint(
            "priority_score BETWEEN 0 AND 100",
            name="ck_alerts_priority_range",
        ),
        Index("idx_alerts_category", "category"),
        Index("idx_alerts_status", "status"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    cluster_id: Mapped[int] = mapped_column(Integer, nullable=False)
    title: Mapped[str] = mapped_column(String(500), nullable=False)
    vulnerability_type: Mapped[str | None] = mapped_column(
        String(100), comment="CWE-xxx"
    )
    attack_vector: Mapped[str | None] = mapped_column(Text)
    business_impact: Mapped[dict | None] = mapped_column(
        JSONB, comment="{confidentiality, integrity, availability}"
    )
    defensive_measures: Mapped[list] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb")
    )
    confidence_score: Mapped[Decimal | None] = mapped_column(Numeric(3, 2))
    priority_score: Mapped[int | None] = mapped_column(Integer)
    category: Mapped[str | None] = mapped_column(
        String(20), comment="CRITICAL, HIGH, MEDIUM, LOW"
    )
    justification: Mapped[str | None] = mapped_column(Text)
    llm_model_used: Mapped[str | None] = mapped_column(String(50))
    status: Mapped[str] = mapped_column(
        String(20), default="active", server_default="active"
    )
    created_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        server_default=text("NOW()"),
    )
    reviewed_by: Mapped[uuid.UUID | None] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("users.id", ondelete="SET NULL"),
    )
    reviewed_at: Mapped[datetime | None] = mapped_column()

    reviewer: Mapped["User | None"] = relationship(  # noqa: F821
        foreign_keys=[reviewed_by],
    )

    def __repr__(self) -> str:
        return f"<Alert {self.title[:40]}… [{self.category}]>"
