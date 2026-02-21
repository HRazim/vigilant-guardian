"""
Vigilant Guardian — Modèles Signal (section 6.1).

- raw_signals   : données brutes collectées depuis les 5 sources
- processed_signals : signaux après pipeline NLP (embeddings, entités, cluster)
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
    text,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from src.models.base import Base


class RawSignal(Base):
    """Signal brut collecté par un collecteur (section 7.1)."""

    __tablename__ = "raw_signals"
    __table_args__ = (
        UniqueConstraint("source", "source_id", name="uq_raw_signals_source_source_id"),
        Index("idx_raw_signals_source", "source"),
        Index("idx_raw_signals_collected", "collected_at"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    source: Mapped[str] = mapped_column(
        String(50), nullable=False, comment="nvd, github, reddit, twitter, mailinglist"
    )
    source_id: Mapped[str | None] = mapped_column(
        String(255), comment="ID unique dans la source d'origine"
    )
    content: Mapped[str] = mapped_column(Text, nullable=False)
    metadata_: Mapped[dict] = mapped_column(
        "metadata", JSONB, default=dict, server_default=text("'{}'::jsonb")
    )
    collected_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        server_default=text("NOW()"),
    )
    processed: Mapped[bool] = mapped_column(
        Boolean, default=False, server_default=text("FALSE")
    )

    # Relation inverse
    processed_signal: Mapped[ProcessedSignal | None] = relationship(
        back_populates="raw_signal", uselist=False
    )

    def __repr__(self) -> str:
        return f"<RawSignal source={self.source} id={self.source_id}>"


class ProcessedSignal(Base):
    """Signal après traitement NLP (section 7.2)."""

    __tablename__ = "processed_signals"
    __table_args__ = (
        Index("idx_processed_cluster", "cluster_id"),
    )

    id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        primary_key=True,
        server_default=text("gen_random_uuid()"),
    )
    raw_signal_id: Mapped[uuid.UUID] = mapped_column(
        UUID(as_uuid=True),
        ForeignKey("raw_signals.id", ondelete="CASCADE"),
        nullable=False,
    )
    entities: Mapped[list] = mapped_column(
        JSONB, default=list, server_default=text("'[]'::jsonb"),
        comment='[{"type": "software", "value": "Apache 2.4.51"}]',
    )
    embedding_ref: Mapped[str | None] = mapped_column(
        String(255), comment="Référence FAISS index"
    )
    cluster_id: Mapped[int | None] = mapped_column(Integer)
    semantic_hash: Mapped[str | None] = mapped_column(
        String(64), comment="Déduplication sémantique"
    )
    processed_at: Mapped[datetime] = mapped_column(
        default=lambda: datetime.now(timezone.utc),
        server_default=text("NOW()"),
    )

    raw_signal: Mapped[RawSignal] = relationship(back_populates="processed_signal")

    def __repr__(self) -> str:
        return f"<ProcessedSignal cluster={self.cluster_id}>"
