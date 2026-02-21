"""initial schema — all tables from conception technique section 6.1

Revision ID: 001_initial
Revises: None
Create Date: 2026-02-21
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision: str = "001_initial"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ── users ───────────────────────────────────────────────────────────
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("email", sa.String(255), unique=True, nullable=False),
        sa.Column("hashed_password", sa.String(255), nullable=False),
        sa.Column("role", sa.String(20), server_default="analyst"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )

    # ── raw_signals ─────────────────────────────────────────────────────
    op.create_table(
        "raw_signals",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("source", sa.String(50), nullable=False),
        sa.Column("source_id", sa.String(255)),
        sa.Column("content", sa.Text(), nullable=False),
        sa.Column("metadata", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb")),
        sa.Column("collected_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("processed", sa.Boolean(), server_default=sa.text("FALSE")),
        sa.UniqueConstraint("source", "source_id", name="uq_raw_signals_source_source_id"),
    )
    op.create_index("idx_raw_signals_source", "raw_signals", ["source"])
    op.create_index("idx_raw_signals_collected", "raw_signals", ["collected_at"])

    # ── processed_signals ───────────────────────────────────────────────
    op.create_table(
        "processed_signals",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("raw_signal_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("raw_signals.id", ondelete="CASCADE"), nullable=False),
        sa.Column("entities", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb")),
        sa.Column("embedding_ref", sa.String(255)),
        sa.Column("cluster_id", sa.Integer()),
        sa.Column("semantic_hash", sa.String(64)),
        sa.Column("processed_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("idx_processed_cluster", "processed_signals", ["cluster_id"])

    # ── alerts ──────────────────────────────────────────────────────────
    op.create_table(
        "alerts",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("cluster_id", sa.Integer(), nullable=False),
        sa.Column("title", sa.String(500), nullable=False),
        sa.Column("vulnerability_type", sa.String(100)),
        sa.Column("attack_vector", sa.Text()),
        sa.Column("business_impact", postgresql.JSONB()),
        sa.Column("defensive_measures", postgresql.JSONB(), server_default=sa.text("'[]'::jsonb")),
        sa.Column("confidence_score", sa.Numeric(3, 2)),
        sa.Column("priority_score", sa.Integer()),
        sa.Column("category", sa.String(20)),
        sa.Column("justification", sa.Text()),
        sa.Column("llm_model_used", sa.String(50)),
        sa.Column("status", sa.String(20), server_default="active"),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
        sa.Column("reviewed_by", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("reviewed_at", sa.DateTime(timezone=True)),
        sa.CheckConstraint("priority_score BETWEEN 0 AND 100", name="ck_alerts_priority_range"),
    )
    op.create_index("idx_alerts_category", "alerts", ["category"])
    op.create_index("idx_alerts_status", "alerts", ["status"])

    # ── audit_logs ──────────────────────────────────────────────────────
    op.create_table(
        "audit_logs",
        sa.Column("id", postgresql.UUID(as_uuid=True), server_default=sa.text("gen_random_uuid()"), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True), sa.ForeignKey("users.id", ondelete="SET NULL")),
        sa.Column("action", sa.String(100), nullable=False),
        sa.Column("entity_type", sa.String(50)),
        sa.Column("entity_id", postgresql.UUID(as_uuid=True)),
        sa.Column("details", postgresql.JSONB(), server_default=sa.text("'{}'::jsonb")),
        sa.Column("created_at", sa.DateTime(timezone=True), server_default=sa.text("NOW()")),
    )
    op.create_index("idx_audit_entity", "audit_logs", ["entity_type", "entity_id"])


def downgrade() -> None:
    op.drop_table("audit_logs")
    op.drop_table("alerts")
    op.drop_table("processed_signals")
    op.drop_table("raw_signals")
    op.drop_table("users")
