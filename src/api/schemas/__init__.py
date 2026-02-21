"""
Vigilant Guardian — Schémas Pydantic (section 2.3).

Contrats d'interface typés pour les échanges entre couches et l'API REST.
"""

from __future__ import annotations

import uuid
from datetime import datetime
from decimal import Decimal
from enum import Enum

from pydantic import BaseModel, Field, EmailStr


# ── Enums ───────────────────────────────────────────────────────────────

class SourceType(str, Enum):
    NVD = "nvd"
    GITHUB = "github"
    REDDIT = "reddit"
    TWITTER = "twitter"
    MAILINGLIST = "mailinglist"


class AlertCategory(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class AlertStatus(str, Enum):
    ACTIVE = "active"
    PENDING_REVIEW = "pending_review"
    REVIEWED = "reviewed"
    DISMISSED = "dismissed"


class UserRole(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


class ImpactLevel(str, Enum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


# ── Collection → Analysis (RawSignal) ──────────────────────────────────

class RawSignalCreate(BaseModel):
    """Contrat Collection → Analysis (section 2.3)."""
    source: SourceType
    source_id: str | None = None
    content: str
    metadata_: dict = Field(default_factory=dict, alias="metadata")

    model_config = {"populate_by_name": True}


class RawSignalRead(RawSignalCreate):
    id: uuid.UUID
    collected_at: datetime
    processed: bool


# ── Analysis → AI Reasoning (AnalyzedCluster) ──────────────────────────

class EntityItem(BaseModel):
    type: str  # software, version, cwe_id, cve_id, vendor
    value: str


class AnalyzedCluster(BaseModel):
    """Contrat Analysis → AI Reasoning (section 2.3)."""
    cluster_id: int
    signals: list[RawSignalRead]
    entities: list[EntityItem]
    embeddings_ref: str | None = None


# ── AI Reasoning → Scoring (DefensiveInsight) ──────────────────────────

class BusinessImpact(BaseModel):
    confidentiality: ImpactLevel
    integrity: ImpactLevel
    availability: ImpactLevel


class DefensiveInsight(BaseModel):
    """Contrat AI Reasoning → Scoring (section 2.3 / 7.3.1)."""
    vulnerability_type: str = Field(description="CWE-XXX (description)")
    attack_vector: str = Field(description="Description défensive du vecteur")
    business_impact: BusinessImpact
    defensive_measures: list[str]
    confidence_score: float = Field(ge=0.0, le=1.0)
    related_cwe: list[str] = Field(default_factory=list)
    related_attack: list[str] = Field(default_factory=list)


# ── Scoring → API (ScoredAlert) ────────────────────────────────────────

class ScoredAlertCreate(BaseModel):
    """Contrat Scoring → API (section 2.3)."""
    cluster_id: int
    title: str
    vulnerability_type: str | None = None
    attack_vector: str | None = None
    business_impact: dict | None = None
    defensive_measures: list[str] = Field(default_factory=list)
    confidence_score: Decimal | None = None
    priority_score: int = Field(ge=0, le=100)
    category: AlertCategory
    justification: str | None = None
    llm_model_used: str | None = None


class ScoredAlertRead(ScoredAlertCreate):
    id: uuid.UUID
    status: AlertStatus
    created_at: datetime
    reviewed_by: uuid.UUID | None = None
    reviewed_at: datetime | None = None


# ── Auth ────────────────────────────────────────────────────────────────

class UserCreate(BaseModel):
    email: EmailStr
    password: str = Field(min_length=8)
    role: UserRole = UserRole.ANALYST


class UserRead(BaseModel):
    id: uuid.UUID
    email: EmailStr
    role: UserRole
    created_at: datetime


class TokenPair(BaseModel):
    access_token: str
    refresh_token: str
    token_type: str = "bearer"


# ── Dashboard ───────────────────────────────────────────────────────────

class DashboardStats(BaseModel):
    total_signals: int
    total_alerts: int
    critical_count: int
    high_count: int
    medium_count: int
    low_count: int
    pending_review: int


class HealthResponse(BaseModel):
    status: str
    service: str
    database: str = "unknown"
    redis: str = "unknown"
    chroma: str = "unknown"
