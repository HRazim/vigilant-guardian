"""
Vigilant Guardian — Configuration centralisée.

Toutes les valeurs sensibles proviennent exclusivement de variables
d'environnement (.env).  Aucune clé ou mot de passe n'est jamais
codé en dur (section 8.2 du document de conception).
"""

from __future__ import annotations

from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    """Paramètres globaux chargés depuis les variables d'environnement."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_file_encoding="utf-8",
        case_sensitive=False,
    )

    # ── Database (PostgreSQL 16) ────────────────────────────────────────
    db_user: str = "vigilant"
    db_password: str = ""
    database_url: str = (
        "postgresql+asyncpg://vigilant:changeme@db:5432/vigilant_guardian"
    )

    # ── Redis 7 (cache + Celery broker) ─────────────────────────────────
    redis_password: str = ""
    redis_url: str = "redis://:changeme@redis:6379/0"

    # ── ChromaDB ≥0.4 (vector store RAG) ────────────────────────────────
    chroma_host: str = "chroma"
    chroma_port: int = 8000
    chroma_token: str = ""

    # ── LLM API Keys (section 3.4) ─────────────────────────────────────
    openai_api_key: str = ""
    anthropic_api_key: str = ""
    mistral_api_key: str = ""

    # ── Authentification JWT (section 8.2 : RS256, exp 1 h, refresh 7 j)
    jwt_secret: str = ""
    jwt_algorithm: str = "RS256"
    jwt_expiration_minutes: int = 60
    jwt_refresh_days: int = 7

    # ── APIs externes (section 7.1) ─────────────────────────────────────
    nvd_api_key: str = ""
    github_token: str = ""
    reddit_client_id: str = ""
    reddit_client_secret: str = ""
    twitter_bearer_token: str = ""

    # ── Application ─────────────────────────────────────────────────────
    app_name: str = "Vigilant Guardian"
    debug: bool = False
    log_level: str = "INFO"
    api_rate_limit: int = 100  # req/min par utilisateur (section 8.2)


settings = Settings()
