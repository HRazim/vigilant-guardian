"""
Vigilant Guardian — FastAPI App Factory (src/api/main.py).

Point d'entrée de l'API REST.  Expose les routes, middleware,
et le endpoint /health utilisé par le Docker HEALTHCHECK (section 4.2).
"""

from __future__ import annotations

from contextlib import asynccontextmanager

import redis.asyncio as aioredis
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from src.config.logging import setup_logging, get_logger
from src.config.settings import settings
from src.api.middleware import RateLimitMiddleware
from src.api.routes import alerts, auth, dashboard, reports

logger = get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):  # type: ignore[no-untyped-def]
    """Startup / shutdown hooks."""
    setup_logging()
    logger.info("application_starting", service=settings.app_name)
    yield
    logger.info("application_stopping")


def create_app() -> FastAPI:
    """Application factory — construit et configure l'instance FastAPI."""

    app = FastAPI(
        title="Vigilant Guardian API",
        description=(
            "AI-Powered Zero-Day Vulnerability Intelligence — "
            "API REST pour la détection proactive de vulnérabilités émergentes."
        ),
        version="0.1.0",
        docs_url="/docs",
        redoc_url="/redoc",
        lifespan=lifespan,
    )

    # ── CORS ────────────────────────────────────────────────────────────
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[
            "http://localhost:3000",  # frontend dev
            "http://frontend:3000",   # frontend Docker
        ],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )

    # ── Rate Limiting (section 8.2 : 100 req/min) ──────────────────────
    app.add_middleware(RateLimitMiddleware, max_requests=settings.api_rate_limit)

    # ── Routes ──────────────────────────────────────────────────────────
    app.include_router(auth.router, prefix="/api/v1/auth", tags=["Auth"])
    app.include_router(alerts.router, prefix="/api/v1/alerts", tags=["Alerts"])
    app.include_router(dashboard.router, prefix="/api/v1/dashboard", tags=["Dashboard"])
    app.include_router(reports.router, prefix="/api/v1/reports", tags=["Reports"])

    # ── Health Check (section 4.2 — HEALTHCHECK Docker) ─────────────────
    @app.get("/health", tags=["System"])
    async def health():
        """Vérifie la connectivité PostgreSQL, Redis et ChromaDB."""
        status_report = {
            "status": "healthy",
            "service": "vigilant-guardian-api",
            "database": "unknown",
            "redis": "unknown",
            "chroma": "unknown",
        }

        # PostgreSQL
        try:
            from src.models.base import engine
            from sqlalchemy import text

            async with engine.connect() as conn:
                await conn.execute(text("SELECT 1"))
            status_report["database"] = "connected"
        except Exception as exc:
            status_report["database"] = f"error: {exc}"
            status_report["status"] = "degraded"

        # Redis
        try:
            r = aioredis.from_url(settings.redis_url)
            await r.ping()
            await r.close()
            status_report["redis"] = "connected"
        except Exception as exc:
            status_report["redis"] = f"error: {exc}"
            status_report["status"] = "degraded"

        # ChromaDB
        try:
            import httpx

            async with httpx.AsyncClient() as client:
                resp = await client.get(
                    f"http://{settings.chroma_host}:{settings.chroma_port}/api/v1/heartbeat",
                    timeout=5,
                )
                if resp.status_code == 200:
                    status_report["chroma"] = "connected"
                else:
                    status_report["chroma"] = f"http {resp.status_code}"
                    status_report["status"] = "degraded"
        except Exception as exc:
            status_report["chroma"] = f"error: {exc}"
            status_report["status"] = "degraded"

        return status_report

    return app


app = create_app()
