"""
Vigilant Guardian — Tâches Celery de rapports (section 9.2 Semaine 8).

Génération de rapports Markdown + PDF via WeasyPrint.
Stub initial — implémentation complète en Semaine 8.
"""

from __future__ import annotations

from src.workers.celery_app import celery_app
from celery.utils.log import get_task_logger

logger = get_task_logger(__name__)


@celery_app.task(name="src.workers.tasks_report.generate_report")
def generate_report(alert_ids: list[str] | None = None):
    """Génère un rapport défensif (stub)."""
    logger.info("Report generation — implémentation Semaine 8")
    return {"status": "not_implemented"}
