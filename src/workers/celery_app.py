"""
Vigilant Guardian — Configuration Celery (section 3.1).

Celery 5.3 + Redis comme broker.  Celery Beat orchestre les jobs
de collecte périodiques selon les fréquences définies en section 7.1 :
- NVD    : toutes les 15 min
- GitHub : toutes les 30 min
- Reddit : toutes les 60 min
- Twitter: toutes les 60 min
- Mailing: quotidien
"""

from __future__ import annotations

from celery import Celery
from celery.schedules import crontab

from src.config.settings import settings

celery_app = Celery(
    "vigilant_guardian",
    broker=settings.redis_url,
    backend=settings.redis_url,
)

celery_app.conf.update(
    # Sérialisation
    task_serializer="json",
    accept_content=["json"],
    result_serializer="json",
    timezone="UTC",
    enable_utc=True,
    # Fiabilité
    task_acks_late=True,
    worker_prefetch_multiplier=1,
    task_reject_on_worker_lost=True,
    # Retry par défaut
    task_default_retry_delay=60,
    task_max_retries=3,
    # Résultats
    result_expires=3600,
)

# ── Beat Schedule (section 7.1 — fréquences de collecte) ───────────────
celery_app.conf.beat_schedule = {
    "collect-nvd-every-15min": {
        "task": "src.workers.tasks_collect.collect_nvd",
        "schedule": 15 * 60,  # 15 min
    },
    "collect-github-every-30min": {
        "task": "src.workers.tasks_collect.collect_github",
        "schedule": 30 * 60,  # 30 min
    },
    "collect-reddit-every-60min": {
        "task": "src.workers.tasks_collect.collect_reddit",
        "schedule": 60 * 60,  # 60 min
    },
    "collect-twitter-every-60min": {
        "task": "src.workers.tasks_collect.collect_twitter",
        "schedule": 60 * 60,  # 60 min
    },
    "collect-mailinglists-daily": {
        "task": "src.workers.tasks_collect.collect_mailinglists",
        "schedule": crontab(hour=2, minute=0),  # 02:00 UTC quotidien
    },
    "run-analysis-pipeline-every-20min": {
        "task": "src.workers.tasks_analyze.run_analysis_pipeline",
        "schedule": 20 * 60,
    },
}

# Auto-discover tasks
celery_app.autodiscover_tasks(["src.workers"])
