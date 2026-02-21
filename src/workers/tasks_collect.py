"""
Vigilant Guardian — Tâches Celery de collecte (section 7.1).

Chaque tâche invoque le collecteur correspondant de manière asynchrone
et stocke les signaux bruts dans raw_signals.
"""

from __future__ import annotations

import asyncio
from datetime import datetime, timedelta, timezone

from celery.utils.log import get_task_logger

from src.workers.celery_app import celery_app
from src.config.settings import settings

logger = get_task_logger(__name__)


def _run_async(coro):
    """Exécute une coroutine dans un event loop dédié (Celery est sync)."""
    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(coro)
    finally:
        loop.close()


async def _store_signals(signals: list) -> int:
    """Persiste les signaux bruts dans PostgreSQL."""
    from sqlalchemy import select
    from src.models.base import AsyncSessionLocal
    from src.models.signal import RawSignal

    stored = 0
    async with AsyncSessionLocal() as session:
        for sig in signals:
            # Vérifie le doublon (source + source_id)
            existing = await session.execute(
                select(RawSignal).where(
                    RawSignal.source == sig.source,
                    RawSignal.source_id == sig.source_id,
                )
            )
            if existing.scalar_one_or_none():
                continue

            db_signal = RawSignal(
                source=sig.source,
                source_id=sig.source_id,
                content=sig.content,
                metadata_=sig.metadata_ if hasattr(sig, "metadata_") else sig.metadata,
            )
            session.add(db_signal)
            stored += 1

        await session.commit()
    return stored


@celery_app.task(
    bind=True,
    name="src.workers.tasks_collect.collect_nvd",
    max_retries=3,
    default_retry_delay=120,
)
def collect_nvd(self):
    """Collecte NVD toutes les 15 min (section 7.1 — 5 req/30s)."""
    logger.info("Starting NVD collection")
    try:
        from src.collectors.nvd_collector import NVDCollector

        collector = NVDCollector()
        since = datetime.now(timezone.utc) - timedelta(minutes=20)

        async def _run():
            signals = await collector.collect(since)
            count = await _store_signals(signals)
            return len(signals), count

        total, stored = _run_async(_run())
        logger.info(f"NVD collection complete: {total} fetched, {stored} new")
        return {"fetched": total, "stored": stored}

    except Exception as exc:
        logger.error(f"NVD collection failed: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    name="src.workers.tasks_collect.collect_github",
    max_retries=3,
    default_retry_delay=120,
)
def collect_github(self):
    """Collecte GitHub toutes les 30 min (section 7.1 — 5000 req/h)."""
    logger.info("Starting GitHub collection")
    try:
        from src.collectors.github_collector import GitHubCollector

        collector = GitHubCollector()
        since = datetime.now(timezone.utc) - timedelta(minutes=35)

        async def _run():
            signals = await collector.collect(since)
            count = await _store_signals(signals)
            return len(signals), count

        total, stored = _run_async(_run())
        logger.info(f"GitHub collection complete: {total} fetched, {stored} new")
        return {"fetched": total, "stored": stored}

    except Exception as exc:
        logger.error(f"GitHub collection failed: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    name="src.workers.tasks_collect.collect_reddit",
    max_retries=3,
    default_retry_delay=180,
)
def collect_reddit(self):
    """Collecte Reddit toutes les 60 min (section 7.1 — 60 req/min)."""
    logger.info("Starting Reddit collection")
    try:
        from src.collectors.reddit_collector import RedditCollector

        collector = RedditCollector()
        since = datetime.now(timezone.utc) - timedelta(minutes=65)

        async def _run():
            signals = await collector.collect(since)
            count = await _store_signals(signals)
            return len(signals), count

        total, stored = _run_async(_run())
        logger.info(f"Reddit collection complete: {total} fetched, {stored} new")
        return {"fetched": total, "stored": stored}

    except Exception as exc:
        logger.error(f"Reddit collection failed: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    name="src.workers.tasks_collect.collect_twitter",
    max_retries=3,
    default_retry_delay=180,
)
def collect_twitter(self):
    """Collecte Twitter toutes les 60 min (section 7.1 — 500k tweets/mois)."""
    logger.info("Starting Twitter collection")
    try:
        from src.collectors.twitter_collector import TwitterCollector

        collector = TwitterCollector()
        since = datetime.now(timezone.utc) - timedelta(minutes=65)

        async def _run():
            signals = await collector.collect(since)
            count = await _store_signals(signals)
            return len(signals), count

        total, stored = _run_async(_run())
        logger.info(f"Twitter collection complete: {total} fetched, {stored} new")
        return {"fetched": total, "stored": stored}

    except Exception as exc:
        logger.error(f"Twitter collection failed: {exc}")
        raise self.retry(exc=exc)


@celery_app.task(
    bind=True,
    name="src.workers.tasks_collect.collect_mailinglists",
    max_retries=2,
    default_retry_delay=600,
)
def collect_mailinglists(self):
    """Collecte Mailing Lists quotidienne (section 7.1 — 1 req/2s)."""
    logger.info("Starting Mailing Lists collection")
    try:
        from src.collectors.mailinglist_collector import MailingListCollector

        collector = MailingListCollector()
        since = datetime.now(timezone.utc) - timedelta(hours=25)

        async def _run():
            signals = await collector.collect(since)
            count = await _store_signals(signals)
            return len(signals), count

        total, stored = _run_async(_run())
        logger.info(f"Mailing Lists collection complete: {total} fetched, {stored} new")
        return {"fetched": total, "stored": stored}

    except Exception as exc:
        logger.error(f"Mailing Lists collection failed: {exc}")
        raise self.retry(exc=exc)
