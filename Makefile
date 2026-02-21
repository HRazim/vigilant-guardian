# ============================================================================
# Vigilant Guardian — Makefile (section 10.2)
# ============================================================================

.PHONY: up down migrate test lint ingest-kb logs clean

# Démarrage complet
up:
	docker compose up -d --build

# Arrêt
down:
	docker compose down

# Migrations Alembic
migrate:
	docker compose exec api alembic upgrade head

# Tests unitaires + couverture
test:
	poetry run pytest tests/ -v --cov=src

# Tests unitaires seuls
test-unit:
	poetry run pytest tests/unit/ -v --cov=src --cov-report=term-missing

# Linting + type checking
lint:
	poetry run ruff check src/ && poetry run mypy src/

# Format code
format:
	poetry run black src/ tests/ && poetry run isort src/ tests/

# Ingestion RAG knowledge base
ingest-kb:
	docker compose exec api python -m knowledge_base.ingest

# Logs temps réel
logs:
	docker compose logs -f --tail=100

# Logs d'un service spécifique
logs-api:
	docker compose logs -f --tail=100 api

logs-worker:
	docker compose logs -f --tail=100 worker

# Shell dans le conteneur API
shell:
	docker compose exec api bash

# Shell Python dans le conteneur API
pyshell:
	docker compose exec api python

# Nouvelle migration Alembic
migration:
	poetry run alembic revision --autogenerate -m "$(msg)"

# Nettoyage complet (volumes inclus)
clean:
	docker compose down -v --remove-orphans
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	find . -type f -name "*.pyc" -delete 2>/dev/null || true

# Vérification santé complète
health:
	@echo "=== Health Check ==="
	@curl -s http://localhost:8000/health | python -m json.tool
	@echo ""
	@echo "=== Docker Status ==="
	@docker compose ps
