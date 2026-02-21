# 🛡️ Vigilant Guardian

**AI-Powered Zero-Day Vulnerability Intelligence**

> Système d'intelligence assisté par IA pour détecter, analyser et expliquer les signaux faibles de vulnérabilités émergentes, permettant une défense proactive et contextuelle.

## Quick Start

```bash
# 1. Cloner et configurer
git clone <repo-url> && cd vigilant-guardian
cp .env.example .env  # ⚠️ Éditer les valeurs

# 2. Lancer la stack
make up

# 3. Appliquer les migrations
make migrate

# 4. Vérifier la santé
make health

# 5. Lancer les tests
make test
```

## Architecture

```
[Frontend Next.js 14] → [API FastAPI] → [Celery Workers]
                              ↓                 ↓
                    [PostgreSQL 16]    [Redis 7 + ChromaDB]
```

- **5 sources** : NVD, GitHub, Reddit, Twitter, Mailing Lists
- **Pipeline NLP** : Sentence-BERT → FAISS → HDBSCAN
- **3 LLMs** : GPT-4o → Claude Sonnet 4.5 → Mistral Large (fallback)
- **Guardrails** : usage strictement défensif, pas d'exploits

## Documentation

- [Guide d'Implémentation](IMPLEMENTATION_GUIDE.md)
- [API Docs](http://localhost:8000/docs) (Swagger UI)
- [Conception Technique](docs/VigilantGuardian_ConceptionTechnique.pdf)

## Stack Technique

| Composant | Technologie |
|-----------|-------------|
| Backend | Python 3.11, FastAPI ≥0.110, SQLAlchemy 2.0, Celery 5.3 |
| Frontend | Next.js 14, TypeScript 5, shadcn/ui, Zustand, Recharts |
| Base de données | PostgreSQL 16, ChromaDB ≥0.4, Redis 7 |
| NLP | Sentence-BERT, spaCy, HDBSCAN, FAISS |
| LLM | GPT-4o, Claude Sonnet 4.5, Mistral Large |

## Licence

Prototype académique — usage interne uniquement.
