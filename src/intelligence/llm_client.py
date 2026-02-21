"""
Vigilant Guardian — LLM Client (section 3.4, 7.3).

Abstraction multi-provider avec fallback automatique :
1. GPT-4o (OpenAI)       — primaire
2. Claude Sonnet 4.5 (Anthropic) — secondaire/fallback
3. Mistral Large          — tertiaire/comparaison

Configuration commune : temperature=0.2, max_tokens=2000, structured JSON.
"""

from __future__ import annotations

import json

from src.config.settings import settings
from src.config.logging import get_logger
from src.intelligence.prompt_templates import SYSTEM_PROMPT, build_analysis_prompt

logger = get_logger(__name__)

# Ordre de priorité des providers (section 3.4)
PROVIDERS = [
    {"name": "openai", "model": "gpt-4o"},
    {"name": "anthropic", "model": "claude-sonnet-4-5-20250929"},
    {"name": "mistral", "model": "mistral-large-latest"},
]


async def _call_openai(prompt: str) -> dict | None:
    """Appel OpenAI GPT-4o (section 3.4)."""
    if not settings.openai_api_key:
        return None

    import openai

    client = openai.AsyncOpenAI(api_key=settings.openai_api_key)
    try:
        response = await client.chat.completions.create(
            model="gpt-4o",
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": prompt},
            ],
            temperature=0.2,
            max_tokens=2000,
            response_format={"type": "json_object"},
        )
        content = response.choices[0].message.content
        result = json.loads(content)
        result["model_used"] = "gpt-4o"
        return result
    except Exception as exc:
        logger.error("openai_call_failed", error=str(exc))
        return None


async def _call_anthropic(prompt: str) -> dict | None:
    """Appel Anthropic Claude Sonnet 4.5 (section 3.4)."""
    if not settings.anthropic_api_key:
        return None

    import anthropic

    client = anthropic.AsyncAnthropic(api_key=settings.anthropic_api_key)
    try:
        response = await client.messages.create(
            model="claude-sonnet-4-5-20250929",
            max_tokens=2000,
            system=SYSTEM_PROMPT,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
        )
        content = response.content[0].text
        # Extraire le JSON du texte (Claude peut ajouter du texte autour)
        json_start = content.find("{")
        json_end = content.rfind("}") + 1
        if json_start >= 0 and json_end > json_start:
            result = json.loads(content[json_start:json_end])
            result["model_used"] = "claude-sonnet-4-5"
            return result
        return None
    except Exception as exc:
        logger.error("anthropic_call_failed", error=str(exc))
        return None


async def _call_mistral(prompt: str) -> dict | None:
    """Appel Mistral Large (section 3.4)."""
    if not settings.mistral_api_key:
        return None

    import httpx

    try:
        async with httpx.AsyncClient() as client:
            resp = await client.post(
                "https://api.mistral.ai/v1/chat/completions",
                headers={
                    "Authorization": f"Bearer {settings.mistral_api_key}",
                    "Content-Type": "application/json",
                },
                json={
                    "model": "mistral-large-latest",
                    "messages": [
                        {"role": "system", "content": SYSTEM_PROMPT},
                        {"role": "user", "content": prompt},
                    ],
                    "temperature": 0.2,
                    "max_tokens": 2000,
                    "response_format": {"type": "json_object"},
                },
                timeout=60,
            )
            resp.raise_for_status()
            data = resp.json()
            content = data["choices"][0]["message"]["content"]
            result = json.loads(content)
            result["model_used"] = "mistral-large"
            return result
    except Exception as exc:
        logger.error("mistral_call_failed", error=str(exc))
        return None


# Map des providers
_PROVIDER_MAP = {
    "openai": _call_openai,
    "anthropic": _call_anthropic,
    "mistral": _call_mistral,
}


async def generate_insight(
    signal_content: str,
    entities: list[dict],
    rag_context: str,
    cross_source_signals: str = "N/A",
) -> dict | None:
    """
    Génère un insight défensif via LLM avec fallback multi-provider.

    Essaie chaque provider dans l'ordre de priorité (section 3.4)
    jusqu'à obtenir une réponse valide.

    Returns:
        dict conforme au schéma DefensiveInsight ou None si échec total.
    """
    prompt = build_analysis_prompt(
        signal_content=signal_content,
        entities=entities,
        rag_context=rag_context,
        cross_source_signals=cross_source_signals,
    )

    for provider in PROVIDERS:
        name = provider["name"]
        call_fn = _PROVIDER_MAP.get(name)
        if call_fn is None:
            continue

        logger.info("llm_attempt", provider=name, model=provider["model"])
        result = await call_fn(prompt)

        if result is not None:
            logger.info(
                "llm_success",
                provider=name,
                confidence=result.get("confidence_score"),
            )
            return result

        logger.warning("llm_fallback", failed_provider=name)

    logger.error("all_llm_providers_failed")
    return None
