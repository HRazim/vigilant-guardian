"""
Vigilant Guardian — Prompt Templates (section 7.3.1).

Prompts structurés exclusivement défensifs.
STRICTEMENT INTERDIT : génération d'exploits, payloads,
instructions offensives (section 1.3, 8.1).
"""

from __future__ import annotations


# ── System Prompt (section 7.3.1 — copie exacte du document) ───────────

SYSTEM_PROMPT = """
Tu es un analyste défensif en cybersécurité. Tu ne génères JAMAIS de code
d'exploit, de payload, ou d'instructions offensives. Ta mission est
exclusivement défensive : identifier, expliquer et recommander des
mesures de protection.

Règles strictes :
1. NE JAMAIS générer de code exécutable d'exploitation
2. NE JAMAIS fournir d'instructions pour reproduire une attaque
3. TOUJOURS orienter vers la défense et la remédiation
4. TOUJOURS citer les sources (CWE, ATT&CK) quand applicable
"""


# ── User Prompt Template (section 7.3.1) ───────────────────────────────

USER_PROMPT_TEMPLATE = """
Contexte Technique :
- Description du signal : {signal_content}
- Logiciel/Version affecté : {extracted_entities}
- Historique similaire (RAG) : {rag_context}
- Sources multiples : {cross_source_signals}

Tâche :
1. Identifier le type de vulnérabilité probable (CWE)
2. Expliquer le vecteur d'attaque potentiel (sans code offensif)
3. Évaluer l'impact métier (triade CIA)
4. Proposer des mesures défensives immédiates
5. Attribuer un score de confiance (0.0-1.0)

Réponds UNIQUEMENT au format JSON suivant :
{{
    "vulnerability_type": "CWE-XXX (description)",
    "attack_vector": "description défensive du vecteur",
    "business_impact": {{
        "confidentiality": "HIGH|MEDIUM|LOW",
        "integrity": "HIGH|MEDIUM|LOW",
        "availability": "HIGH|MEDIUM|LOW"
    }},
    "defensive_measures": ["mesure 1", "mesure 2", "mesure 3"],
    "confidence_score": 0.XX,
    "related_cwe": ["CWE-XXX"],
    "related_attack": ["T1XXX"]
}}
"""


def build_analysis_prompt(
    signal_content: str,
    entities: list[dict],
    rag_context: str,
    cross_source_signals: str = "N/A",
) -> str:
    """
    Construit le prompt utilisateur à partir du template (section 7.3.1).

    Args:
        signal_content: description textuelle des signaux du cluster.
        entities: entités extraites par le pipeline NLP.
        rag_context: contexte récupéré depuis ChromaDB (RAG).
        cross_source_signals: corrélations inter-sources.

    Returns:
        Prompt formaté prêt à être envoyé au LLM.
    """
    entities_str = ", ".join(
        f"{e.get('type', 'unknown')}: {e.get('value', '')}"
        for e in entities
    ) or "Non identifiés"

    return USER_PROMPT_TEMPLATE.format(
        signal_content=signal_content[:3000],
        extracted_entities=entities_str,
        rag_context=rag_context[:2000],
        cross_source_signals=cross_source_signals[:1000],
    )
