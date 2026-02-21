"""
Vigilant Guardian — Guardrails IA (section 8.1).

Pipeline de filtrage en 3 étapes sur chaque sortie LLM :
1. Filtrage Regex : détection patterns exploits (shellcode, payloads, etc.)
2. Classification IA : DistilBERT fine-tuné (offensive vs défensif)
3. Validation Humaine : CRITICAL/HIGH → status "pending_review"

STRICTEMENT INTERDIT (sections 1.3, 8.3) :
- Génération d'exploits exécutables
- Payloads, shellcode, injection SQL, reverse shell
- Instructions offensives de toute nature
"""

from __future__ import annotations

import re

from src.config.logging import get_logger

logger = get_logger(__name__)

# ── Étape 1 : Patterns regex de contenu offensif (section 8.1) ─────────

OFFENSIVE_PATTERNS = [
    # Shellcode
    re.compile(r"\\x[0-9a-f]{2}(?:\\x[0-9a-f]{2}){3,}", re.IGNORECASE),
    # Reverse shell patterns
    re.compile(r"(?:bash|sh|nc|ncat|netcat)\s+-[ei]\s+/dev/tcp", re.IGNORECASE),
    re.compile(r"(?:python|perl|ruby|php)\s+-[ec].*?socket", re.IGNORECASE),
    # SQL injection payloads
    re.compile(r"(?:UNION\s+SELECT|OR\s+1\s*=\s*1|DROP\s+TABLE|;\s*DELETE)", re.IGNORECASE),
    # Common exploit patterns
    re.compile(r"(?:msfconsole|meterpreter|metasploit)", re.IGNORECASE),
    re.compile(r"(?:exploit/|payload/|auxiliary/)", re.IGNORECASE),
    # Base64 encoded payloads (long sequences)
    re.compile(r"(?:base64\s*-d|atob\(|btoa\().*[A-Za-z0-9+/=]{50,}", re.IGNORECASE),
    # PowerShell download cradles
    re.compile(r"(?:Invoke-WebRequest|IEX\s*\(|DownloadString)", re.IGNORECASE),
    # Common C exploit patterns
    re.compile(r"(?:strcpy|sprintf|gets)\s*\(.*\).*overflow", re.IGNORECASE),
    # Nmap/scanner patterns
    re.compile(r"nmap\s+-[sSTUAP]", re.IGNORECASE),
]

# Mots-clés fortement offensifs
OFFENSIVE_KEYWORDS = {
    "reverse shell", "bind shell", "shellcode", "payload",
    "exploit code", "proof of concept exploit", "poc exploit",
    "remote code execution exploit", "buffer overflow exploit",
    "privilege escalation exploit", "weaponize",
}


def _check_regex(text: str) -> list[str]:
    """Étape 1 : détecte les patterns regex offensifs."""
    violations: list[str] = []

    for pattern in OFFENSIVE_PATTERNS:
        matches = pattern.findall(text)
        if matches:
            violations.append(f"Regex match: {pattern.pattern[:60]}…")

    text_lower = text.lower()
    for keyword in OFFENSIVE_KEYWORDS:
        if keyword in text_lower:
            violations.append(f"Offensive keyword: '{keyword}'")

    return violations


def _check_classification(text: str) -> float:
    """
    Étape 2 : Classification IA offensive vs défensif (section 8.1).

    Utilise un score heuristique en attendant le fine-tuning de DistilBERT
    (prévu Semaine 6).  Le modèle fine-tuné remplacera cette heuristique.

    Returns:
        Score "défensif" entre 0.0 et 1.0.  Score < 0.85 = rejet.
    """
    defensive_indicators = [
        "remediation", "mitigation", "patch", "update", "firewall",
        "defensive", "protect", "harden", "monitor", "detect",
        "block", "filter", "restrict", "audit", "review",
        "disable", "configure", "policy", "compliance",
        "vulnerability management", "incident response",
    ]
    offensive_indicators = [
        "exploit", "shellcode", "payload", "inject", "bypass",
        "escalat", "exfiltrat", "reverse shell", "backdoor",
        "rootkit", "trojan", "weaponize", "attack tool",
    ]

    text_lower = text.lower()
    def_count = sum(1 for w in defensive_indicators if w in text_lower)
    off_count = sum(1 for w in offensive_indicators if w in text_lower)

    total = def_count + off_count
    if total == 0:
        return 0.9  # Neutre → probablement safe

    defensive_ratio = def_count / total
    return min(1.0, defensive_ratio + 0.1)  # Petit biais vers défensif


def filter_output(llm_output: dict) -> dict | None:
    """
    Pipeline de filtrage guardrails complet (section 8.1).

    Args:
        llm_output: sortie JSON du LLM (schéma DefensiveInsight).

    Returns:
        dict filtré si le contenu est défensif, None si rejeté.
    """
    if not llm_output or not isinstance(llm_output, dict):
        logger.warning("guardrails_invalid_input")
        return None

    # Sérialiser tout le contenu pour analyse
    full_text = " ".join(str(v) for v in llm_output.values())

    # ── Étape 1 : Filtrage Regex ────────────────────────────────────────
    regex_violations = _check_regex(full_text)
    if regex_violations:
        logger.warning(
            "guardrails_regex_violation",
            violations=regex_violations,
        )
        # Supprimer le contenu offensif des mesures défensives
        if "defensive_measures" in llm_output:
            cleaned_measures = []
            for measure in llm_output["defensive_measures"]:
                measure_violations = _check_regex(measure)
                if not measure_violations:
                    cleaned_measures.append(measure)
            llm_output["defensive_measures"] = cleaned_measures

        # Re-vérifier après nettoyage
        cleaned_text = " ".join(str(v) for v in llm_output.values())
        if _check_regex(cleaned_text):
            logger.error("guardrails_rejected_after_cleaning")
            return None

    # ── Étape 2 : Classification IA ─────────────────────────────────────
    defensive_score = _check_classification(full_text)
    if defensive_score < 0.85:
        logger.warning(
            "guardrails_classification_rejected",
            defensive_score=defensive_score,
        )
        return None

    llm_output["defensive_score"] = defensive_score

    # ── Étape 3 : Tag pour validation humaine ───────────────────────────
    # (Le status pending_review est géré dans tasks_analyze.py)

    logger.info(
        "guardrails_passed",
        defensive_score=defensive_score,
    )
    return llm_output
