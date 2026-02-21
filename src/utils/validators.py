"""
Vigilant Guardian — Validators (section 8.2).

Validateurs communs pour l'application.
"""

from __future__ import annotations

import re


CVE_PATTERN = re.compile(r"^CVE-\d{4}-\d{4,}$")
CWE_PATTERN = re.compile(r"^CWE-\d{1,4}$")


def is_valid_cve(value: str) -> bool:
    """Vérifie le format CVE-YYYY-NNNNN."""
    return bool(CVE_PATTERN.match(value))


def is_valid_cwe(value: str) -> bool:
    """Vérifie le format CWE-NNN."""
    return bool(CWE_PATTERN.match(value))


def sanitize_source_id(source: str, source_id: str) -> str:
    """Nettoie et valide un identifiant de source."""
    cleaned = re.sub(r"[^\w\-./:]", "", source_id)
    return f"{source}:{cleaned}"[:255]
