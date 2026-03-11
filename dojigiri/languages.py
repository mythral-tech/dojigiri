"""Language-specific bug patterns — regex rules for static analysis.

Thin registry that assembles rules from the ``rules`` subpackage and
exposes the public API consumed by detector.py, __main__.py, and tests.

Called by: detector.py.
Calls into: rules/ (rule data), types.py (Severity/Category enums).
Data in -> Data out: language string in -> list[Rule] out.
"""

from __future__ import annotations  # noqa

from .rules import (
    CSHARP_RULES,
    GO_RULES,
    JAVA_RULES,
    JAVASCRIPT_RULES,
    PHP_RULES,
    PYTHON_RULES,
    RUST_RULES,
    SECURITY_RULES,
    TYPESCRIPT_RULES,
    UNIVERSAL_RULES,
    Rule,
)
from .types import SEVERITY_ORDER

# ─── Rule registry ───────────────────────────────────────────────────

LANGUAGE_RULES: dict[str, list[Rule]] = {
    "python": PYTHON_RULES,
    "javascript": JAVASCRIPT_RULES,
    "typescript": JAVASCRIPT_RULES + TYPESCRIPT_RULES,  # TS gets JS patterns + TS-specific
    "go": GO_RULES,
    "rust": RUST_RULES,
    "java": JAVA_RULES,
    "csharp": CSHARP_RULES,
    "php": PHP_RULES,
}


def get_rules_for_language(lang: str) -> list[Rule]:
    """Return universal + security + language-specific rules."""
    rules = UNIVERSAL_RULES + SECURITY_RULES
    if lang in LANGUAGE_RULES:
        rules = rules + LANGUAGE_RULES[lang]
    return rules


_SEVERITY_ORDER = {s.value: v for s, v in SEVERITY_ORDER.items()}


def list_all_rules() -> list[dict]:
    """Return a deduplicated list of all rules with metadata.

    Each dict: {"name", "severity", "category", "languages", "message", "suggestion"}.
    Rules appearing in multiple language sets are merged (languages combined).
    Universal/security rules get languages=["all"].
    """
    seen: dict[str, dict] = {}  # rule_name -> dict

    from .compliance import get_cwe, get_nist

    def _add_rules(rules: list[Rule], languages: list[str]) -> None:
        for _pattern, severity, category, name, message, suggestion in rules:
            if name in seen:
                existing_langs = seen[name]["languages"]
                if existing_langs != ["all"]:
                    for lang in languages:
                        if lang not in existing_langs:
                            existing_langs.append(lang)
            else:
                entry = {
                    "name": name,
                    "severity": severity.value,
                    "category": category.value,
                    "languages": list(languages),
                    "message": message,
                    "suggestion": suggestion,
                }
                cwe = get_cwe(name)
                if cwe:
                    entry["cwe"] = cwe
                nist = get_nist(name)
                if nist:
                    entry["nist"] = nist
                seen[name] = entry

    # Universal and security rules apply to all languages
    _add_rules(UNIVERSAL_RULES, ["all"])
    _add_rules(SECURITY_RULES, ["all"])

    # Language-specific rules
    for lang, rules in LANGUAGE_RULES.items():
        _add_rules(rules, [lang])

    return sorted(seen.values(), key=lambda r: (_SEVERITY_ORDER.get(r["severity"], 9), r["name"]))
