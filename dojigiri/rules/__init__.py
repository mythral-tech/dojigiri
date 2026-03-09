"""Rules package — regex-based static analysis rules split by language.

Loads rules from YAML files (primary) with Python module fallback.
Re-exports all rule lists and the Rule type for backward compatibility.
"""

from __future__ import annotations

import logging

from ._compile import Rule, _compile

logger = logging.getLogger(__name__)


def _load_rules() -> (
    tuple[list[Rule], list[Rule], list[Rule], list[Rule], list[Rule], list[Rule], list[Rule]]
):
    """Load rules from YAML, falling back to Python modules if YAML unavailable."""
    try:
        from .loader import load_yaml_rules_dir

        yaml_rules = load_yaml_rules_dir()
        if yaml_rules:
            universal = yaml_rules.get("universal", [])
            python = yaml_rules.get("python", [])
            javascript = yaml_rules.get("javascript", [])
            go = yaml_rules.get("go", [])
            rust = yaml_rules.get("rust", [])
            java = yaml_rules.get("java", [])
            security = yaml_rules.get("security", [])

            if universal or python or javascript or security:
                logger.debug(
                    "Loaded rules from YAML: %d universal, %d python, %d javascript, "
                    "%d go, %d rust, %d java, %d security",
                    len(universal),
                    len(python),
                    len(javascript),
                    len(go),
                    len(rust),
                    len(java),
                    len(security),
                )
                return universal, python, javascript, go, rust, java, security
    except Exception as exc:
        logger.debug("YAML rule loading failed, falling back to Python: %s", exc)

    # Fallback to Python modules
    from .go import GO_RULES
    from .java import JAVA_RULES
    from .javascript import JAVASCRIPT_RULES
    from .python import PYTHON_RULES
    from .rust import RUST_RULES
    from .security import SECURITY_RULES
    from .universal import UNIVERSAL_RULES

    return UNIVERSAL_RULES, PYTHON_RULES, JAVASCRIPT_RULES, GO_RULES, RUST_RULES, JAVA_RULES, SECURITY_RULES


(
    UNIVERSAL_RULES,
    PYTHON_RULES,
    JAVASCRIPT_RULES,
    GO_RULES,
    RUST_RULES,
    JAVA_RULES,
    SECURITY_RULES,
) = _load_rules()

__all__ = [
    "GO_RULES",
    "JAVA_RULES",
    "JAVASCRIPT_RULES",
    "PYTHON_RULES",
    "RUST_RULES",
    "SECURITY_RULES",
    "UNIVERSAL_RULES",
    "Rule",
    "_compile",
]
