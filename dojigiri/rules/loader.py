"""YAML rule loader — loads rules from .yaml/.yml files and compiles them.

Loads rule definitions from YAML files in the yaml/ directory (or any
specified directory), validates required fields, and returns compiled Rule
tuples compatible with the existing engine.

Called by: rules/__init__.py
Calls into: _compile.py (Rule type), types.py (Severity/Category enums)
Data in -> Data out: YAML files -> list[Rule]
"""

from __future__ import annotations  # noqa

import logging
import re
from pathlib import Path

from ..types import Category, Severity
from ._compile import Rule

logger = logging.getLogger(__name__)

# Default YAML rules directory (sibling of this file)
_YAML_DIR = Path(__file__).parent / "yaml"

_SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "warning": Severity.WARNING,
    "info": Severity.INFO,
}

_CATEGORY_MAP = {
    "bug": Category.BUG,
    "security": Category.SECURITY,
    "performance": Category.PERFORMANCE,
    "style": Category.STYLE,
    "dead_code": Category.DEAD_CODE,
}

_FLAG_MAP = {
    "IGNORECASE": re.IGNORECASE,
    "MULTILINE": re.MULTILINE,
    "DOTALL": re.DOTALL,
    "VERBOSE": re.VERBOSE,
}

# Required fields for each rule entry
_REQUIRED_FIELDS = {"id", "severity", "category", "pattern", "message"}


def _compile_yaml_rules(rules_data: list[dict]) -> list[Rule]:
    """Compile a list of raw YAML rule dicts into Rule tuples.

    Each dict must have: id, severity, category, pattern, message.
    Optional: suggestion, flags, confidence, cwe.

    Invalid rules are skipped with a warning.
    """
    compiled: list[Rule] = []
    for i, entry in enumerate(rules_data):
        # Validate required fields
        missing = _REQUIRED_FIELDS - set(entry.keys())
        if missing:
            logger.warning(
                "Skipping YAML rule #%d: missing required fields: %s", i, missing
            )
            continue

        rule_id = entry["id"]
        pattern_str = entry["pattern"]

        # Parse severity
        severity = _SEVERITY_MAP.get(entry["severity"])
        if severity is None:
            logger.warning(
                "Skipping YAML rule '%s': invalid severity '%s'",
                rule_id,
                entry["severity"],
            )
            continue

        # Parse category
        category = _CATEGORY_MAP.get(entry["category"])
        if category is None:
            logger.warning(
                "Skipping YAML rule '%s': invalid category '%s'",
                rule_id,
                entry["category"],
            )
            continue

        # Parse optional regex flags
        flags = 0
        for flag_name in entry.get("flags", []):
            flag = _FLAG_MAP.get(flag_name)
            if flag is None:
                logger.warning(
                    "YAML rule '%s': unknown regex flag '%s', ignoring",
                    rule_id,
                    flag_name,
                )
            else:
                flags |= flag

        # Compile pattern
        try:
            compiled_pattern = re.compile(pattern_str, flags)
        except re.error as exc:
            logger.warning(
                "Skipping YAML rule '%s': invalid regex: %s", rule_id, exc
            )
            continue

        message = entry["message"]
        suggestion = entry.get("suggestion")

        compiled.append((compiled_pattern, severity, category, rule_id, message, suggestion))

    return compiled


def load_yaml_rules(yaml_path: Path) -> list[Rule]:
    """Load and compile rules from a single YAML file.

    The file must have a top-level 'rules' key containing a list of rule dicts.
    Returns an empty list if the file cannot be parsed or has no rules.
    """
    try:
        import yaml
    except ImportError:
        logger.debug("PyYAML not installed — cannot load %s", yaml_path)
        return []

    try:
        text = yaml_path.read_text(encoding="utf-8")
        data = yaml.safe_load(text)
    except Exception as exc:
        logger.warning("Failed to load YAML rule file %s: %s", yaml_path, exc)
        return []

    if not isinstance(data, dict) or "rules" not in data:
        logger.warning("YAML rule file %s has no 'rules' key", yaml_path)
        return []

    rules_data = data["rules"]
    if not isinstance(rules_data, list):
        logger.warning("YAML rule file %s: 'rules' is not a list", yaml_path)
        return []

    return _compile_yaml_rules(rules_data)


def load_yaml_rules_dir(directory: Path | None = None) -> dict[str, list[Rule]]:
    """Load all YAML rule files from a directory.

    Returns a dict mapping rule-set name (filename stem) to compiled rules.
    E.g. {"python": [...], "universal": [...], ...}

    Uses the built-in yaml/ directory by default.
    """
    if directory is None:
        directory = _YAML_DIR

    if not directory.is_dir():
        logger.debug("YAML rules directory not found: %s", directory)
        return {}

    result: dict[str, list[Rule]] = {}
    for path in sorted(directory.iterdir()):
        if path.suffix in (".yaml", ".yml"):
            rules = load_yaml_rules(path)
            if rules:
                result[path.stem] = rules

    return result
