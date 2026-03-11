"""Shared compile helper and Rule type alias for all rule modules."""

from __future__ import annotations  # noqa

import re

from ..types import Category, Severity

# Each rule: (pattern, severity, category, rule_name, message, suggestion)
Rule = tuple[re.Pattern, Severity, Category, str, str, str | None]


def _compile(rules: list[tuple]) -> list[Rule]:
    compiled = []
    for pat, sev, cat, name, msg, sug in rules:
        compiled.append((re.compile(pat), sev, cat, name, msg, sug))
    return compiled
