"""JavaScript / TypeScript rules."""

from __future__ import annotations

from ..types import Category, Severity
from ._compile import Rule, _compile

JAVASCRIPT_RULES: list[Rule] = _compile(
    [
        # Note: var-usage rule removed — it's a style opinion, not a correctness issue.
        # Projects using var intentionally (Express, CommonJS) get massive noise.
        # Users who want it can add it as a custom rule via .doji.toml.
        # == instead of ===
        (
            r"(?<![=!])={2}(?!=)",
            Severity.WARNING,
            Category.BUG,
            "loose-equality",
            "Loose equality (==) can cause type coercion bugs",
            "Use strict equality (===) instead",
        ),
        # console.log leftover
        (
            r"\bconsole\.log\s*\(",
            Severity.INFO,
            Category.STYLE,
            "console-log",
            "console.log() left in code",
            "Remove or replace with proper logging",
        ),
        # eval
        (
            r"\beval\s*\(",
            Severity.CRITICAL,
            Category.SECURITY,
            "eval-usage",
            "eval() can execute arbitrary code — XSS risk",
            "Avoid eval() entirely",
        ),
        # innerHTML
        (
            r"\.innerHTML\s*=",
            Severity.WARNING,
            Category.SECURITY,
            "innerhtml",
            "innerHTML assignment — XSS risk if value is user-controlled",
            "Use textContent or sanitize HTML before inserting",
        ),
        # insertAdjacentHTML
        (
            r"\.insertAdjacentHTML\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "insert-adjacent-html",
            "insertAdjacentHTML() — XSS risk if value is user-controlled",
            "Sanitize HTML content before inserting",
        ),
        # document.write
        (
            r"\bdocument\.write\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "document-write",
            "document.write() is a security risk and blocks rendering",
            "Use DOM manipulation methods instead",
        ),
    ]
)
