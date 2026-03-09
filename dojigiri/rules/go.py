"""Go rules."""

from __future__ import annotations

from ..types import Category, Severity
from ._compile import Rule, _compile

GO_RULES: list[Rule] = _compile(
    [
        # Unchecked error
        (
            r"^\s*\w+(?:,\s*_)\s*[:=]=",
            Severity.WARNING,
            Category.BUG,
            "unchecked-error",
            "Error return value discarded with _",
            "Handle the error explicitly",
        ),
        # fmt.Println in production
        (
            r"\bfmt\.Print(?:ln|f)?\s*\(",
            Severity.INFO,
            Category.STYLE,
            "fmt-print",
            "fmt.Print left in code",
            "Use structured logging instead",
        ),
    ]
)
