"""Rust rules."""

from __future__ import annotations  # noqa

from ..types import Category, Severity
from ._compile import Rule, _compile

RUST_RULES: list[Rule] = _compile(
    [
        # unwrap()
        (
            r"\.unwrap\(\)",
            Severity.WARNING,
            Category.BUG,
            "unwrap",
            ".unwrap() will panic on None/Err",
            "Use pattern matching or the ? operator",
        ),
        # .expect() — same panic risk as unwrap
        (
            r"\.expect\s*\(",
            Severity.WARNING,
            Category.BUG,
            "expect-panic",
            ".expect() will panic on None/Err",
            "Use pattern matching or the ? operator instead",
        ),
        # unsafe block
        (
            r"\bunsafe\s*\{",
            Severity.WARNING,
            Category.SECURITY,
            "unsafe-block",
            "Unsafe block — memory safety guarantees suspended",
            "Minimize unsafe usage and document invariants",
        ),
    ]
)
