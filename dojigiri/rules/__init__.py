"""Rules package — regex-based static analysis rules split by language.

Re-exports all rule lists and the Rule type for backward compatibility.
"""

from __future__ import annotations

from ._compile import Rule, _compile
from .go import GO_RULES
from .java import JAVA_RULES
from .javascript import JAVASCRIPT_RULES
from .python import PYTHON_RULES
from .rust import RUST_RULES
from .security import SECURITY_RULES
from .universal import UNIVERSAL_RULES

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
