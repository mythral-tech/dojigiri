"""CWE and NIST SP 800-53 compliance mappings for all Dojigiri rules."""

from typing import Optional


# CWE (Common Weakness Enumeration) mappings
# Maps rule names to CWE IDs
CWE_MAP: dict[str, str] = {
    # Universal rules
    "hardcoded-secret": "CWE-798",
    "aws-credentials": "CWE-798",
    "todo-marker": "CWE-546",
    "long-line": "CWE-1078",
    "insecure-http": "CWE-319",
    "sql-injection": "CWE-89",

    # Python rules
    "bare-except": "CWE-396",
    "mutable-default": "CWE-1188",
    "none-comparison": "CWE-597",
    "eval-usage": "CWE-95",
    "exec-usage": "CWE-95",
    "open-without-with": "CWE-404",
    "os-system": "CWE-78",
    "shell-true": "CWE-78",
    "star-import": "CWE-1061",
    "assert-statement": "CWE-617",
    "fstring-no-expr": "CWE-1078",
    "pickle-unsafe": "CWE-502",
    "yaml-unsafe": "CWE-502",
    "weak-hash": "CWE-328",
    "weak-random": "CWE-330",

    # JavaScript/TypeScript rules
    "loose-equality": "CWE-597",
    "console-log": "CWE-532",
    "innerhtml": "CWE-79",
    "insert-adjacent-html": "CWE-79",
    "document-write": "CWE-79",

    # Go rules
    "unchecked-error": "CWE-252",
    "fmt-print": "CWE-532",

    # Rust rules
    "unwrap": "CWE-252",
    "expect-panic": "CWE-252",
    "unsafe-block": "CWE-676",

    # Security rules
    "path-traversal": "CWE-22",
    "private-key": "CWE-321",
    "db-connection-string": "CWE-798",
    "logging-sensitive-data": "CWE-532",
    "insecure-crypto": "CWE-327",
    "insecure-ecb-mode": "CWE-327",

    # Semantic/AST rules (detector.py, semantic/)
    "syntax-error": "CWE-670",
    "unused-import": "CWE-561",
    "exception-swallowed": "CWE-390",
    "shadowed-builtin": "CWE-710",
    "shadowed-builtin-param": "CWE-710",
    "type-comparison": "CWE-595",
    "global-keyword": "CWE-1108",
    "unreachable-code": "CWE-561",
    "high-complexity": "CWE-1121",
    "too-many-args": "CWE-1064",
    "empty-exception-handler": "CWE-390",

    # Scope analysis
    "unused-variable": "CWE-563",
    "variable-shadowing": "CWE-710",
    "possibly-uninitialized": "CWE-457",

    # Null safety
    "null-dereference": "CWE-476",

    # Resource analysis
    "resource-leak": "CWE-404",

    # Taint analysis
    "taint-flow": "CWE-20",

    # Code smells
    "god-class": "CWE-1075",
    "feature-envy": "CWE-1075",
    "long-method": "CWE-1080",
    "near-duplicate": "CWE-1041",
    "semantic-clone": "CWE-1041",

    # Graph analysis
    "dead-function": "CWE-561",
    "arg-count-mismatch": "CWE-628",
    "cross-file-issue": "CWE-710",
}


# NIST SP 800-53 control mappings
# Maps rule names to relevant NIST controls
NIST_MAP: dict[str, list[str]] = {
    # Secrets / credentials
    "hardcoded-secret": ["SC-12", "SC-28", "IA-5"],
    "aws-credentials": ["SC-12", "SC-28", "IA-5"],
    "private-key": ["SC-12", "SC-28", "IA-5"],
    "db-connection-string": ["SC-12", "SC-28", "IA-5"],

    # Injection
    "sql-injection": ["SI-10", "SI-16"],
    "eval-usage": ["SI-10", "SI-16"],
    "exec-usage": ["SI-10", "SI-16"],
    "os-system": ["SI-10", "SI-16"],
    "shell-true": ["SI-10", "SI-16"],
    "taint-flow": ["SI-10", "SI-16"],

    # XSS
    "innerhtml": ["SI-10", "SI-16"],
    "insert-adjacent-html": ["SI-10", "SI-16"],
    "document-write": ["SI-10", "SI-16"],

    # Deserialization
    "pickle-unsafe": ["SI-10", "SI-16"],
    "yaml-unsafe": ["SI-10", "SI-16"],

    # Cryptography
    "weak-hash": ["SC-13", "SC-12"],
    "weak-random": ["SC-13", "SC-12"],
    "insecure-crypto": ["SC-13", "SC-12"],
    "insecure-ecb-mode": ["SC-13", "SC-12"],
    "insecure-http": ["SC-8", "SC-13"],

    # Path traversal
    "path-traversal": ["SI-10", "AC-3"],

    # Logging
    "logging-sensitive-data": ["AU-3", "SI-11"],
    "console-log": ["AU-3"],
    "fmt-print": ["AU-3"],

    # Error handling
    "bare-except": ["SI-11"],
    "exception-swallowed": ["SI-11"],
    "empty-exception-handler": ["SI-11"],
    "unchecked-error": ["SI-11"],
    "unwrap": ["SI-11"],
    "expect-panic": ["SI-11"],

    # Resource management
    "open-without-with": ["SC-24"],
    "resource-leak": ["SC-24"],
    "null-dereference": ["SI-16"],

    # Code quality (mapped to SA family — System and Services Acquisition)
    "high-complexity": ["SA-11"],
    "too-many-args": ["SA-11"],
    "god-class": ["SA-11"],
    "long-method": ["SA-11"],
    "near-duplicate": ["SA-11"],
    "semantic-clone": ["SA-11"],
    "dead-function": ["SA-11"],
    "unreachable-code": ["SA-11"],
    "unused-import": ["SA-11"],
    "unused-variable": ["SA-11"],
}


def get_cwe(rule: str) -> Optional[str]:
    """Return the CWE ID for a rule name, or None if unmapped."""
    return CWE_MAP.get(rule)


def get_nist(rule: str) -> list[str]:
    """Return NIST SP 800-53 controls for a rule name, or empty list."""
    return NIST_MAP.get(rule, [])
