"""CWE and NIST SP 800-53 compliance mapping tables for all Dojigiri rules.

Pure data module — maps rule names to CWE IDs and NIST control families.
Used to enrich findings with industry-standard compliance references.

Called by: config.py (Finding.to_dict), report_html.py, semantic/explain.py
Calls into: nothing (pure data, no dojigiri imports)
Data in -> Data out: rule name string -> CWE/NIST identifier strings
"""

from __future__ import annotations

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
    "subprocess-audit": "CWE-78",
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
    "django-mark-safe": "CWE-79",
    "django-extra-sql": "CWE-89",
    "paramiko-auto-add-policy": "CWE-295",
    "paramiko-exec-command": "CWE-78",
    "weak-rsa-key": "CWE-326",
    "requests-no-timeout": "CWE-400",
    "logging-config-listen": "CWE-94",
    "ssrf-risk": "CWE-918",
    "url-scheme-audit": "CWE-918",
    "ssti-risk": "CWE-1336",
    "xxe-risk": "CWE-611",
    "jwt-insecure": "CWE-345",
    "hardcoded-ip": "CWE-547",
    "unsafe-deserialization": "CWE-502",
    "insecure-tempfile": "CWE-377",
    # Fold 2 additions
    "os-popen": "CWE-78",
    "subprocess-shell": "CWE-78",
    "os-startfile": "CWE-78",
    "insecure-file-permissions": "CWE-732",
    "bind-all-interfaces": "CWE-668",
    "jinja2-autoescape-off": "CWE-79",
    "pycrypto-deprecated": "CWE-327",
    "ssl-wrap-socket": "CWE-295",
    "requests-no-verify": "CWE-295",
    "ssl-verify-disabled": "CWE-295",
    # Fold 4 additions
    "hardcoded-tmp": "CWE-377",
    "hardcoded-password-default": "CWE-798",
    "debug-enabled": "CWE-489",
    "toctou-file-check": "CWE-367",
    # Fold 5 additions
    "archive-slip": "CWE-22",
    "tarfile-open": "CWE-22",
    "unencrypted-ftp": "CWE-319",
    "unencrypted-telnet": "CWE-319",
    "smtp-cleartext": "CWE-319",
    "webbrowser-open": "CWE-601",
    "ctypes-load-library": "CWE-114",
    "rmtree-audit": "CWE-22",
    "dynamic-import": "CWE-502",
    "env-path-injection": "CWE-426",
    "sys-path-modify": "CWE-426",
    # Fold 6 additions
    "compile-usage": "CWE-95",
    "regex-injection": "CWE-1333",
    "http-connection-cleartext": "CWE-319",
    # Fold 7 additions
    "os-exec": "CWE-78",
    "os-spawn": "CWE-78",
    # Java-specific rules
    "java-sql-injection": "CWE-89",
    "java-xss": "CWE-79",
    "java-cmdi": "CWE-78",
    "java-ldap-injection": "CWE-90",
    "java-xpath-injection": "CWE-643",
    "java-weak-crypto": "CWE-327",
    "java-weak-hash": "CWE-328",
    "java-weak-random": "CWE-330",
    "java-trust-boundary": "CWE-501",
    "java-insecure-cookie": "CWE-614",
    "java-path-traversal": "CWE-22",
    # Semantic/AST rules (detector.py, semantic/)
    "syntax-error": "CWE-670",
    "unused-import": "CWE-561",
    "exception-swallowed": "CWE-390",
    "exception-swallowed-continue": "CWE-390",
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
    "taint-flow-cross-file": "CWE-20",
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
    # SCA
    "vulnerable-dependency": "CWE-1395",
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
    "subprocess-audit": ["SI-10", "SI-16"],
    "taint-flow": ["SI-10", "SI-16"],
    "taint-flow-cross-file": ["SI-10", "SI-16"],
    # XSS
    "innerhtml": ["SI-10", "SI-16"],
    "insert-adjacent-html": ["SI-10", "SI-16"],
    "document-write": ["SI-10", "SI-16"],
    # Deserialization
    "pickle-unsafe": ["SI-10", "SI-16"],
    "yaml-unsafe": ["SI-10", "SI-16"],
    "unsafe-deserialization": ["SI-10", "SI-16"],
    # SSRF
    "ssrf-risk": ["SI-10", "SC-7"],
    "url-scheme-audit": ["SI-10", "SC-7"],
    # SSTI
    "ssti-risk": ["SI-10", "SI-16"],
    # XXE
    "xxe-risk": ["SI-10", "SC-4"],
    # JWT
    "jwt-insecure": ["SC-13", "IA-5"],
    # Hardcoded config
    "hardcoded-ip": ["CM-6"],
    # Tempfile
    "insecure-tempfile": ["SC-28"],
    # Fold 2 additions
    "os-popen": ["SI-10", "SI-16"],
    "subprocess-shell": ["SI-10", "SI-16"],
    "os-startfile": ["SI-10", "SI-16"],
    "insecure-file-permissions": ["AC-3", "AC-6"],
    "bind-all-interfaces": ["SC-7", "CM-6"],
    "jinja2-autoescape-off": ["SI-10", "SI-16"],
    "pycrypto-deprecated": ["SC-13", "SC-12"],
    "ssl-wrap-socket": ["SC-8", "SC-13"],
    "requests-no-verify": ["SC-8", "SC-13"],
    "ssl-verify-disabled": ["SC-8", "SC-13"],
    "hardcoded-tmp": ["SC-28"],
    "hardcoded-password-default": ["SC-12", "IA-5"],
    "debug-enabled": ["CM-6", "SI-11"],
    "toctou-file-check": ["SI-16"],
    "archive-slip": ["SI-10", "AC-3"],
    "tarfile-open": ["SI-10", "AC-3"],
    "unencrypted-ftp": ["SC-8", "SC-13"],
    "unencrypted-telnet": ["SC-8", "SC-13"],
    "smtp-cleartext": ["SC-8", "SC-13"],
    "webbrowser-open": ["SI-10"],
    "ctypes-load-library": ["SI-10", "SI-16"],
    "rmtree-audit": ["SI-10", "AC-3"],
    "dynamic-import": ["SI-10", "SI-16"],
    "env-path-injection": ["CM-6", "SI-16"],
    "sys-path-modify": ["CM-6", "SI-16"],
    "compile-usage": ["SI-10", "SI-16"],
    "regex-injection": ["SI-10"],
    "http-connection-cleartext": ["SC-8", "SC-13"],
    "os-exec": ["SI-10", "SI-16"],
    "os-spawn": ["SI-10", "SI-16"],
    # Cryptography
    "weak-hash": ["SC-13", "SC-12"],
    "weak-random": ["SC-13", "SC-12"],
    "insecure-crypto": ["SC-13", "SC-12"],
    "insecure-ecb-mode": ["SC-13", "SC-12"],
    "weak-rsa-key": ["SC-13", "SC-12"],
    "insecure-http": ["SC-8", "SC-13"],
    "requests-no-timeout": ["SC-5", "SI-17"],
    "logging-config-listen": ["SI-10", "CM-7"],
    "django-mark-safe": ["SI-10"],
    "django-extra-sql": ["SI-10"],
    "paramiko-auto-add-policy": ["SC-8", "SC-23"],
    "paramiko-exec-command": ["SI-10", "SI-16"],
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
    # SCA
    "vulnerable-dependency": ["RA-5", "SI-2"],
    # Java-specific rules
    "java-sql-injection": ["SI-10", "SI-16"],
    "java-xss": ["SI-10", "SI-16"],
    "java-cmdi": ["SI-10", "SI-16"],
    "java-ldap-injection": ["SI-10", "SI-16"],
    "java-xpath-injection": ["SI-10", "SI-16"],
    "java-weak-crypto": ["SC-13", "SC-12"],
    "java-weak-hash": ["SC-13", "SC-12"],
    "java-weak-random": ["SC-13", "SC-12"],
    "java-trust-boundary": ["SI-10", "AC-4"],
    "java-insecure-cookie": ["SC-8", "SC-23"],
    "java-path-traversal": ["SI-10", "AC-3"],
}


def get_cwe(rule: str) -> str | None:
    """Return the CWE ID for a rule name, or None if unmapped."""
    return CWE_MAP.get(rule)


def get_nist(rule: str) -> list[str]:
    """Return NIST SP 800-53 controls for a rule name, or empty list."""
    return NIST_MAP.get(rule, [])
