"""Language-specific bug patterns — regex rules for static analysis."""

import re
from .config import Severity, Category

# Each rule: (pattern, severity, category, rule_name, message, suggestion)
# pattern can be a compiled regex or a string (compiled at load time)

Rule = tuple[re.Pattern, Severity, Category, str, str, str | None]


def _compile(rules: list[tuple]) -> list[Rule]:
    compiled = []
    for pat, sev, cat, name, msg, sug in rules:
        compiled.append((re.compile(pat), sev, cat, name, msg, sug))
    return compiled


# ─── Universal (all languages) ────────────────────────────────────────

UNIVERSAL_RULES: list[Rule] = _compile([
    # Secrets & credentials
    (
        r"""(?i)(?:api[_-]?key|secret[_-]?key|password|passwd|token|auth[_-]?token)\s*[:=]\s*['"][A-Za-z0-9+/=_\-]{8,}['"]""",
        Severity.CRITICAL, Category.SECURITY,
        "hardcoded-secret",
        "Possible hardcoded secret or API key",
        "Use environment variables or a secrets manager",
    ),
    (
        r"""(?i)(?:aws[_-]?access|aws[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9+/=]{16,}['"]""",
        Severity.CRITICAL, Category.SECURITY,
        "aws-credentials",
        "Possible hardcoded AWS credentials",
        "Use IAM roles or environment variables",
    ),
    # TODO/FIXME — only in comment lines (# or //)
    (
        r"(?i)(?:^|\s)(?:#|//).*\b(?:TODO|FIXME|HACK|XXX)\b",
        Severity.INFO, Category.STYLE,
        "todo-marker",
        "TODO/FIXME marker found",
        None,
    ),
    # Long lines
    (
        r"^.{201,}$",
        Severity.INFO, Category.STYLE,
        "long-line",
        "Line exceeds 200 characters",
        "Break into multiple lines for readability",
    ),
    # Insecure HTTP
    (
        r"""['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0)""",
        Severity.WARNING, Category.SECURITY,
        "insecure-http",
        "Insecure HTTP URL (not localhost)",
        "Use HTTPS instead",
    ),
    # SQL injection patterns
    (
        r"""(?i)(?:execute|cursor\.execute|query)\s*\(\s*(?:f['"]|['"].*%s|['"].*\+\s*\w+|['"].*\{)""",
        Severity.CRITICAL, Category.SECURITY,
        "sql-injection",
        "Possible SQL injection — string interpolation in query",
        "Use parameterized queries",
    ),
])


# ─── Python ───────────────────────────────────────────────────────────

PYTHON_RULES: list[Rule] = _compile([
    # Bare except
    (
        r"^\s*except\s*:",
        Severity.WARNING, Category.BUG,
        "bare-except",
        "Bare except catches all exceptions including SystemExit and KeyboardInterrupt",
        "Use 'except Exception:' to avoid catching KeyboardInterrupt/SystemExit",
    ),
    # Mutable default argument
    (
        r"def\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|set\(\))",
        Severity.WARNING, Category.BUG,
        "mutable-default",
        "Mutable default argument — shared across all calls",
        "Use None as default and create inside function body",
    ),
    # == None / != None
    (
        r"(?:==|!=)\s*None",
        Severity.WARNING, Category.STYLE,
        "none-comparison",
        "Use 'is None' or 'is not None' instead of == / !=",
        "Replace with 'is None' or 'is not None'",
    ),
    # eval/exec
    (
        r"\beval\s*\(",
        Severity.CRITICAL, Category.SECURITY,
        "eval-usage",
        "eval() can execute arbitrary code",
        "Use ast.literal_eval() for safe evaluation, or avoid entirely",
    ),
    (
        r"\bexec\s*\(",
        Severity.CRITICAL, Category.SECURITY,
        "exec-usage",
        "exec() can execute arbitrary code",
        "Avoid exec() — restructure code to not need it",
    ),
    # open() without with — simple heuristic: assignment of open() on a line not starting with "with"
    (
        r"^(?!\s*with\s)\s*\w+\s*=\s*open\s*\(",
        Severity.WARNING, Category.BUG,
        "open-without-with",
        "File opened without 'with' statement — may not be closed on error",
        "Use 'with open(...) as f:' for automatic cleanup",
    ),
    # os.system / subprocess with shell=True
    (
        r"\bos\.system\s*\(",
        Severity.WARNING, Category.SECURITY,
        "os-system",
        "os.system() is vulnerable to shell injection",
        "Use subprocess.run() with a list of arguments",
    ),
    (
        r"subprocess\.\w+\([^)]*shell\s*=\s*True",
        Severity.WARNING, Category.SECURITY,
        "shell-true",
        "subprocess with shell=True is vulnerable to injection",
        "Pass command as a list without shell=True",
    ),
    # Star imports
    (
        r"^from\s+\S+\s+import\s+\*",
        Severity.WARNING, Category.STYLE,
        "star-import",
        "Star import pollutes namespace and hides dependencies",
        "Import specific names instead",
    ),
    # assert in production
    (
        r"^\s*assert\s+",
        Severity.INFO, Category.BUG,
        "assert-statement",
        "Assert statements are stripped with -O flag",
        "Use explicit if/raise for production checks",
    ),
    # f-string without expression — must match f"..." with NO { inside at all
    # Uses negative lookahead to avoid matching strings that contain braces
    (
        r"""(?<!\w)f(['"])(?:(?!\{)(?!\1).)*\1""",
        Severity.INFO, Category.STYLE,
        "fstring-no-expr",
        "f-string without any expressions — unnecessary f prefix",
        "Remove the f prefix",
    ),
    # Unsafe pickle deserialization
    (
        r"\bpickle\.loads?\s*\(",
        Severity.CRITICAL, Category.SECURITY,
        "pickle-unsafe",
        "pickle.load()/loads() can execute arbitrary code during deserialization",
        "Use json, msgpack, or a safe serialization format instead",
    ),
    # Unsafe yaml.load - match yaml.load() calls but not those with SafeLoader
    # Note: This uses a negative lookahead that checks the entire match
    (
        r"\byaml\.load\s*\((?!.*\bLoader\s*=\s*yaml\.SafeLoader)[^)]+\)",
        Severity.CRITICAL, Category.SECURITY,
        "yaml-unsafe",
        "yaml.load() without SafeLoader can execute arbitrary code",
        "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
    ),
    # Weak hash algorithms
    (
        r"\bhashlib\.(?:md5|sha1)\s*\(",
        Severity.WARNING, Category.SECURITY,
        "weak-hash",
        "MD5/SHA1 are cryptographically weak hash algorithms",
        "Use hashlib.sha256() or stronger for security-sensitive hashing",
    ),
    # Weak random (not cryptographically secure)
    (
        r"\brandom\.(?:choice|randint|random|uniform|randrange|shuffle|sample)\s*\(",
        Severity.INFO, Category.SECURITY,
        "weak-random",
        "random module is not cryptographically secure",
        "Use secrets module for security-sensitive random values",
    ),
])


# ─── JavaScript / TypeScript ─────────────────────────────────────────

JAVASCRIPT_RULES: list[Rule] = _compile([
    # var usage
    (
        r"\bvar\s+\w+",
        Severity.WARNING, Category.STYLE,
        "var-usage",
        "'var' has function scoping — can cause unexpected behavior",
        "Use 'let' or 'const' instead",
    ),
    # == instead of ===
    (
        r"(?<![=!])={2}(?!=)",
        Severity.WARNING, Category.BUG,
        "loose-equality",
        "Loose equality (==) can cause type coercion bugs",
        "Use strict equality (===) instead",
    ),
    # console.log leftover
    (
        r"\bconsole\.log\s*\(",
        Severity.INFO, Category.STYLE,
        "console-log",
        "console.log() left in code",
        "Remove or replace with proper logging",
    ),
    # eval
    (
        r"\beval\s*\(",
        Severity.CRITICAL, Category.SECURITY,
        "eval-usage",
        "eval() can execute arbitrary code — XSS risk",
        "Avoid eval() entirely",
    ),
    # innerHTML
    (
        r"\.innerHTML\s*=",
        Severity.WARNING, Category.SECURITY,
        "innerhtml",
        "innerHTML assignment — XSS risk if value is user-controlled",
        "Use textContent or sanitize HTML before inserting",
    ),
    # insertAdjacentHTML
    (
        r"\.insertAdjacentHTML\s*\(",
        Severity.WARNING, Category.SECURITY,
        "insert-adjacent-html",
        "insertAdjacentHTML() — XSS risk if value is user-controlled",
        "Sanitize HTML content before inserting",
    ),
    # document.write
    (
        r"\bdocument\.write\s*\(",
        Severity.WARNING, Category.SECURITY,
        "document-write",
        "document.write() is a security risk and blocks rendering",
        "Use DOM manipulation methods instead",
    ),
])


# ─── Go ───────────────────────────────────────────────────────────────

GO_RULES: list[Rule] = _compile([
    # Unchecked error
    (
        r"^\s*\w+(?:,\s*_)\s*[:=]=",
        Severity.WARNING, Category.BUG,
        "unchecked-error",
        "Error return value discarded with _",
        "Handle the error explicitly",
    ),
    # fmt.Println in production
    (
        r"\bfmt\.Print(?:ln|f)?\s*\(",
        Severity.INFO, Category.STYLE,
        "fmt-print",
        "fmt.Print left in code",
        "Use structured logging instead",
    ),
])


# ─── Rust ─────────────────────────────────────────────────────────────

RUST_RULES: list[Rule] = _compile([
    # unwrap()
    (
        r"\.unwrap\(\)",
        Severity.WARNING, Category.BUG,
        "unwrap",
        ".unwrap() will panic on None/Err",
        "Use pattern matching or the ? operator",
    ),
    # .expect() — same panic risk as unwrap
    (
        r"\.expect\s*\(",
        Severity.WARNING, Category.BUG,
        "expect-panic",
        ".expect() will panic on None/Err",
        "Use pattern matching or the ? operator instead",
    ),
    # unsafe block
    (
        r"\bunsafe\s*\{",
        Severity.WARNING, Category.SECURITY,
        "unsafe-block",
        "Unsafe block — memory safety guarantees suspended",
        "Minimize unsafe usage and document invariants",
    ),
])


# ─── Security patterns (applied to all languages) ────────────────────

SECURITY_RULES: list[Rule] = _compile([
    # Path traversal
    (
        r"""(?:open|read|write|include|require)\s*\([^)]*\.\./""",
        Severity.CRITICAL, Category.SECURITY,
        "path-traversal",
        "Possible path traversal attack with ../",
        "Validate and sanitize file paths",
    ),
    # Private key
    (
        r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----",
        Severity.CRITICAL, Category.SECURITY,
        "private-key",
        "Private key found in source code",
        "Remove immediately and rotate the key",
    ),
])


# ─── Rule registry ───────────────────────────────────────────────────

LANGUAGE_RULES: dict[str, list[Rule]] = {
    "python": PYTHON_RULES,
    "javascript": JAVASCRIPT_RULES,
    "typescript": JAVASCRIPT_RULES,  # TS shares JS patterns
    "go": GO_RULES,
    "rust": RUST_RULES,
}


def get_rules_for_language(lang: str) -> list[Rule]:
    """Return universal + security + language-specific rules."""
    rules = UNIVERSAL_RULES + SECURITY_RULES
    if lang in LANGUAGE_RULES:
        rules = rules + LANGUAGE_RULES[lang]
    return rules
