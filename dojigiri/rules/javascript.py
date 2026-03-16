"""JavaScript / TypeScript rules."""

from __future__ import annotations  # noqa

from ..types import Category, Severity
from ._compile import Rule, _compile

JAVASCRIPT_RULES: list[Rule] = _compile(
    [
        # ── Security ─────────────────────────────────────────────────

        # eval / Function constructor with variable input
        (
            r"\beval\s*\(",
            Severity.CRITICAL,
            Category.SECURITY,
            "eval-usage",
            "eval() can execute arbitrary code — XSS risk",
            "Avoid eval() entirely",
        ),
        (
            r"\bnew\s+Function\s*\(",
            Severity.CRITICAL,
            Category.SECURITY,
            "function-constructor",
            "new Function() is equivalent to eval() — code injection risk",  # doji:ignore(ssti-risk)
            "Avoid dynamic code generation; use a lookup table or safe parser",
        ),
        # DOM XSS sinks
        (
            r"\.innerHTML\s*=",
            Severity.WARNING,
            Category.SECURITY,
            "innerhtml",
            "innerHTML assignment — XSS risk if value is user-controlled",
            "Use textContent or sanitize HTML before inserting",
        ),
        (
            r"\.outerHTML\s*=",
            Severity.WARNING,
            Category.SECURITY,
            "outerhtml",
            "outerHTML assignment — XSS risk if value is user-controlled",
            "Use textContent or DOM manipulation methods instead",
        ),
        (
            r"\.insertAdjacentHTML\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "insert-adjacent-html",
            "insertAdjacentHTML() — XSS risk if value is user-controlled",
            "Sanitize HTML content before inserting",
        ),
        (
            r"\bdocument\.write(?:ln)?\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "document-write",
            "document.write() is a security risk and blocks rendering",  # doji:ignore(xss-document-write)
            "Use DOM manipulation methods instead",
        ),
        # Prototype pollution
        (
            r"\b__proto__\b",
            Severity.WARNING,
            Category.SECURITY,
            "proto-access",
            "__proto__ access — prototype pollution vector",
            "Use Object.getPrototypeOf() / Object.create() instead",
        ),
        (
            r"\bObject\.assign\s*\(\s*(?:\{\}|[a-zA-Z_$])",
            Severity.INFO,
            Category.SECURITY,
            "object-assign-merge",
            "Object.assign() with dynamic source — prototype pollution risk if source is user-controlled",
            "Validate/sanitize input objects; strip __proto__ and constructor keys",
        ),
        # Open redirect
        (
            r"(?:window\.location|document\.location|location\.href)\s*=\s*(?!['\"](/|https?://))",
            Severity.WARNING,
            Category.SECURITY,
            "open-redirect",
            "Dynamic location assignment — open redirect risk if value is user-controlled",
            "Validate redirect URLs against an allowlist of trusted domains",
        ),
        # Insecure randomness
        (
            r"\bMath\.random\s*\(\s*\)",
            Severity.WARNING,
            Category.SECURITY,
            "insecure-random",
            "Math.random() is not cryptographically secure",
            "Use crypto.getRandomValues() or crypto.randomUUID() for security-sensitive values",
        ),
        # postMessage without origin check
        (
            r"\.addEventListener\s*\(\s*['\"]message['\"]",
            Severity.INFO,
            Category.SECURITY,
            "postmessage-no-origin",
            "postMessage listener — verify event.origin is checked before processing",
            "Always check event.origin against expected domains before trusting message data",
        ),
        # RegExp DoS (catastrophic backtracking patterns)
        (
            r"new\s+RegExp\s*\([^)]*\+",
            Severity.WARNING,
            Category.SECURITY,
            "regexp-injection",
            "RegExp constructed with dynamic input — ReDoS and injection risk",
            "Escape user input with a regex-escape function before building patterns",
        ),
        # Insecure cookie settings
        (
            r"document\.cookie\s*=\s*(?!.*(?:;|secure|httponly))",
            Severity.WARNING,
            Category.SECURITY,
            "insecure-cookie",
            "Cookie set without security flags",
            "Set Secure, HttpOnly, and SameSite flags on cookies",
        ),
        # CORS misconfiguration
        (
            r"""(?i)['"]Access-Control-Allow-Origin['"]\s*[:,]\s*['"]\*['"]""",
            Severity.WARNING,
            Category.SECURITY,
            "cors-wildcard",
            "CORS Access-Control-Allow-Origin set to * — allows any origin",
            "Restrict CORS to specific trusted origins",
        ),
        # JWT algorithm none
        (
            r"""(?i)algorithm\s*[:=]\s*['"]none['"]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "jwt-alg-none",
            "JWT algorithm set to 'none' — signature bypass",
            "Always use a strong signing algorithm (RS256 or ES256)",
        ),
        # NoSQL injection ($where, $regex with variable)
        (
            r"""\$(?:where|regex)\s*[:=]""",
            Severity.WARNING,
            Category.SECURITY,
            "nosql-injection",
            "MongoDB operator ($where/$regex) — NoSQL injection risk if value is user-controlled",
            "Use parameterized queries; never pass raw user input to MongoDB operators",
        ),
        # Command injection via child_process
        (
            r"""(?:child_process\.exec|execSync)\s*\(\s*(?!['"])""",
            Severity.CRITICAL,
            Category.SECURITY,
            "js-command-injection",
            "child_process.exec() with dynamic argument — command injection risk",
            "Use execFile() or spawn() with argument arrays instead of shell strings",
        ),
        (
            r"""(?:child_process\.exec|execSync)\s*\(\s*['"].*?\$\{""",
            Severity.CRITICAL,
            Category.SECURITY,
            "js-command-injection-template",
            "child_process.exec() with template literal interpolation — command injection",
            "Use execFile() or spawn() with argument arrays; never interpolate into shell strings",
        ),
        # Path traversal via fs
        (
            r"""(?:fs\.(?:readFile|writeFile|readdir|unlink|stat|access|mkdir|rmdir|createReadStream|createWriteStream)(?:Sync)?)\s*\(\s*(?!['"]|__dirname|__filename|path\.join\s*\(\s*__dirname)""",
            Severity.WARNING,
            Category.SECURITY,
            "js-path-traversal",
            "fs operation with dynamic path — path traversal risk",
            "Validate and sanitize file paths; use path.resolve() and check against a base directory",
        ),
        # Hardcoded JWT secret
        (
            r"""(?:jwt\.sign|jwt\.verify)\s*\([^)]*,\s*['"][^'"]{8,}['"]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "js-hardcoded-jwt-secret",
            "Hardcoded JWT secret in source code",
            "Use environment variables or a secrets manager for JWT secrets",
        ),
        # Disabled TLS verification
        (
            r"""rejectUnauthorized\s*:\s*false""",
            Severity.CRITICAL,
            Category.SECURITY,
            "js-tls-reject-unauthorized",
            "TLS certificate verification disabled (rejectUnauthorized: false)",
            "Enable certificate verification; use proper CA certificates instead",
        ),
        # NODE_TLS_REJECT_UNAUTHORIZED=0
        (
            r"""NODE_TLS_REJECT_UNAUTHORIZED.*=.*['"]?0['"]?""",
            Severity.CRITICAL,
            Category.SECURITY,
            "js-tls-env-disable",
            "NODE_TLS_REJECT_UNAUTHORIZED=0 disables all TLS verification",
            "Remove this setting; configure proper CA certificates instead",
        ),

        # ── Quality / Bugs ───────────────────────────────────────────

        # debugger statement
        (
            r"^\s*debugger\s*;?\s*$",
            Severity.WARNING,
            Category.BUG,
            "debugger-statement",
            "debugger statement left in code — will pause execution in browser",
            "Remove debugger statements before committing",
        ),
        # Note: var-usage rule intentionally omitted — it's a style opinion.
        # Projects using var intentionally (Express, CommonJS) get massive noise.
        # Users who want it can add it as a custom rule via .doji.toml.
        # Empty catch block (swallowed error)
        (
            r"catch\s*\(\s*\w*\s*\)\s*\{\s*\}",
            Severity.WARNING,
            Category.BUG,
            "empty-catch",
            "Empty catch block — error is silently swallowed",
            "Handle the error or add a comment explaining why it's intentionally ignored",
        ),
        # alert() left in code
        (
            r"\balert\s*\(\s*",
            Severity.INFO,
            Category.STYLE,
            "alert-usage",
            "alert() left in code",
            "Remove alert() calls; use proper UI notifications",
        ),
        # Async function call without await
        (
            r"(?:^|[;=,(])\s*(?!return\b|await\b|yield\b|new\b)\w+\.\w+Async\s*\(",
            Severity.INFO,
            Category.BUG,
            "missing-await-hint",
            "Call to *Async() function — verify await is not missing",
            "Add await if this should be awaited; rename if it's not actually async",
        ),
        # Promise without catch
        (
            r"\.then\s*\([^)]*\)\s*(?!\.catch|\.finally)",
            Severity.INFO,
            Category.BUG,
            "promise-no-catch",
            "Promise .then() without .catch() — unhandled rejection risk",
            "Add .catch() handler or use async/await with try/catch",
        ),
        # setTimeout/setInterval with string arg (implicit eval)
        (
            r"""(?:setTimeout|setInterval)\s*\(\s*['"]""",
            Severity.WARNING,
            Category.SECURITY,
            "settimeout-string",
            "setTimeout/setInterval with string argument — implicit eval()",
            "Pass a function reference instead of a string",
        ),
        # Assigning to prototype directly
        (
            r"\.prototype\s*=\s*\{",
            Severity.INFO,
            Category.BUG,
            "prototype-overwrite",
            "Overwriting .prototype object — destroys constructor property",
            "Use Object.assign() on existing prototype or set properties individually",
        ),
        # with statement
        (
            r"^\s*with\s*\(",
            Severity.WARNING,
            Category.BUG,
            "with-statement",
            "with statement creates ambiguous scope — deprecated in strict mode",
            "Use explicit object references instead of with",
        ),
        # Bitwise operator where logical was likely intended
        (
            r"(?:if|while|&&|\|\|)\s*\(.*?[^&|]\s*[&|]\s*[^&|]",
            Severity.INFO,
            Category.BUG,
            "bitwise-in-condition",
            "Bitwise operator in boolean context — possibly intended && or ||",
            "Use && (logical AND) or || (logical OR) for boolean logic",
        ),
    ]
)
