"""Java rules."""

from __future__ import annotations

from ..types import Category, Severity
from ._compile import Rule, _compile

JAVA_RULES: list[Rule] = _compile(
    [
        # Weak cryptography — DES, RC2, RC4, Blowfish, DESede/3DES (CWE-327)
        # Must NOT match AES, AES/GCM, ChaCha20
        (
            r"""(?:Cipher|KeyGenerator)\.getInstance\s*\(\s*["'](?:[^"']*(?:DES|RC2|RC4|Blowfish|DESede)[^"']*)["']""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-weak-crypto",
            "Weak/broken cryptographic algorithm (DES, RC2, RC4, Blowfish, or 3DES)",
            "Use AES/GCM/NoPadding or ChaCha20-Poly1305",
        ),
        # Weak hashing — MD5, SHA1, SHA-1 (CWE-328)
        # Must NOT match SHA-256, SHA-384, SHA-512
        (
            r"""MessageDigest\.getInstance\s*\(\s*["'](?:MD[245]|SHA-?1)["']""",
            Severity.WARNING,
            Category.SECURITY,
            "java-weak-hash",
            "Weak hash algorithm (MD5/SHA1) — vulnerable to collision attacks",
            "Use SHA-256 or stronger (SHA-384, SHA-512)",
        ),
        # Weak hashing — variable algorithm from properties/config (CWE-328)
        # MessageDigest.getInstance(variable) where algorithm is loaded at runtime.
        # The FP filter suppresses when the property is known-safe (hashAlg2=SHA-256).
        (
            r"""MessageDigest\.getInstance\s*\(\s*(?!["'])([a-z]\w*)\s*[,)]""",
            Severity.WARNING,
            Category.SECURITY,
            "java-weak-hash",
            "Hash algorithm from variable — may resolve to weak algorithm (MD5/SHA1)",
            "Use a hardcoded strong algorithm (SHA-256, SHA-384, SHA-512)",
        ),
        # Weak randomness — java.util.Random is not cryptographically secure (CWE-330)
        # Must NOT match SecureRandom
        (
            r"""(?<!Secure)\bRandom\s*\(|new\s+java\.util\.Random\s*\(|Math\.random\s*\(""",
            Severity.WARNING,
            Category.SECURITY,
            "java-weak-random",
            "java.util.Random is not cryptographically secure",
            "Use java.security.SecureRandom for security-sensitive random values",
        ),
        # Trust boundary violation — session.setAttribute/putValue (CWE-501)
        (
            r"""(?:session|getSession\(\))\.(?:setAttribute|putValue)\s*\(""",
            Severity.WARNING,
            Category.SECURITY,
            "java-trust-boundary",
            "Potential trust boundary violation — untrusted data stored in session",
            "Validate and sanitize input before storing in HttpSession",
        ),
        # Insecure cookie — setSecure(false) (CWE-614)
        (
            r"""\.setSecure\s*\(\s*false\s*\)""",
            Severity.WARNING,
            Category.SECURITY,
            "java-insecure-cookie",
            "Cookie Secure flag explicitly disabled — cookie sent over HTTP",
            "Use cookie.setSecure(true) to restrict cookies to HTTPS",
        ),
        # ─── Java SQL Injection (CWE-89) ─────────────────────────────
        # Java-specific: string concatenation into SQL with DB API sink calls
        # on the same line. Complements universal sql-injection rules which
        # catch the string-build line separately.
        (
            r"""\.(?:prepareCall|prepareStatement|queryForObject|queryForList|batchUpdate)\s*\([^)]*\+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-sql-injection",
            "SQL injection — string concatenation passed to Java DB API",
            "Use PreparedStatement with ? placeholders and bind parameters",
        ),
        (
            r"""\.(?:executeQuery|executeUpdate|execute)\s*\([^)]*\+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-sql-injection",
            "SQL injection — string concatenation in SQL execute call",
            "Use PreparedStatement with ? placeholders and bind parameters",
        ),
        # SQL string built with concatenation on separate line:
        # String sql = "SELECT ... " + bar + "..."  (tainted SQL variable)
        # Catches: "{call " + param + "}", "SELECT ... '" + bar + "'"
        (
            r"""(?:String\s+)?sql\s*=\s*["'][^"']*["']\s*\+\s*(?!["'])\w+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-sql-injection",
            "SQL injection — string concatenation in SQL query construction",
            "Use PreparedStatement with ? placeholders and bind parameters",
        ),
        # ─── Java XSS (CWE-79) ───────────────────────────────────────
        # HttpServletResponse output sinks with variable arguments.
        # Pattern 1: format/printf with variable as format string (not literal)
        # TP: response.getWriter().format(param, obj)
        (
            r"""\.getWriter\s*\(\s*\)\s*\.(?:format|printf)\s*\(\s*(?:java\.util\.Locale\.\w+\s*,\s*)?(?!["'])(\w+)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-xss",
            "XSS — user-controlled format string written to HTTP response",
            "Escape output with ESAPI.encoder().encodeForHTML() or use a templating engine with auto-escaping",
        ),
        # Pattern 2: write/print/println with variable arg (not string literal)
        # TP: response.getWriter().write(param), .println(bar)
        (
            r"""\.getWriter\s*\(\s*\)\s*\.(?:write|print|println)\s*\(\s*(?!["'])(\w+)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-xss",
            "XSS — variable written directly to HTTP response",
            "Escape output with ESAPI.encoder().encodeForHTML() or use a templating engine with auto-escaping",
        ),
        # Pattern 3: write with string concat: write("text" + param)
        # TP: response.getWriter().write("Parameter value: " + param)
        (
            r"""\.getWriter\s*\(\s*\)\s*\.(?:write|print|println)\s*\(\s*["'][^"']*["']\s*\+\s*\w+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-xss",
            "XSS — string concatenation with variable written to HTTP response",
            "Escape output with ESAPI.encoder().encodeForHTML() or use a templating engine with auto-escaping",
        ),
        # Pattern 4: format/printf with literal format string + obj args (taint may be in args)
        # TP: response.getWriter().format("Formatted like: %1$s and %2$s.", obj)
        # where obj = {"a", bar} — taint is in the array
        (
            r"""\.getWriter\s*\(\s*\)\s*\.(?:format|printf)\s*\(\s*(?:java\.util\.Locale\.\w+\s*,\s*)?["'][^"']*%\d*\$?[sd][^"']*["']\s*,\s*\w+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-xss",
            "XSS — format string output may contain user-controlled data in arguments",
            "Escape all arguments with ESAPI.encoder().encodeForHTML() before formatting",
        ),
        # Pattern 5: PrintWriter variable (out = response.getWriter()) then out.write/print
        # TP: out.write(bar), out.println(param)
        # Excludes System.out which is console logging, not HTTP response
        (
            r"""(?<!System\.)(?<!System)\bout\.(?:write|print|println|printf|format)\s*\(\s*(?!["'])(\w+)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-xss",
            "XSS — variable written to HTTP response via PrintWriter",
            "Escape output with ESAPI.encoder().encodeForHTML() or use a templating engine with auto-escaping",
        ),
        # ─── Java Command Injection (CWE-78) ─────────────────────────
        # Runtime.exec() with string concatenation: r.exec(cmd + bar)
        (
            r"""\.exec\s*\([^)]*\+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-cmdi",
            "Command injection — string concatenation in exec()",
            "Use ProcessBuilder with explicit argument list (no shell), validate inputs against allowlist",
        ),
        # ProcessBuilder/argList: .add("echo " + param)
        (
            r"""(?:ProcessBuilder|\.command)\s*\(.*\.add\s*\(\s*["'][^"']*["']\s*\+\s*(?!["'])\w+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-cmdi",
            "Command injection — string concatenation in process command argument",
            "Use ProcessBuilder with explicit argument list (no shell), validate inputs against allowlist",
        ),
        # Array init with concat: String[] args = {a1, a2, "echo " + param} or {a1, a2, cmd + bar}
        # Matches both new String[]{...} and implicit String[] x = {...}
        (
            r"""(?:new\s+String\s*\[\s*\]\s*|String\s*\[\s*\]\s*\w+\s*=\s*)\{[^}]*["']\s*\+\s*\w+[^}]*\}""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-cmdi",
            "Command injection — string concatenation in command array",
            "Use ProcessBuilder with explicit argument list (no shell), validate inputs against allowlist",
        ),
        # Array init with variable + variable concat (no string literal)
        (
            r"""(?:new\s+String\s*\[\s*\]\s*|String\s*\[\s*\]\s*\w+\s*=\s*)\{[^}]*\b(?:cmd|command)\s*\+\s*\w+[^}]*\}""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-cmdi",
            "Command injection — variable concatenation in command array",
            "Use ProcessBuilder with explicit argument list (no shell), validate inputs against allowlist",
        ),
        # ProcessBuilder.command(args) — command set from variable
        (
            r"""\.command\s*\(\s*(?!["'])([a-z]\w*)\s*\)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-cmdi",
            "Command injection — variable passed to ProcessBuilder.command()",
            "Validate command arguments against an allowlist",
        ),
        # Environment injection: String[] argsEnv = {variable} (not string literal)
        (
            r"""argsEnv\s*=\s*\{\s*(?!["'])\w+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-cmdi",
            "Command injection — user-controlled environment variable in process execution",
            "Sanitize environment variables or use a fixed environment",
        ),
        # ─── Java LDAP Injection (CWE-90) ────────────────────────────
        # String concatenation into LDAP filter string (uid= + param pattern)
        (
            r"""["'].*(?:uid|cn|sn|mail|ou|dc)\s*=\s*["']\s*\+\s*\w+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-ldap-injection",
            "LDAP injection — string concatenation in LDAP filter",
            "Use parameterized LDAP queries or escape special characters with LdapEncoder",
        ),
        # ─── Java XPath Injection (CWE-643) ──────────────────────────
        # String concatenation into XPath expression followed by evaluate()
        (
            r"""["'].*(?:@\w+|/\w+)\s*=\s*'["']\s*\+\s*\w+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-xpath-injection",
            "XPath injection — string concatenation in XPath expression",
            "Use XPath parameterization (XPathVariableResolver) or validate/escape input",
        ),
        # ─── Java Path Traversal (CWE-22) ────────────────────────────
        # File I/O constructors with a variable argument (not a string literal)
        (
            r"""new\s+(?:java\.io\.)?(?:File(?:Input|Output)?Stream|File(?:Reader|Writer)?|RandomAccessFile)\s*\(\s*(?:new\s+(?:java\.io\.)?File\s*\()?\s*[a-z]\w*\s*[,)]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-path-traversal",
            "Path traversal — variable input in file I/O constructor",
            "Validate and canonicalize file paths before use",
        ),
        # new File(variable) — single-arg constructor with non-literal
        (
            r"""new\s+(?:java\.io\.)?File\s*\(\s*[a-z]\w*\s*[,)]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-path-traversal",
            "Path traversal — variable input in File constructor",
            "Validate and canonicalize file paths before use",
        ),
        # new File(anything, variable) — two-arg constructor with variable as second arg
        # Catches: new File(TESTFILES_DIR, bar), new File(new File(...), bar)
        # Uses .+ for first arg to handle nested constructors like new File(new File(...), bar)
        (
            r"""new\s+(?:java\.io\.)?File\s*\([^)]+,\s*[a-z]\w*\s*\)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-path-traversal",
            "Path traversal — variable path component in File constructor",
            "Validate and canonicalize file paths before use",
        ),
        # new FileInputStream(new File(variable)) — nested File in stream constructor
        (
            r"""new\s+(?:java\.io\.)?(?:FileInputStream|FileOutputStream|FileReader|FileWriter)\s*\(\s*new\s+(?:java\.io\.)?File\s*\(\s*[a-z]\w*\s*\)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-path-traversal",
            "Path traversal — variable input in nested File/stream constructor",
            "Validate and canonicalize file paths before use",
        ),
        # Paths.get(variable) — NIO path with non-literal
        (
            r"""(?:java\.nio\.file\.)?Paths\.get\s*\(\s*[a-z]\w*\s*[,)]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "java-path-traversal",
            "Path traversal — variable input in Paths.get()",
            "Validate and canonicalize file paths before use",
        ),
    ]
)
