"""Cross-language security rules — applied to all languages."""

from __future__ import annotations  # noqa

from ..types import Category, Severity
from ._compile import Rule, _compile

SECURITY_RULES: list[Rule] = _compile(
    [
        # Path traversal — excludes require() since require('../..') is standard
        # Node.js module resolution, not user-controlled path construction
        (
            r"""(?:open|read|write|include)\s*\([^)]*\.\./""",
            Severity.CRITICAL,
            Category.SECURITY,
            "path-traversal",
            "Possible path traversal attack with ../",
            "Validate and sanitize file paths",
        ),
        # Private key (RSA, EC, DSA, OPENSSH)
        (
            r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----",
            Severity.CRITICAL,
            Category.SECURITY,
            "private-key",
            "Private key found in source code",
            "Remove immediately and rotate the key",
        ),
        # Database connection strings with embedded credentials
        (
            r"""(?i)(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|amqp|jdbc:[a-z]+)://[^:]+:[^@]+@""",
            Severity.CRITICAL,
            Category.SECURITY,
            "db-connection-string",
            "Database connection string with embedded credentials",
            "Use environment variables for connection strings",
        ),
        # Logging sensitive data — require variable/attribute reference, not just keyword mention
        (
            r"""(?i)(?:log(?:ger)?\.(?:info|debug|warn|error|critical|warning)|print|console\.log|puts)\s*\(.*\b(?:password|passwd|secret_key|api_key|auth_token|credential)\b""",
            Severity.WARNING,
            Category.SECURITY,
            "logging-sensitive-data",
            "Possibly logging sensitive data (password, secret, token)",
            "Redact sensitive values before logging",
        ),
        # logging.config.listen — accepts arbitrary logging config over network
        (
            r"""logging\.config\.listen\s*\(""",
            Severity.CRITICAL,
            Category.SECURITY,
            "logging-config-listen",
            "logging.config.listen() accepts config over network — can load arbitrary handler classes (RCE)",  # doji:ignore(logging-config-listen)
            "Avoid network-based logging config; use file-based or environment-based config instead",
        ),
        # Insecure crypto: DES
        (
            r"""\bDES\b\.new\(|\bDES\.(?:encrypt|decrypt)\b|from\s+Crypto\.Cipher\s+import\s+DES\b""",
            Severity.WARNING,
            Category.SECURITY,
            "insecure-crypto",
            "DES encryption is broken — 56-bit keys are trivially brute-forced",
            "Use AES-256 or ChaCha20 instead",
        ),
        # Insecure crypto: ECB mode
        (
            r"""(?i)(?:MODE_ECB|mode\s*=\s*['"]?ECB|\.ECB\b)""",  # doji:ignore(insecure-ecb-mode)
            Severity.WARNING,
            Category.SECURITY,
            "insecure-ecb-mode",
            "ECB mode does not hide data patterns — insecure for most uses",
            "Use CBC, GCM, or CTR mode instead",
        ),
        # Insecure crypto: Blowfish — 64-bit block cipher, birthday attacks feasible
        (
            r"""\bBlowfish\b\.new\(|\bBlowfish\.(?:encrypt|decrypt)\b|from\s+Crypto\.Cipher\s+import\s+Blowfish\b""",
            Severity.WARNING,
            Category.SECURITY,
            "insecure-crypto",
            "Blowfish has 64-bit blocks — vulnerable to birthday attacks at scale",
            "Use AES-256 or ChaCha20 instead",
        ),
        # Insecure crypto: RC4/ARC4 — broken stream cipher
        (
            r"""\bARC4\b\.new\(|\bARC4\.(?:encrypt|decrypt)\b|from\s+Crypto\.Cipher\s+import\s+ARC4\b|\bRC4\b""",
            Severity.WARNING,
            Category.SECURITY,
            "insecure-crypto",
            "RC4/ARC4 is a broken stream cipher with known biases",  # doji:ignore(insecure-rc4)
            "Use AES-GCM or ChaCha20-Poly1305 instead",
        ),
        # requests without timeout — can hang indefinitely
        (
            r"""requests\.(?:get|post|put|delete|patch|head|request)\s*\([^)]*\)\s*(?!.*timeout)""",
            Severity.WARNING,
            Category.SECURITY,
            "requests-no-timeout",
            "HTTP request without timeout — can hang indefinitely",
            "Always pass timeout= to requests calls",
        ),
        # SSRF — URL constructed from user input passed to HTTP clients
        # Skip url_for() (framework-generated URLs) and fetch('/...' (relative paths)
        (
            r"""(?:requests\.(?:get|post|put|delete|patch|head)\s*\(|urllib\.request\.urlopen\s*\(|http\.client\.HTTP\w*Connection\s*\(|fetch\s*\(\s*(?!['"]/)(?!url_for)|axios\.(?:get|post|put|delete)\s*\(|http\.Get\s*\(|http\.Post\s*\()(?!.*url_for\s*\()""",
            Severity.WARNING,
            Category.SECURITY,
            "ssrf-risk",
            "HTTP request — verify URL is not constructed from user input (SSRF risk)",
            "Validate URLs against an allowlist of domains/schemes before making requests",
        ),
        # URL open scheme audit — urlopen/urlretrieve accept file:// and custom schemes
        (
            r"""(?:urllib\.request\.urlopen\s*\(|urllib\.request\.urlretrieve\s*\(|urlopen\s*\()""",
            Severity.WARNING,
            Category.SECURITY,
            "url-scheme-audit",
            "urlopen permits file:/ and custom schemes — verify URL scheme is restricted to https",
            "Validate URL scheme against allowlist (e.g., only https://) before opening",
        ),
        # SSTI — template rendering from string (not file)
        # Excludes: function definitions, calls with immediate string literal args (safe)
        (
            r"""(?<!def )(?:Template\s*\((?!\s*['"])|render_template_string\s*\((?!\s*['"])|from_string\s*\((?!\s*['"])|Environment\s*\(\s*\)\.from_string|Jinja2\s*\(.*\bstring\b|new\s+Function\s*\()""",
            Severity.CRITICAL,
            Category.SECURITY,
            "ssti-risk",
            "Template constructed from string — may allow server-side template injection",
            "Use pre-compiled templates from files, never from user-controlled strings",
        ),
        # XXE — XML parsing without disabling external entities
        # Catches both fully-qualified (xml.etree.ElementTree.parse) and aliased (ET.parse) forms
        (
            r"""(?:xml\.etree\.ElementTree\.(?:parse|fromstring|iterparse)\s*\(|xml\.dom\.minidom\.(?:parse|parseString)\s*\(|xml\.sax\.(?:parse|parseString)\s*\(|lxml\.etree\.(?:parse|fromstring|iterparse)\s*\(|DocumentBuilderFactory|XMLReader|SAXParser|DOMParser\s*\(\)|ET\.(?:parse|fromstring|iterparse)\s*\(|etree\.(?:parse|fromstring|iterparse)\s*\(|minidom\.(?:parse|parseString)\s*\(|sax\.(?:parse|parseString)\s*\()""",  # doji:ignore(xxe-risk)
            Severity.WARNING,
            Category.SECURITY,
            "xxe-risk",
            "XML parsing — ensure external entities are disabled to prevent XXE attacks",
            "Use defusedxml (Python), disable DTDs/external entities in parser config",
        ),
        # JWT — insecure algorithm or missing verification
        (
            r"""(?:jwt\.decode\s*\([^)]*(?:algorithms\s*=\s*\[['"]none['"]\]|verify\s*=\s*False|options\s*=\s*\{[^}]*'verify_\w+'\s*:\s*False)|\.decode\s*\(\s*token[^)]*algorithm\s*=\s*['"](?:none|HS256)['"])""",
            Severity.CRITICAL,
            Category.SECURITY,
            "jwt-insecure",
            "JWT decoded with insecure settings — disabled verification or 'none' algorithm",
            "Always verify JWT signatures with a strong algorithm (RS256/ES256) and validate claims",
        ),
        # Hardcoded IP addresses (not localhost/0.0.0.0)
        (
            r"""(?<!\d)(?!127\.0\.0\.1|0\.0\.0\.0|255\.255\.255\.255)(?:(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)\.){3}(?:25[0-5]|2[0-4]\d|1\d\d|[1-9]\d|\d)(?!\d)""",
            Severity.INFO,
            Category.SECURITY,
            "hardcoded-ip",
            "Hardcoded IP address — may break in different environments",
            "Use configuration files or environment variables for IP addresses",
        ),
        # Binding to all interfaces
        (
            r"""(?:\.bind|\.run|start_server|HTTPServer|TCPServer|UDPServer|SimpleXMLRPCServer|ThreadingTCPServer|ForkingTCPServer|BaseManager|SyncManager)\s*\([^)]*['"]0\.0\.0\.0['"]|=\s*['"]0\.0\.0\.0['"]""",
            Severity.WARNING,
            Category.SECURITY,
            "bind-all-interfaces",
            "Binding to 0.0.0.0 exposes the service to all network interfaces",
            "Bind to specific interface (127.0.0.1 for local-only, or configure via env var)",
        ),
        # TOCTOU: check-then-use file race conditions
        (
            r"\bos\.path\.(?:exists|isfile|isdir)\s*\(\s*\w+\s*\)",
            Severity.INFO,
            Category.SECURITY,
            "toctou-file-check",
            "File existence check before use — potential TOCTOU race condition",
            "Use try/except around the file operation instead of checking first",
        ),
    ]
)
