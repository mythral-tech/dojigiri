"""Language-specific bug patterns — regex rules for static analysis.

Defines compiled regex rules for each supported language (Python, JS/TS, Go,
Java, C/C++, etc.), each tagged with a Severity and Category.

Called by: detector.py.
Calls into: config.py (Severity and Category enums only).
Data in → Data out: language string in → list[Rule] out.
"""

from __future__ import annotations

import re

from .types import Category, Severity

# Each rule: (pattern, severity, category, rule_name, message, suggestion)
# pattern can be a compiled regex or a string (compiled at load time)

Rule = tuple[re.Pattern, Severity, Category, str, str, str | None]


def _compile(rules: list[tuple]) -> list[Rule]:
    compiled = []
    for pat, sev, cat, name, msg, sug in rules:
        compiled.append((re.compile(pat), sev, cat, name, msg, sug))
    return compiled


# ─── Universal (all languages) ────────────────────────────────────────

UNIVERSAL_RULES: list[Rule] = _compile(
    [
        # Secrets & credentials — exclude common placeholder values
        (
            r"""(?i)(?<!\w)(?!(?:fake|mock|dummy|stub)[_-])(?:api[_-]?key|secret[_-]?key|secret|password|passwd|token|auth[_-]?token|jwt[_-]?secret|signing[_-]?key|encryption[_-]?key|private[_-]?key|client[_-]?secret|\w+[_-](?:secret|token|password|passwd|pass|key))\s*[:=]\s*['"](?!(?:demo|example|placeholder|test|sample|changeme|change[_-]me|your[_-]?|xxx|TODO|INSERT|REPLACE)[_\-0-9'"])[A-Za-z0-9+/=_\-!@#$%^&*]{8,}['"]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "hardcoded-secret",
            "Possible hardcoded secret or API key",
            "Use environment variables or a secrets manager",
        ),
        # Secrets in dict literals: "password": "value" or 'api_key': 'value'
        (
            r"""(?i)['"](?:api[_-]?key|secret[_-]?key|password|passwd|token|auth[_-]?token|database[_-]?password|db[_-]?password|aws[_-]?secret[_-]?\w*|client[_-]?secret|private[_-]?key|encryption[_-]?key|signing[_-]?key|\w+[_-]secret[_-]?\w*key|\w+[_-]secret)['"]\s*:\s*['"](?!(?:demo|example|placeholder|test|sample|changeme|change[_-]me|your[_-]?|xxx|TODO|INSERT|REPLACE)[_\-0-9'"])[A-Za-z0-9+/=_\-!@#$%^&*.]{8,}['"]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "hardcoded-secret",
            "Possible hardcoded secret in dict/config literal",
            "Use environment variables or a secrets manager",
        ),
        (
            r"""(?i)(?:aws[_-]?access|aws[_-]?secret)\s*[:=]\s*['"][A-Za-z0-9+/=]{16,}['"]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "aws-credentials",
            "Possible hardcoded AWS credentials",
            "Use IAM roles or environment variables",
        ),
        # TODO/FIXME — only in comment lines (# or //)
        (
            r"(?i)(?:^|\s)(?:#|//).*\b(?:TODO|FIXME|HACK|XXX)\b",
            Severity.INFO,
            Category.STYLE,
            "todo-marker",
            "TODO/FIXME marker found",
            None,
        ),
        # Long lines
        (
            r"^.{201,}$",
            Severity.INFO,
            Category.STYLE,
            "long-line",
            "Line exceeds 200 characters",
            "Break into multiple lines for readability",
        ),
        # Insecure HTTP — skip namespace URIs (xmlns, W3C, schemas, purl),
        # data: URIs, and XML namespace declarations
        (
            r"""(?!.*(?:xmlns\s*=|data:))['"]http://(?!localhost|127\.0\.0\.1|0\.0\.0\.0|www\.w3\.org/|schemas\.|purl\.org/|xml\.org/|relaxng\.org/|docbook\.org/|openid\.net/|ogp\.me/)""",
            Severity.WARNING,
            Category.SECURITY,
            "insecure-http",
            "Insecure HTTP URL (not localhost)",
            "Use HTTPS instead",
        ),
        # SQL injection patterns (f-strings, %, +, .format)
        (
            r"""(?i)(?:execute(?:many)?|cursor\.execute(?:many)?|query|\.execute)\s*\(\s*(?:f['"]|['"].*?%s|['"].*?\+\s*\w+|['"].*?\{)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Possible SQL injection — string interpolation in query",
            "Use parameterized queries",
        ),
        # SQL injection via .format() on query strings
        (
            r"""(?i)['"](?:SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER)\b.*?['"]\.format\s*\(""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Possible SQL injection — .format() on SQL string",
            "Use parameterized queries instead of string formatting",
        ),
        # SQL injection via text() wrapping with interpolation
        (
            r"""(?i)\btext\s*\(\s*f['"]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Possible SQL injection — f-string inside text()",
            "Use text() with :param bindparams instead",
        ),
        # SQL injection via + concatenation on SQL keywords
        (
            r"""(?i)['"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b.*?['"]\s*\+""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Possible SQL injection — string concatenation on SQL query",
            "Use parameterized queries instead of string concatenation",
        ),
        # SQL injection via % formatting on SQL keywords
        (
            r"""(?i)['"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^'"]*%s[^'"]*['"]\s*%""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Possible SQL injection — % formatting on SQL query",
            "Use parameterized queries instead of % formatting",
        ),
        # Django ORM .raw() with f-string or format — SQL injection
        (
            r"""\.raw\s*\(\s*(?:f['"]|['"].*?\.format\s*\(|['"].*?%s)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "sql-injection",
            "Django .raw() with string interpolation — SQL injection",
            "Use .raw() with parameterized query: Model.objects.raw('SELECT ... WHERE id = %s', [user_id])",
        ),
    ]
)


# ─── Python ───────────────────────────────────────────────────────────

PYTHON_RULES: list[Rule] = _compile(
    [
        # Bare except
        (
            r"^\s*except\s*:",
            Severity.WARNING,
            Category.BUG,
            "bare-except",
            "Bare except catches all exceptions including SystemExit and KeyboardInterrupt",
            "Use 'except Exception:' to avoid catching KeyboardInterrupt/SystemExit",
        ),
        # Mutable default argument (simple single-line heuristic; AST check handles multiline)
        (
            r"def\s+\w+\s*\([^)]*=\s*(?:\[\]|\{\}|set\(\))",
            Severity.WARNING,
            Category.BUG,
            "mutable-default",
            "Mutable default argument — shared across all calls",
            "Use None as default and create inside function body",
        ),
        # == None / != None
        (
            r"(?:==|!=)\s*None",
            Severity.WARNING,
            Category.STYLE,
            "none-comparison",
            "Use 'is None' or 'is not None' instead of == / !=",
            "Replace with 'is None' or 'is not None'",
        ),
        # eval/exec
        (
            r"\beval\s*\(",
            Severity.CRITICAL,
            Category.SECURITY,
            "eval-usage",
            "eval() can execute arbitrary code",
            "Use ast.literal_eval() for safe evaluation, or avoid entirely",
        ),
        (
            r"\bexec\s*\(",
            Severity.CRITICAL,
            Category.SECURITY,
            "exec-usage",
            "exec() can execute arbitrary code",
            "Avoid exec() — restructure code to not need it",
        ),
        # open() without with — simple heuristic: assignment of open() on a line not starting with "with"
        (
            r"^(?!\s*with\s)\s*\w+\s*=\s*open\s*\(",
            Severity.WARNING,
            Category.BUG,
            "open-without-with",
            "File opened without 'with' statement — may not be closed on error",
            "Use 'with open(...) as f:' for automatic cleanup",
        ),
        # os.system / subprocess with shell=True
        (
            r"\bos\.system\s*\(",  # doji:ignore(os-system)
            Severity.WARNING,
            Category.SECURITY,
            "os-system",
            "os.system() is vulnerable to shell injection",
            "Use subprocess.run() with a list of arguments",
        ),
        (
            r"subprocess\.\w+\([^)]*shell\s*=\s*True",
            Severity.WARNING,
            Category.SECURITY,
            "shell-true",
            "subprocess with shell=True is vulnerable to injection",
            "Pass command as a list without shell=True",
        ),
        # subprocess call audit — flag any subprocess.run/call/Popen for review
        # Excludes: calls with hardcoded list args like subprocess.run(["git", ...])
        (
            r"subprocess\.(?:run|call|check_call|check_output|Popen)\s*\((?!\s*\[)",
            Severity.INFO,
            Category.SECURITY,
            "subprocess-audit",
            "subprocess call — verify input is not constructed from untrusted data",
            "Ensure command arguments are hardcoded or validated, never from raw user input",
        ),
        # Star imports
        (
            r"^from\s+\S+\s+import\s+\*",
            Severity.WARNING,
            Category.STYLE,
            "star-import",
            "Star import pollutes namespace and hides dependencies",
            "Import specific names instead",
        ),
        # assert in production
        (
            r"(?:^\s*|[;:]\s*)assert\s+",
            Severity.INFO,
            Category.BUG,
            "assert-statement",
            "Assert statements are stripped with -O flag",
            "Use explicit if/raise for production checks",
        ),
        # f-string without expression — must match f"..." with NO { inside at all
        # Uses negative lookahead to avoid matching strings that contain braces.
        # Skips triple-quoted f-strings (expressions may be on later lines) and
        # handles escaped quotes (\" inside f"...") correctly.
        (
            r"""(?<!\w)f(['"])(?!\1\1)(?:(?:\\.|(?!\{)(?!\1)[^\\]))*\1""",
            Severity.INFO,
            Category.STYLE,
            "fstring-no-expr",
            "f-string without any expressions — unnecessary f prefix",
            "Remove the f prefix",
        ),
        # Unsafe pickle deserialization
        (
            r"\bpickle\.(?:loads?\s*\(|Unpickler\s*\()",  # doji:ignore(pickle-unsafe)
            Severity.CRITICAL,
            Category.SECURITY,
            "pickle-unsafe",
            "pickle.load()/loads()/Unpickler() can execute arbitrary code during deserialization",
            "Use json, msgpack, or a safe serialization format instead",
        ),
        # Pickle alternatives — equally dangerous
        (
            r"\b(?:dill|cloudpickle|shelve)\.loads?\s*\(",
            Severity.CRITICAL,
            Category.SECURITY,
            "pickle-unsafe",
            "Pickle-equivalent deserialization — can execute arbitrary code",
            "Use json, msgpack, or a safe serialization format instead",
        ),
        # jsonpickle — JSON wrapper around pickle
        (
            r"\bjsonpickle\.(?:decode|loads?)\s*\(",
            Severity.CRITICAL,
            Category.SECURITY,
            "pickle-unsafe",
            "jsonpickle can execute arbitrary code via crafted JSON",
            "Use json.loads() for safe JSON deserialization",
        ),
        # Unsafe yaml.load — flag any yaml.load( call; detector will suppress if SafeLoader found nearby
        (
            r"\byaml\.load\s*\(",
            Severity.CRITICAL,
            Category.SECURITY,
            "yaml-unsafe",
            "yaml.load() without SafeLoader can execute arbitrary code",
            "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",
        ),
        # yaml.load_all and yaml.unsafe_load — same risk
        (
            r"\byaml\.(?:load_all|unsafe_load|unsafe_load_all)\s*\(",
            Severity.CRITICAL,
            Category.SECURITY,
            "yaml-unsafe",
            "yaml.load_all()/unsafe_load() can execute arbitrary code",
            "Use yaml.safe_load_all() instead",
        ),
        # Weak hash algorithms (called or passed as reference)
        (
            r"""\bhashlib\.(?:md5|sha1)\b|\bhashlib\.new\s*\(\s*['"](?:md5|sha1)['"]""",
            Severity.WARNING,
            Category.SECURITY,
            "weak-hash",
            "MD5/SHA1 are cryptographically weak hash algorithms",
            "Use hashlib.sha256() or stronger for security-sensitive hashing",
        ),
        # Weak random (not cryptographically secure)
        (
            r"\brandom\.(?:choice|randint|random|uniform|randrange|shuffle|sample)\s*\(",
            Severity.INFO,
            Category.SECURITY,
            "weak-random",
            "random module is not cryptographically secure",
            "Use secrets module for security-sensitive random values",
        ),
        # Unsafe deserialization — marshal and shelve
        (
            r"\b(?:marshal\.loads?\s*\(|shelve\.open\s*\()",
            Severity.CRITICAL,
            Category.SECURITY,
            "unsafe-deserialization",
            "marshal/shelve can execute arbitrary code during deserialization",
            "Use json or msgpack for untrusted data; shelve is pickle-backed",
        ),
        # Insecure tempfile usage
        (
            r"\b(?:tempfile\.mktemp\s*\(|os\.tempnam\s*\(|os\.tmpnam\s*\()",
            Severity.WARNING,
            Category.SECURITY,
            "insecure-tempfile",
            "mktemp/tempnam/tmpnam are vulnerable to race conditions (TOCTOU)",
            "Use tempfile.mkstemp() or tempfile.NamedTemporaryFile() instead",
        ),
        # os.exec* family — replaces current process
        (
            r"\bos\.exec(?:l|le|lp|lpe|v|ve|vp|vpe)\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "os-exec",
            "os.exec*() replaces the current process — verify arguments are trusted",
            "Use subprocess.run() for better control and input validation",
        ),
        # os.spawn* family — spawns new process
        (
            r"\bos\.spawn(?:l|le|lp|lpe|v|ve|vp|vpe)\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "os-spawn",
            "os.spawn*() spawns a new process — verify arguments are trusted",
            "Use subprocess.run() for better control and input validation",
        ),
        # os.popen — shell process, injection risk
        (
            r"\bos\.popen\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "os-popen",
            "os.popen() starts a shell process — vulnerable to injection",
            "Use subprocess.run() with a list of arguments instead",
        ),
        # subprocess.getoutput / getstatusoutput — always use shell
        (
            r"\bsubprocess\.(?:getoutput|getstatusoutput)\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "subprocess-shell",
            "subprocess.getoutput()/getstatusoutput() always uses shell — vulnerable to injection",
            "Use subprocess.run() with a list of arguments instead",
        ),
        # os.startfile — opens file with default handler (Windows)
        (
            r"\bos\.startfile\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "os-startfile",
            "os.startfile() opens file with default handler — could launch executables",
            "Validate file type and path before opening",
        ),
        # os.chmod with permissive mask (world-writable/executable)
        (
            r"\bos\.chmod\s*\([^)]*,\s*0o?[0-7](?:[1-35-7][0-7]|[0-7][1-35-7])\b",
            Severity.WARNING,
            Category.SECURITY,
            "insecure-file-permissions",
            "os.chmod() with overly permissive mode — world-writable or world-readable+executable",
            "Use restrictive permissions (e.g., 0o600 for owner-only read/write)",
        ),
        # Jinja2 Environment without autoescape — XSS risk
        (
            r"\bEnvironment\s*\(\s*\)|\bEnvironment\s*\([^)]*autoescape\s*=\s*False",
            Severity.WARNING,
            Category.SECURITY,
            "jinja2-autoescape-off",
            "Jinja2 Environment with autoescape disabled — XSS risk",
            "Use autoescape=True or select_autoescape() for HTML templates",
        ),
        # pyCrypto is unmaintained — use pycryptodome
        (
            r"from\s+Crypto(?:\.Cipher)?\s+import\s+",
            Severity.INFO,
            Category.SECURITY,
            "pycrypto-deprecated",
            "pyCrypto is unmaintained and has known vulnerabilities",
            "Switch to pycryptodome (same API, maintained fork)",
        ),
        # ssl.wrap_socket — deprecated, no cert verification by default
        (
            r"\bssl\.wrap_socket\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "ssl-wrap-socket",
            "ssl.wrap_socket() is deprecated and does not verify certificates by default",
            "Use ssl.SSLContext.wrap_socket() with proper cert verification",
        ),
        # requests with verify=False — disables SSL cert verification
        (
            r"(?:requests|httpx)\.(?:get|post|put|delete|patch|head|options|request)\s*\([^)]*verify\s*=\s*False",
            Severity.WARNING,
            Category.SECURITY,
            "requests-no-verify",
            "requests call with verify=False disables SSL certificate verification",
            "Remove verify=False to enable certificate verification (default behavior)",
        ),
        # Session-level verify=False
        (
            r"\.verify\s*=\s*False",
            Severity.WARNING,
            Category.SECURITY,
            "ssl-verify-disabled",
            "SSL certificate verification disabled — vulnerable to MITM attacks",
            "Enable certificate verification or use a custom CA bundle",
        ),
        # ssl._create_unverified_context() — explicitly skips verification
        (
            r"\bssl\._create_unverified_context\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "ssl-verify-disabled",
            "ssl._create_unverified_context() disables all certificate verification",
            "Use ssl.create_default_context() for verified connections",
        ),
        # ssl.CERT_NONE — disables certificate verification
        (
            r"\bssl\.CERT_NONE\b",
            Severity.WARNING,
            Category.SECURITY,
            "ssl-verify-disabled",
            "ssl.CERT_NONE disables certificate verification — MITM risk",
            "Use ssl.CERT_REQUIRED for certificate verification",
        ),
        # Hardcoded /tmp directory — predictable location, symlink attacks
        (
            r"""['"]\/(?:tmp|var\/tmp)\/""",
            Severity.INFO,
            Category.SECURITY,
            "hardcoded-tmp",
            "Hardcoded /tmp path — predictable location vulnerable to symlink attacks",
            "Use tempfile.mkdtemp() or tempfile.NamedTemporaryFile() for secure temp files",
        ),
        # Password as default function argument
        (
            r"""def\s+\w+\s*\([^)]*(?:password|secret|secret_key|api_key|token)\s*(?::\s*\w+\s*)?=\s*['"][^'"]+['"]""",
            Severity.WARNING,
            Category.SECURITY,
            "hardcoded-password-default",
            "Default secret/password in function signature — visible in source and help()",
            "Use None as default and require explicit argument or env var",
        ),
        # Django DEBUG=True
        (
            r"(?:^\s*DEBUG\s*=\s*True\b|\.run\s*\([^)]*debug\s*=\s*True)",
            Severity.WARNING,
            Category.SECURITY,
            "debug-enabled",
            "DEBUG=True may expose sensitive information in production",
            "Set DEBUG=False in production and use environment variables",
        ),
        # compile() with user input — code compilation
        (
            r"\bcompile\s*\([^)]*,\s*['\"]<(?:string|input)>['\"]",
            Severity.WARNING,
            Category.SECURITY,
            "compile-usage",
            "compile() can compile arbitrary code — verify input is trusted",
            "Use ast.literal_eval() for safe evaluation of data literals",
        ),
        # User-controlled regex — ReDoS risk
        (
            r"\bre\.(?:compile|search|match|findall|sub|split)\s*\(\s*(?![bruf]*['\"])\w+",
            Severity.INFO,
            Category.SECURITY,
            "regex-injection",
            "Regex pattern from variable — potential ReDoS if user-controlled",
            "Use re.escape() on user input or set a timeout with regex module",
        ),
        # http.client.HTTPConnection — unencrypted
        (
            r"\bhttp\.client\.HTTPConnection\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "http-connection-cleartext",
            "HTTPConnection uses unencrypted HTTP",
            "Use http.client.HTTPSConnection for encrypted connections",
        ),
        # Archive extraction without path validation — zip/tar slip
        (
            r"\b(?:zipfile\.ZipFile|ZipFile)\s*\([^)]*\).*\.extractall\s*\(|\.extractall\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "archive-slip",
            "Archive extractall() without path validation — zip/tar slip attack",
            "Validate member paths before extraction or use extraction filters",
        ),
        # tarfile.open + extractall
        (
            r"\btarfile\.open\b",
            Severity.INFO,
            Category.SECURITY,
            "tarfile-open",
            "tarfile.open() — ensure extractall() uses data_filter or validates member paths",
            "Use tf.extractall(filter='data') (Python 3.12+) or validate each member",
        ),
        # Unencrypted protocols — FTP
        (
            r"\bftplib\.FTP\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "unencrypted-ftp",
            "FTP transmits credentials and data in cleartext",
            "Use ftplib.FTP_TLS or SFTP (paramiko) instead",
        ),
        # Unencrypted protocols — Telnet
        (
            r"\btelnetlib\.Telnet\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "unencrypted-telnet",
            "Telnet transmits everything in cleartext — inherently insecure",
            "Use SSH (paramiko) instead of telnet",
        ),
        # Unencrypted protocols — SMTP without TLS
        (
            r"\bsmtplib\.SMTP\s*\(",
            Severity.INFO,
            Category.SECURITY,
            "smtp-cleartext",
            "SMTP connection may transmit credentials in cleartext",
            "Use smtplib.SMTP_SSL or call starttls() immediately after connecting",
        ),
        # webbrowser.open with variable — arbitrary URL scheme
        (
            r"\bwebbrowser\.open\s*\(",
            Severity.INFO,
            Category.SECURITY,
            "webbrowser-open",
            "webbrowser.open() can open arbitrary URL schemes (file://, javascript:)",
            "Validate the URL scheme against an allowlist before opening",
        ),
        # ctypes library loading — arbitrary code execution
        (
            r"\bctypes\.(?:cdll|windll|oledll)\.LoadLibrary\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "ctypes-load-library",
            "Loading shared library via ctypes — arbitrary code execution if path is user-controlled",
            "Validate library path against allowlist, never accept user input",
        ),
        # shutil.rmtree — dangerous with user input
        (
            r"\bshutil\.rmtree\s*\(",
            Severity.INFO,
            Category.SECURITY,
            "rmtree-audit",
            "shutil.rmtree() recursively deletes — verify path is not user-controlled",
            "Validate path against a safe base directory before deletion",
        ),
        # importlib.import_module — dynamic module loading
        (
            r"\bimportlib\.import_module\s*\(\s*(?![bruf]*['\"])\w+",
            Severity.INFO,
            Category.SECURITY,
            "dynamic-import",
            "Dynamic module import — arbitrary code execution if module name is user-controlled",
            "Validate module name against an allowlist",
        ),
        # LD_PRELOAD / PATH / PYTHONPATH manipulation
        (
            r"""os\.environ\s*\[\s*['"](?:LD_PRELOAD|LD_LIBRARY_PATH|PATH|PYTHONPATH)['"]\s*\]\s*=""",
            Severity.WARNING,
            Category.SECURITY,
            "env-path-injection",
            "Modifying LD_PRELOAD/PATH/PYTHONPATH — can enable code injection",
            "Avoid modifying these environment variables at runtime",
        ),
        # sys.path manipulation
        (
            r"\bsys\.path\.(?:insert|append)\s*\(",
            Severity.INFO,
            Category.SECURITY,
            "sys-path-modify",
            "sys.path modification — could enable module hijacking if path is untrusted",
            "Avoid dynamic sys.path changes with untrusted paths",
        ),
        # Django mark_safe — XSS risk if content is user-controlled
        (
            r"\bmark_safe\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "django-mark-safe",
            "mark_safe() bypasses Django's auto-escaping — XSS risk if content is user-controlled",
            "Use format_html() or escape user content before marking safe",
        ),
        # Django QuerySet.extra() — raw SQL injection
        (
            r"\.extra\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "django-extra-sql",
            "QuerySet.extra() uses raw SQL — injection risk if values are user-controlled",
            "Use Django ORM methods (filter, annotate) instead of extra()",
        ),
        # Paramiko AutoAddPolicy — auto-accept unknown host keys
        (
            r"\bparamiko\.AutoAddPolicy\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "paramiko-auto-add-policy",
            "AutoAddPolicy() accepts unknown SSH host keys — vulnerable to MITM attacks",
            "Use RejectPolicy or manually verify host keys",
        ),
        # Paramiko exec_command — command injection if command is user-controlled
        (
            r"\.exec_command\s*\(",
            Severity.INFO,
            Category.SECURITY,
            "paramiko-exec-command",
            "SSH exec_command — verify command is not constructed from user input",
            "Validate and sanitize command arguments, use allowlist of commands",
        ),
        # Weak RSA key size (< 2048 bits)
        (
            r"key_size\s*=\s*(?:512|768|1024)\b",
            Severity.WARNING,
            Category.SECURITY,
            "weak-rsa-key",
            "RSA key size < 2048 bits is considered breakable",
            "Use key_size=2048 or higher (NIST recommends >= 2048)",
        ),
        # TripleDES — deprecated cipher
        (
            r"\bTripleDES\b|\b3DES\b|\bDES3\b",
            Severity.WARNING,
            Category.SECURITY,
            "insecure-crypto",
            "TripleDES/3DES is deprecated — slow and approaching theoretical breaks",
            "Use AES-256 or ChaCha20 instead",
        ),
        # ── Flask/Django security ─────────────────────────────────────────
        # Hardcoded SECRET_KEY — must be a string assignment, not env lookup
        (
            r"""^\s*SECRET_KEY\s*=\s*['"][A-Za-z0-9+/=_\-!@#$%^&*]{8,}['"]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "hardcoded-secret-key",
            "SECRET_KEY hardcoded in source — session hijacking and forgery risk",
            "Load SECRET_KEY from environment variable or secrets manager",
        ),
        # Django CSRF middleware disabled
        (
            r"""(?:MIDDLEWARE(?:_CLASSES)?)\s*=\s*\[(?:[^\]]*?)(?!.*CsrfViewMiddleware).*?\]""",
            Severity.WARNING,
            Category.SECURITY,
            "csrf-middleware-disabled",
            "CsrfViewMiddleware not found in MIDDLEWARE — CSRF protection disabled",
            "Add 'django.middleware.csrf.CsrfViewMiddleware' to MIDDLEWARE",
        ),
        # @csrf_exempt decorator — disables CSRF on specific view
        (
            r"@csrf_exempt\b",
            Severity.WARNING,
            Category.SECURITY,
            "csrf-exempt",
            "@csrf_exempt disables CSRF protection on this view",
            "Remove @csrf_exempt or implement alternative CSRF validation",
        ),
        # Django ALLOWED_HOSTS wildcard — allows any host header
        (
            r"""ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]""",
            Severity.WARNING,
            Category.SECURITY,
            "django-allowed-hosts-wildcard",
            "ALLOWED_HOSTS = ['*'] accepts any Host header — HTTP Host header attacks",
            "Set ALLOWED_HOSTS to specific domain names",
        ),
        # Django RawSQL / raw() — SQL injection risk
        (
            r"\.raw\s*\(\s*(?!['\"]SELECT\s)(?!['\"]INSERT\s)|RawSQL\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "django-raw-sql",
            "Raw SQL query — injection risk if parameters are not properly escaped",
            "Use Django ORM queries or pass parameters via the params argument",
        ),
        # Flask/Django unsafe redirect — open redirect via user input
        (
            r"\bredirect\s*\(\s*(?:request\.|f['\"]|[a-zA-Z_]\w*(?:\[|\.))",
            Severity.WARNING,
            Category.SECURITY,
            "unsafe-redirect",
            "Redirect target may be user-controlled — open redirect vulnerability",
            "Validate redirect URL against allowlist or use url_for()/reverse()",
        ),
        # Flask send_file with user input — path traversal
        (
            r"\bsend_file\s*\(\s*(?:request\.|f['\"]|os\.path\.join\s*\([^)]*request\.)",
            Severity.WARNING,
            Category.SECURITY,
            "flask-send-file-traversal",
            "send_file() with user-controlled path — directory traversal risk",
            "Use send_from_directory() with a fixed base directory instead",
        ),
        # ── Cryptography — weak TLS ──────────────────────────────────────
        # Weak TLS protocol versions — SSLv2, SSLv3, TLSv1, TLSv1.1
        (
            r"\bssl\.PROTOCOL_(?:SSLv2|SSLv3|SSLv23|TLSv1(?:_1)?)\b",
            Severity.CRITICAL,
            Category.SECURITY,
            "weak-tls-version",
            "Weak TLS protocol version — SSLv2/v3/TLS1.0/1.1 are broken or deprecated",
            "Use ssl.PROTOCOL_TLS_CLIENT or ssl.TLSVersion.TLSv1_2 minimum",
        ),
        # SSLContext with minimum_version set to broken protocol
        (
            r"minimum_version\s*=\s*ssl\.TLSVersion\.(?:SSLv3|TLSv1(?:_1)?)\b",
            Severity.CRITICAL,
            Category.SECURITY,
            "weak-tls-version",
            "TLS minimum version set to deprecated protocol",
            "Set minimum_version to ssl.TLSVersion.TLSv1_2 or TLSv1_3",
        ),
        # pyOpenSSL weak TLS method
        (
            r"\bSSL\.(?:SSLv2_METHOD|SSLv3_METHOD|SSLv23_METHOD|TLSv1_METHOD|TLSv1_1_METHOD)\b",
            Severity.CRITICAL,
            Category.SECURITY,
            "weak-tls-version",
            "pyOpenSSL weak TLS method — use TLS 1.2+ only",
            "Use SSL.TLSv1_2_METHOD or SSL.TLS_METHOD with proper options",
        ),
        # Weak cipher suites — RC4, DES, NULL, EXPORT, anon
        (
            r"""set_ciphers\s*\(\s*['"](?:[^'"]*(?:RC4|DES|NULL|EXPORT|anon|eNULL|aNULL)[^'"]*)['"]\s*\)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "weak-cipher-suite",
            "Weak cipher suite configured — RC4/DES/NULL/EXPORT/anon ciphers are broken",
            "Use strong cipher suites: set_ciphers('ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM')",
        ),
        # ── Authentication ────────────────────────────────────────────────
        # Empty password comparison — if password == ""
        (
            r"""(?:password|passwd|pass|secret)\s*(?:==|!=)\s*['"]["']""",
            Severity.WARNING,
            Category.SECURITY,
            "empty-password-check",
            "Comparing password against empty string — weak authentication logic",
            "Use proper password validation with minimum length/complexity requirements",
        ),
        # No password / allow_agent patterns in connection functions
        (
            r"""\.connect\s*\([^)]*password\s*=\s*['"]["']""",
            Severity.WARNING,
            Category.SECURITY,
            "empty-password-connection",
            "Connection with empty password string — authentication bypass risk",
            "Require non-empty password from secure credential store",
        ),
        # ── Network / CORS / Headers ─────────────────────────────────────
        # CORS wildcard — Access-Control-Allow-Origin: *
        (
            r"""(?:Access-Control-Allow-Origin|CORS_ORIGIN_ALLOW_ALL|CORS_ALLOW_ALL_ORIGINS)\s*[:=]\s*(?:['\"]?\*['\"]?|True)""",
            Severity.WARNING,
            Category.SECURITY,
            "cors-wildcard",
            "CORS wildcard allows any origin — credentials and data may leak cross-origin",
            "Specify allowed origins explicitly via an allowlist",
        ),
        # Flask CORS with wildcard origins
        (
            r"\bCORS\s*\(\s*\w+\s*(?:,\s*origins\s*=\s*['\"]?\*['\"]?)?(?:\s*\))",
            Severity.WARNING,
            Category.SECURITY,
            "cors-wildcard",
            "Flask-CORS with default wildcard origin — all cross-origin requests allowed",
            "Pass origins=['https://yourdomain.com'] to restrict allowed origins",
        ),
        # Missing security headers — X-Content-Type-Options / X-Frame-Options
        # (this is a settings audit for Django)
        (
            r"^\s*(?:SECURE_BROWSER_XSS_FILTER|X_FRAME_OPTIONS|SECURE_CONTENT_TYPE_NOSNIFF)\s*=\s*False",
            Severity.WARNING,
            Category.SECURITY,
            "security-header-disabled",
            "Security header explicitly disabled — browser protections weakened",
            "Set to True or remove the override to use Django's secure defaults",
        ),
        # Django SECURE_SSL_REDIRECT disabled
        (
            r"^\s*SECURE_SSL_REDIRECT\s*=\s*False",
            Severity.INFO,
            Category.SECURITY,
            "ssl-redirect-disabled",
            "SECURE_SSL_REDIRECT=False — HTTP traffic not redirected to HTTPS",
            "Set SECURE_SSL_REDIRECT=True in production",
        ),
        # ── Deserialization — additional coverage ─────────────────────────
        # cpickle (Python 2 compat, sometimes imported in Py3 codebases)
        (
            r"\b(?:cPickle|_pickle)\.(?:loads?\s*\(|Unpickler\s*\()",
            Severity.CRITICAL,
            Category.SECURITY,
            "pickle-unsafe",
            "cPickle/_pickle deserialization can execute arbitrary code",
            "Use json or msgpack for untrusted data",
        ),
        # ── File operations — zip slip single extract ─────────────────────
        # ZipFile.extract() without path validation — single-file zip slip
        (
            r"\.extract\s*\(\s*(?!.*\bfilter\b)",
            Severity.INFO,
            Category.SECURITY,
            "zipfile-extract-audit",
            "Archive extract() — verify member path does not escape target directory",
            "Check that extracted path starts with intended directory (no ../ traversal)",
        ),
        # ── Additional high-value rules ───────────────────────────────────
        # Django SESSION_COOKIE_SECURE = False — session hijacking over HTTP
        (
            r"^\s*SESSION_COOKIE_SECURE\s*=\s*False",
            Severity.WARNING,
            Category.SECURITY,
            "session-cookie-insecure",
            "SESSION_COOKIE_SECURE=False — session cookie sent over HTTP",
            "Set SESSION_COOKIE_SECURE=True in production to restrict to HTTPS",
        ),
        # Django SESSION_COOKIE_HTTPONLY = False — XSS can steal sessions
        (
            r"^\s*SESSION_COOKIE_HTTPONLY\s*=\s*False",
            Severity.WARNING,
            Category.SECURITY,
            "session-cookie-no-httponly",
            "SESSION_COOKIE_HTTPONLY=False — session cookie accessible to JavaScript",
            "Set SESSION_COOKIE_HTTPONLY=True to prevent XSS-based session theft",
        ),
        # Flask app.run(host='0.0.0.0') — binding to all interfaces in production
        (
            r"""\.run\s*\([^)]*host\s*=\s*['"]0\.0\.0\.0['"]""",
            Severity.WARNING,
            Category.SECURITY,
            "bind-all-interfaces",
            "Flask app binding to 0.0.0.0 — exposed to all network interfaces",
            "Bind to 127.0.0.1 for local dev or use a reverse proxy in production",
        ),
    ]
)


# ─── JavaScript / TypeScript ─────────────────────────────────────────

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


# ─── Go ───────────────────────────────────────────────────────────────

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


# ─── Rust ─────────────────────────────────────────────────────────────

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


# ─── Java ─────────────────────────────────────────────────────────────

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


# ─── Security patterns (applied to all languages) ────────────────────

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
            "logging.config.listen() accepts config over network — can load arbitrary handler classes (RCE)",
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
            "RC4/ARC4 is a broken stream cipher with known biases",
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


# ─── Rule registry ───────────────────────────────────────────────────

LANGUAGE_RULES: dict[str, list[Rule]] = {
    "python": PYTHON_RULES,
    "javascript": JAVASCRIPT_RULES,
    "typescript": JAVASCRIPT_RULES,  # TS shares JS patterns
    "go": GO_RULES,
    "rust": RUST_RULES,
    "java": JAVA_RULES,
}


def get_rules_for_language(lang: str) -> list[Rule]:
    """Return universal + security + language-specific rules."""
    rules = UNIVERSAL_RULES + SECURITY_RULES
    if lang in LANGUAGE_RULES:
        rules = rules + LANGUAGE_RULES[lang]
    return rules


_SEVERITY_ORDER = {
    Severity.CRITICAL.value: 0,
    Severity.WARNING.value: 1,
    Severity.INFO.value: 2,
}


def list_all_rules() -> list[dict]:
    """Return a deduplicated list of all rules with metadata.

    Each dict: {"name", "severity", "category", "languages", "message", "suggestion"}.
    Rules appearing in multiple language sets are merged (languages combined).
    Universal/security rules get languages=["all"].
    """
    seen: dict[str, dict] = {}  # rule_name -> dict

    from .compliance import get_cwe, get_nist

    def _add_rules(rules: list[Rule], languages: list[str]):
        for _pattern, severity, category, name, message, suggestion in rules:
            if name in seen:
                existing_langs = seen[name]["languages"]
                if existing_langs != ["all"]:
                    for lang in languages:
                        if lang not in existing_langs:
                            existing_langs.append(lang)
            else:
                entry = {
                    "name": name,
                    "severity": severity.value,
                    "category": category.value,
                    "languages": list(languages),
                    "message": message,
                    "suggestion": suggestion,
                }
                cwe = get_cwe(name)
                if cwe:
                    entry["cwe"] = cwe
                nist = get_nist(name)
                if nist:
                    entry["nist"] = nist
                seen[name] = entry

    # Universal and security rules apply to all languages
    _add_rules(UNIVERSAL_RULES, ["all"])
    _add_rules(SECURITY_RULES, ["all"])

    # Language-specific rules
    for lang, rules in LANGUAGE_RULES.items():
        _add_rules(rules, [lang])

    return sorted(seen.values(), key=lambda r: (_SEVERITY_ORDER.get(r["severity"], 9), r["name"]))
