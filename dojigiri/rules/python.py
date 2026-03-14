"""Python-specific rules."""

from __future__ import annotations  # noqa

from ..types import Category, Severity
from ._compile import Rule, _compile

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
            "os.system() is vulnerable to shell injection",  # doji:ignore(os-system)
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
            "pickle.load()/loads()/Unpickler() can execute arbitrary code during deserialization",  # doji:ignore(deserialization-unsafe,pickle-unsafe)
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
            "yaml.load() without SafeLoader can execute arbitrary code",  # doji:ignore(deserialization-unsafe)
            "Use yaml.safe_load() or yaml.load(data, Loader=yaml.SafeLoader)",  # doji:ignore(deserialization-unsafe)
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
            "os.popen() starts a shell process — vulnerable to injection",  # doji:ignore(os-popen)
            "Use subprocess.run() with a list of arguments instead",
        ),
        # subprocess.getoutput / getstatusoutput — always use shell
        (
            r"\bsubprocess\.(?:getoutput|getstatusoutput)\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "subprocess-shell",
            "subprocess.getoutput()/getstatusoutput() always uses shell — vulnerable to injection",  # doji:ignore(subprocess-shell)
            "Use subprocess.run() with a list of arguments instead",
        ),
        # os.startfile — opens file with default handler (Windows)
        (
            r"\bos\.startfile\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "os-startfile",
            "os.startfile() opens file with default handler — could launch executables",  # doji:ignore(os-startfile)
            "Validate file type and path before opening",
        ),
        # os.chmod with permissive mask (world-writable/executable)
        (
            r"\bos\.chmod\s*\([^)]*,\s*0o?[0-7](?:[1-7][0-7]|[0-7][1-7])\b",
            Severity.WARNING,
            Category.SECURITY,
            "insecure-file-permissions",
            "os.chmod() with overly permissive mode — group or world permissions are non-zero",
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
            "ssl.wrap_socket() is deprecated and does not verify certificates by default",  # doji:ignore(ssl-wrap-socket)
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
            "ssl._create_unverified_context() disables all certificate verification",  # doji:ignore(insecure-ssl-context,ssl-verify-disabled)
            "Use ssl.create_default_context() for verified connections",
        ),
        # ssl.CERT_NONE — disables certificate verification
        (
            r"\bssl\.CERT_NONE\b",  # doji:ignore(insecure-ssl-context)
            Severity.WARNING,
            Category.SECURITY,
            "ssl-verify-disabled",
            "ssl.CERT_NONE disables certificate verification — MITM risk",  # doji:ignore(insecure-ssl-context,ssl-verify-disabled)
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
            "DEBUG=True may expose sensitive information in production",  # doji:ignore(debug-enabled,generic-debug-enabled)
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
            "Archive extractall() without path validation — zip/tar slip attack",  # doji:ignore(archive-slip)
            "Validate member paths before extraction or use extraction filters",
        ),
        # tarfile.open + extractall
        (
            r"\btarfile\.open\b",
            Severity.INFO,
            Category.SECURITY,
            "tarfile-open",
            "tarfile.open() — ensure extractall() uses data_filter or validates member paths",
            "Use tf.extractall(filter='data') (Python 3.12+) or validate each member",  # doji:ignore(archive-slip)
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
            "mark_safe() bypasses Django's auto-escaping — XSS risk if content is user-controlled",  # doji:ignore(django-mark-safe)
            "Use format_html() or escape user content before marking safe",
        ),
        # Django QuerySet.extra() — raw SQL injection
        (
            r"\.extra\s*\(",
            Severity.WARNING,
            Category.SECURITY,
            "django-extra-sql",
            "QuerySet.extra() uses raw SQL — injection risk if values are user-controlled",  # doji:ignore(django-extra-sql)
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
            "TripleDES/3DES is deprecated — slow and approaching theoretical breaks",  # doji:ignore(insecure-crypto)
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
            r"@csrf_exempt\b",  # doji:ignore(csrf-exempt,csrf-disabled)
            Severity.WARNING,
            Category.SECURITY,
            "csrf-exempt",
            "@csrf_exempt disables CSRF protection on this view",  # doji:ignore(csrf-exempt,csrf-disabled)
            "Remove @csrf_exempt or implement alternative CSRF validation",  # doji:ignore(csrf-exempt,csrf-disabled)
        ),
        # Django ALLOWED_HOSTS wildcard — allows any host header
        (
            r"""ALLOWED_HOSTS\s*=\s*\[\s*['\"]\*['\"]""",
            Severity.WARNING,
            Category.SECURITY,
            "django-allowed-hosts-wildcard",
            "ALLOWED_HOSTS = ['*'] accepts any Host header — HTTP Host header attacks",  # doji:ignore(django-allowed-hosts-wildcard)
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
            r"\bssl\.PROTOCOL_(?:SSLv2|SSLv3|SSLv23|TLSv1(?:_1)?)\b",  # doji:ignore(weak-tls-version,generic-weak-tls-version)
            Severity.CRITICAL,
            Category.SECURITY,
            "weak-tls-version",
            "Weak TLS protocol version — SSLv2/v3/TLS1.0/1.1 are broken or deprecated",  # doji:ignore(weak-tls-version,generic-weak-tls-version)
            "Use ssl.PROTOCOL_TLS_CLIENT or ssl.TLSVersion.TLSv1_2 minimum",
        ),
        # SSLContext with minimum_version set to broken protocol
        (
            r"minimum_version\s*=\s*ssl\.TLSVersion\.(?:SSLv3|TLSv1(?:_1)?)\b",  # doji:ignore(weak-tls-version,generic-weak-tls-version)
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
            r"""set_ciphers\s*\(\s*['"](?:[^'"]*(?:RC4|DES|NULL|EXPORT|anon|eNULL|aNULL)[^'"]*)['"]\s*\)""",  # doji:ignore(insecure-rc4)
            Severity.CRITICAL,
            Category.SECURITY,
            "weak-cipher-suite",
            "Weak cipher suite configured — RC4/DES/NULL/EXPORT/anon ciphers are broken",  # doji:ignore(insecure-rc4)
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
            "SESSION_COOKIE_SECURE=False — session cookie sent over HTTP",  # doji:ignore(session-insecure)
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
