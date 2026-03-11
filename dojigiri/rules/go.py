"""Go rules."""

from __future__ import annotations  # noqa

from ..types import Category, Severity
from ._compile import Rule, _compile

GO_RULES: list[Rule] = _compile(
    [
        # ── Security ─────────────────────────────────────────────────

        # SQL injection via fmt.Sprintf
        (
            r"""(?i)fmt\.Sprintf\s*\(\s*['"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b""",
            Severity.CRITICAL,
            Category.SECURITY,
            "go-sql-sprintf",
            "SQL query built with fmt.Sprintf — SQL injection risk",
            "Use parameterized queries with database/sql placeholder ($1, ?, @p1)",
        ),
        # SQL injection via string concatenation
        (
            r"""(?i)(?:['"](?:SELECT|INSERT|UPDATE|DELETE|DROP)\b[^'"]*['"]\s*\+)""",
            Severity.CRITICAL,
            Category.SECURITY,
            "go-sql-concat",
            "SQL query built with string concatenation — SQL injection risk",
            "Use parameterized queries with database/sql placeholder ($1, ?, @p1)",
        ),
        # Command injection via exec.Command with variable
        (
            r"""exec\.Command\s*\(\s*(?!['"])""",
            Severity.WARNING,
            Category.SECURITY,
            "go-command-injection",
            "exec.Command() with dynamic argument — command injection risk if user-controlled",
            "Validate command and arguments; never pass unsanitized user input",
        ),
        # Command injection via exec.CommandContext with variable
        (
            r"""exec\.CommandContext\s*\(\s*\w+\s*,\s*(?!['"])""",
            Severity.WARNING,
            Category.SECURITY,
            "go-command-injection-ctx",
            "exec.CommandContext() with dynamic argument — command injection risk",
            "Validate command and arguments; never pass unsanitized user input",
        ),
        # Path traversal (os.Open/ReadFile with variable, not hardcoded string)
        (
            r"""(?:os\.(?:Open|OpenFile|ReadFile|Create|Remove|RemoveAll|Mkdir|MkdirAll)|ioutil\.(?:ReadFile|ReadDir|WriteFile))\s*\(\s*(?!['"])""",
            Severity.WARNING,
            Category.SECURITY,
            "go-path-traversal",
            "File operation with dynamic path — path traversal risk",
            "Use filepath.Clean() and validate path is within expected base directory",
        ),
        # Hardcoded credentials
        (
            r"""(?i)(?:password|passwd|secret|apiKey|api_key|token)\s*[:=]\s*['"][^'"]{8,}['"]""",
            Severity.CRITICAL,
            Category.SECURITY,
            "go-hardcoded-credential",
            "Possible hardcoded credential in Go source",
            "Use environment variables or a secrets manager",
        ),
        # Weak crypto — MD5
        (
            r"""\bmd5\.(?:New|Sum)\b""",
            Severity.WARNING,
            Category.SECURITY,
            "go-weak-crypto-md5",
            "MD5 is cryptographically broken — collisions are trivial",
            "Use SHA-256 or SHA-3 for integrity; use bcrypt/scrypt/argon2 for passwords",
        ),
        # Weak crypto — SHA1
        (
            r"""\bsha1\.(?:New|Sum)\b""",
            Severity.WARNING,
            Category.SECURITY,
            "go-weak-crypto-sha1",
            "SHA1 is cryptographically weak — collision attacks demonstrated",
            "Use SHA-256 or SHA-3 instead",
        ),
        # Weak crypto — DES
        (
            r"""\bdes\.NewCipher\b""",
            Severity.WARNING,
            Category.SECURITY,
            "go-weak-crypto-des",
            "DES is broken — 56-bit keys are trivially brute-forced",
            "Use AES (aes.NewCipher) instead",
        ),
        # Insecure TLS
        (
            r"""InsecureSkipVerify\s*:\s*true""",
            Severity.CRITICAL,
            Category.SECURITY,
            "go-insecure-tls",
            "TLS certificate verification disabled (InsecureSkipVerify: true)",
            "Enable certificate verification; configure proper CA certificates",
        ),
        # MinVersion TLS 1.0/1.1
        (
            r"""MinVersion\s*:\s*tls\.Version(?:TLS10|TLS11|SSL30)\b""",
            Severity.WARNING,
            Category.SECURITY,
            "go-weak-tls-version",
            "TLS minimum version set below 1.2 — vulnerable to known attacks",
            "Set MinVersion to tls.VersionTLS12 or tls.VersionTLS13",
        ),
        # Unsafe pointer
        (
            r"""\bunsafe\.Pointer\b""",
            Severity.WARNING,
            Category.SECURITY,
            "go-unsafe-pointer",
            "unsafe.Pointer bypasses Go type safety — memory corruption risk",
            "Avoid unsafe unless absolutely necessary; document safety invariants",
        ),
        # SSRF (http.Get/Post with variable URL)
        (
            r"""http\.(?:Get|Post|PostForm|Head)\s*\(\s*(?!['"])""",
            Severity.WARNING,
            Category.SECURITY,
            "go-ssrf",
            "HTTP request with dynamic URL — SSRF risk if URL is user-controlled",
            "Validate URL against an allowlist of trusted domains/schemes",
        ),
        # Unvalidated redirect
        (
            r"""http\.Redirect\s*\(\s*\w+\s*,\s*\w+\s*,\s*(?!['"])""",
            Severity.WARNING,
            Category.SECURITY,
            "go-open-redirect",
            "HTTP redirect with dynamic URL — open redirect risk",
            "Validate redirect target against an allowlist of trusted paths/domains",
        ),

        # ── Quality / Bugs ───────────────────────────────────────────

        # Unchecked error (_, err := ... pattern where err is _)
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
        # defer in loop
        (
            r"^\s*for\s.*\{[\s\S]*?\bdefer\b",
            Severity.WARNING,
            Category.BUG,
            "go-defer-in-loop",
            "defer inside loop — deferred calls accumulate until function returns",
            "Move deferred cleanup into a separate function called from the loop body",
        ),
        # Goroutine leak (go func without WaitGroup/channel/context patterns)
        (
            r"\bgo\s+func\s*\(",
            Severity.INFO,
            Category.BUG,
            "go-goroutine-anonymous",
            "Anonymous goroutine — verify it has a termination mechanism (channel, context, WaitGroup)",
            "Ensure goroutines can be cancelled and their completion is tracked",
        ),
        # Nil map assignment (assigning to a map that might not be initialized)
        (
            r"""var\s+\w+\s+map\[""",
            Severity.INFO,
            Category.BUG,
            "go-nil-map",
            "Map declared with var (nil) — assignment will panic if not initialized with make()",
            "Initialize with make() or a map literal before use",
        ),
        # panic() in library code
        (
            r"^\s*panic\s*\(",
            Severity.WARNING,
            Category.BUG,
            "go-panic",
            "panic() crashes the program — inappropriate for library code and most application code",
            "Return an error instead of panicking; reserve panic for truly unrecoverable states",
        ),
        # String conversion in hot path hint
        (
            r"""\bstring\(\[\]byte\(""",
            Severity.INFO,
            Category.PERFORMANCE,
            "go-string-byte-copy",
            "string([]byte(...)) creates a copy — may impact performance in hot paths",
            "Consider using unsafe.String() (Go 1.20+) in performance-critical code after benchmarking",
        ),
        # Race condition hint: global var without sync
        (
            r"""^var\s+\w+\s+(?:map|int|string|bool|\[\])\b""",
            Severity.INFO,
            Category.BUG,
            "go-global-var",
            "Package-level mutable variable — data race risk if accessed from goroutines",
            "Protect with sync.Mutex/RWMutex, use sync.Map, or channel-based access",
        ),
    ]
)
