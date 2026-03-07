"""Constants, paths, and configuration loading.

Constants (extensions, skip dirs, LLM settings), project config from .doji.toml,
custom rule compilation. Types and bundling moved to types.py and bundling.py.

Called by: virtually every other module in the package.
Calls into: types.py (enums for custom rule compilation)
Data in → Data out: .doji.toml files → config dicts; regex strings → compiled rules.
"""

import logging
import os
import re
from pathlib import Path
from typing import Optional

from .types import Severity, Category

logger = logging.getLogger(__name__)

# ─── Classification & Compliance ─────────────────────────────────────

CLASSIFICATION_LEVELS = ("UNCLASSIFIED", "CUI", "CONFIDENTIAL", "SECRET", "TOP SECRET")

PROFILES: dict[str, dict] = {
    "owasp": {
        "min_severity": "warning",
        "ignore_rules": ["todo-marker", "long-line", "fstring-no-expr", "console-log", "fmt-print"],
        "description": "OWASP Top 10 focus — security findings only",
    },
    "dod": {
        "min_severity": "info",
        "classification": "CUI",
        "description": "DoD/defense compliance — all findings, CWE/NIST metadata, CUI markings",
    },
    "ci": {
        "min_severity": "warning",
        "ignore_rules": ["todo-marker", "long-line", "fstring-no-expr"],
        "description": "CI/CD pipeline — warnings and above, no noise",
    },
}


# ─── File discovery ──────────────────────────────────────────────────

LANGUAGE_EXTENSIONS = {
    ".py": "python",
    ".js": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
    ".jsx": "javascript",
    ".go": "go",
    ".rs": "rust",
    ".java": "java",
    ".c": "c",
    ".cpp": "cpp",
    ".h": "c",
    ".hpp": "cpp",
    ".rb": "ruby",
    ".php": "php",
    ".cs": "csharp",
    ".swift": "swift",
    ".kt": "kotlin",
    ".pine": "pine",
    ".sh": "bash",
    ".bash": "bash",
    ".sql": "sql",
    ".html": "html",
    ".css": "css",
}

SKIP_DIRS = {
    ".git", ".svn", ".hg", "node_modules", "__pycache__", ".mypy_cache",
    ".pytest_cache", "venv", ".venv", "env", ".env", "dist", "build",
    ".tox", ".eggs", "*.egg-info", ".claude", ".next", ".nuxt",
    "target", "out", "bin", "obj",
}

SKIP_FILES = {
    "package-lock.json", "yarn.lock", "pnpm-lock.yaml", "Pipfile.lock",
    "poetry.lock", "composer.lock", "Cargo.lock", "Gemfile.lock",
}

SENSITIVE_FILE_PATTERNS = [
    ".env", ".env.local", ".env.development", ".env.production",
    ".env.staging", ".env.test",
    "*.pem", "*.key", "*.p12", "*.pfx", "*.jks", "*.keystore",
    "secrets.json", "credentials.json", "service-account.json",
    ".netrc", ".npmrc", "id_rsa", "id_ed25519", "id_ecdsa",
]

MAX_FILE_SIZE = 1_000_000  # 1MB — skip binary/huge files

DEFAULT_DOJI_IGNORE = """\
# Build artifacts
build/
dist/
bin/
obj/
out/
target/

# Dependencies
node_modules/
vendor/
.venv/
venv/
Packages/

# Caches and generated
__pycache__/
.mypy_cache/
.pytest_cache/
*.pyc

# Version control
.git/

# IDE
.idea/
.vs/
.vscode/

# Binary/asset files (not code)
*.exe
*.dll
*.so
*.o
*.a
*.lib
*.pdb
"""


# ─── LLM config ─────────────────────────────────────────────────────

LLM_MODEL = "claude-sonnet-4-20250514"
LLM_MAX_TOKENS = 4096  # scan
LLM_DEBUG_MAX_TOKENS = 8192  # debug needs room for code examples
LLM_OPTIMIZE_MAX_TOKENS = 8192  # optimize needs room for before/after
LLM_ANALYZE_MAX_TOKENS = 8192  # cross-file analysis
LLM_SYNTHESIS_MAX_TOKENS = 8192  # project synthesis
LLM_FIX_MAX_TOKENS = 8192
LLM_TEMPERATURE = 0.0

# Cost per million tokens (Sonnet 4)
LLM_INPUT_COST_PER_M = 3.0
LLM_OUTPUT_COST_PER_M = 15.0

# ─── Tiered model selection ──────────────────────────────────────────
# Tasks are assigned a tier that determines which model to use.
# "scan" (basic chunk review) uses Haiku for cost efficiency.
# "deep" (debug, optimize, cross-file, synthesis, fix) uses Sonnet for quality.
# Set DOJI_LLM_TIER_MODE=off to force single-model (Sonnet) for everything.
LLM_TIER_MODE = "auto"  # "auto" | "off"
LLM_SCAN_MODEL = "claude-haiku-4-20250514"   # fast/cheap for scan chunks
LLM_DEEP_MODEL = "claude-sonnet-4-20250514"  # reasoning-heavy tasks

# Chunking
CHUNK_SIZE = 400  # lines per chunk
CHUNK_OVERLAP = 30  # overlap lines between chunks

# Storage
STORAGE_DIR = Path.home() / ".dojigiri"
REPORTS_DIR = STORAGE_DIR / "reports"
CACHE_FILE = STORAGE_DIR / "file_cache.json"


LANGUAGE_DEBUG_HINTS = {
    "python": (
        "Common Python bugs: mutable default arguments, late-binding closures, "
        "generator exhaustion after first iteration, GIL-related race conditions, "
        "incorrect exception chaining (raise X from Y), __del__ side effects, "
        "circular imports, descriptor protocol misuse, metaclass conflicts."
    ),
    "javascript": (
        "Common JS bugs: 'this' binding loss in callbacks/destructuring, "
        "unhandled Promise rejections, event loop blocking with sync I/O, "
        "closure over loop variables (var vs let), prototype pollution, "
        "implicit type coercion (== vs ===), floating point precision."
    ),
    "typescript": (
        "Common TS bugs: type assertions masking runtime errors, 'any' type leaks, "
        "incorrect discriminated union narrowing, unsound generic variance, "
        "Promise<void> vs void confusion, exhaustiveness checking gaps."
    ),
    "go": (
        "Common Go bugs: goroutine leaks (missing context cancellation), "
        "race conditions on shared state, nil interface vs nil pointer confusion, "
        "deferred function argument evaluation timing, slice append aliasing, "
        "unchecked error returns, mutex copy."
    ),
    "rust": (
        "Common Rust bugs: unwrap/expect on None/Err in non-test code, "
        "lifetime issues with async code, deadlocks from nested Mutex locks, "
        "integer overflow in release mode, unsafe block soundness holes, "
        "Send/Sync trait bound violations."
    ),
}

LANGUAGE_OPTIMIZE_HINTS = {
    "python": (
        "Python optimization: list/dict/set comprehensions over loops, generators for "
        "large sequences, __slots__ for data classes, functools.lru_cache/cache, "
        "asyncio for I/O-bound work, collections.defaultdict/Counter, "
        "str.join over concatenation, local variable access over global."
    ),
    "javascript": (
        "JS optimization: avoid DOM thrashing (batch reads/writes), use Map/Set over "
        "plain objects for frequent lookups, avoid creating closures in hot loops, "
        "use requestAnimationFrame for visual updates, web workers for CPU work, "
        "lazy loading, debounce/throttle event handlers."
    ),
    "typescript": (
        "TS optimization: same as JS plus — use const enums, avoid excessive type "
        "instantiation, prefer interfaces over type intersections for speed, "
        "use ReadonlyArray for immutable data."
    ),
    "go": (
        "Go optimization: pre-allocate slices with make([]T, 0, cap), avoid "
        "fmt.Sprintf in hot paths, use sync.Pool for frequent allocations, "
        "buffer I/O with bufio, use strings.Builder for concatenation, "
        "profile with pprof before optimizing, channel sizing."
    ),
    "rust": (
        "Rust optimization: avoid unnecessary clones, use &str over String in args, "
        "prefer iterators over index loops, use Vec::with_capacity, "
        "avoid Box<dyn Trait> in hot paths (use enums), "
        "use rayon for data parallelism, profile with cargo flamegraph."
    ),
}


# ─── Configuration loading ───────────────────────────────────────────

def get_api_key() -> Optional[str]:
    return os.environ.get("ANTHROPIC_API_KEY")


def get_llm_config(project_config: Optional[dict] = None) -> dict:
    """Build LLM backend config from env vars and .doji.toml [dojigiri.llm] section.

    Priority: env vars > .doji.toml > defaults.
    Returns dict with keys: backend, model, base_url, api_key.
    """
    toml_llm = {}
    if project_config:
        toml_llm = project_config.get("llm", {})

    # Security: api_key and base_url are NOT read from .doji.toml.
    # A malicious repo could plant a .doji.toml that redirects API calls
    # to an attacker-controlled endpoint, exfiltrating the user's API key
    # and source code. Only env vars and CLI flags are trusted for these.
    if toml_llm.get("api_key"):
        logger.warning(
            "Ignoring api_key in .doji.toml — API keys must be set via environment "
            "variables (ANTHROPIC_API_KEY, OPENAI_API_KEY) for security."
        )
    if toml_llm.get("base_url"):
        logger.warning(
            "Ignoring base_url in .doji.toml — LLM endpoint must be set via "
            "DOJI_LLM_BASE_URL env var or --base-url flag for security."
        )

    return {
        "backend": os.environ.get("DOJI_LLM_BACKEND") or toml_llm.get("backend"),
        "model": os.environ.get("DOJI_LLM_MODEL") or toml_llm.get("model"),
        "base_url": os.environ.get("DOJI_LLM_BASE_URL"),
        "api_key": None,  # env-only — never from config files
    }


def load_ignore_patterns(root: Path) -> list[str]:
    """Load .doji-ignore file from project root. Returns fnmatch patterns."""
    ignore_file = root / ".doji-ignore"
    if not ignore_file.exists():
        return []
    patterns = []
    for line in ignore_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def load_project_config(root: Path) -> dict:
    """Load .doji.toml config file from project root.

    Returns a dict with config options:
    - ignore_rules: list of rule names to suppress
    - min_severity: minimum severity level
    - min_confidence: minimum confidence level (for LLM findings)
    - workers: number of parallel workers
    - rules: list of custom rule dicts

    Returns empty dict if config file doesn't exist or fails to parse.
    """
    try:
        import tomllib  # Python 3.11+
    except ImportError:
        try:
            import tomli as tomllib  # Python 3.10 fallback
        except ImportError:
            return {}  # No TOML support, skip config

    config_file = root / ".doji.toml"
    if not config_file.exists():
        return {}

    try:
        with open(config_file, "rb") as f:
            data = tomllib.load(f)
        return data.get("dojigiri", {})
    except (ValueError, OSError, KeyError) as e:  # TOMLDecodeError is subclass of ValueError
        logger.warning("Could not parse %s: %s", config_file, e)
        return {}


# Custom rule type
from typing import NamedTuple


class CustomRule(NamedTuple):
    pattern: re.Pattern
    severity: Severity
    category: Category
    name: str
    message: str
    suggestion: Optional[str]
    languages: Optional[list[str]]


def _is_safe_regex(pattern_str: str) -> bool:
    """Check if a regex pattern is safe from ReDoS attacks.

    Rejects nested quantifiers (e.g., (a+)+) and test-runs the compiled
    pattern against adversarial strings to catch catastrophic backtracking.
    Returns True for patterns that are safe (or merely invalid — invalid
    patterns are handled separately by re.compile error handling).
    """
    # Reject patterns that are excessively long
    if len(pattern_str) > 500:
        return False
    # Reject nested quantifiers: a group (including non-capturing (?:), lookahead
    # (?=), etc.) containing a quantifier, with a quantifier on the group itself.
    # e.g. (a+)+, (?:a+)+, (?=a+)+, (x*){2,}
    if re.search(r'(?:\((?:\?[:!=<])?[^)]*[+*?{][^)]*\)[+*?{])', pattern_str):
        return False
    # Reject alternation with single-char overlapping branches inside quantified groups
    # e.g. (a|a)+, but NOT (error|warning)+ which is safe
    if re.search(r'\((?:\?:)?([a-zA-Z])\|(\1)\)[+*{]', pattern_str):
        return False
    # Test-run: compile and match against adversarial strings with a timeout thread
    try:
        compiled = re.compile(pattern_str)
        import concurrent.futures
        def _test_regex():
            for test_str in ["a" * 10000, "b" * 10000, "ab" * 5000, "\x00" * 10000]:
                compiled.search(test_str)
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(_test_regex)
            future.result(timeout=2.0)  # 2-second hard timeout
    except re.error:
        # Invalid regex — let the caller's re.compile() handle the error message
        return True
    except (RecursionError, MemoryError):
        return False
    except (concurrent.futures.TimeoutError, TimeoutError):
        return False
    return True


def compile_custom_rules(config: dict) -> list[CustomRule]:
    """Compile custom rules from .doji.toml config into regex tuples.

    Each rule in config["rules"] should have:
      - pattern: str (regex pattern, required)
      - severity: str (critical/warning/info, default: warning)
      - category: str (bug/security/performance/style/dead_code, default: bug)
      - name: str (kebab-case rule name, required)
      - message: str (human-readable message, required)
      - suggestion: str (optional)
      - languages: list[str] (optional, omit for all languages)

    Returns list of (re.Pattern, Severity, Category, name, message, suggestion, languages) tuples.
    Invalid rules are silently skipped with a stderr warning.
    """
    rules_data = config.get("rules", [])
    if not rules_data:
        return []

    severity_map = {
        "critical": Severity.CRITICAL,
        "warning": Severity.WARNING,
        "info": Severity.INFO,
    }
    category_map = {
        "bug": Category.BUG,
        "security": Category.SECURITY,
        "performance": Category.PERFORMANCE,
        "style": Category.STYLE,
        "dead_code": Category.DEAD_CODE,
    }

    compiled = []
    for i, rule in enumerate(rules_data):
        # Validate required fields
        pattern_str = rule.get("pattern")
        name = rule.get("name")
        message = rule.get("message")

        if not pattern_str or not name or not message:
            logger.warning("Skipping custom rule #%d: missing pattern, name, or message", i)
            continue

        # ReDoS safety check
        if not _is_safe_regex(pattern_str):
            logger.warning("Skipping custom rule '%s': potentially unsafe regex (ReDoS risk)", name)
            continue

        # Compile pattern
        try:
            compiled_pattern = re.compile(pattern_str)
        except re.error as e:
            logger.warning("Skipping custom rule '%s': invalid regex: %s", name, e)
            continue

        # Parse severity (default: warning)
        severity = severity_map.get(rule.get("severity", "warning"))
        if severity is None:
            logger.warning("Skipping custom rule '%s': invalid severity '%s'", name, rule.get('severity'))
            continue

        # Parse category (default: bug)
        category = category_map.get(rule.get("category", "bug"))
        if category is None:
            logger.warning("Skipping custom rule '%s': invalid category '%s'", name, rule.get('category'))
            continue

        suggestion = rule.get("suggestion")
        languages = rule.get("languages")  # None means all languages

        compiled.append((compiled_pattern, severity, category, name, message, suggestion, languages))

    return compiled
