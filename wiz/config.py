"""Data structures, enums, paths, and LLM configuration."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
import os
import re
import sys
from datetime import datetime


class Severity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


class Source(Enum):
    STATIC = "static"
    AST = "ast"
    LLM = "llm"


class Category(Enum):
    BUG = "bug"
    SECURITY = "security"
    PERFORMANCE = "performance"
    STYLE = "style"
    DEAD_CODE = "dead_code"


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

REDACT_SNIPPET_RULES = {"hardcoded-secret", "aws-credentials"}


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class Finding:
    file: str
    line: int
    severity: Severity
    category: Category
    source: Source
    rule: str
    message: str
    suggestion: Optional[str] = None
    snippet: Optional[str] = None
    confidence: Optional[Confidence] = None  # LLM findings only

    def to_dict(self) -> dict:
        snippet = "[REDACTED]" if self.rule in REDACT_SNIPPET_RULES else self.snippet
        d = {
            "file": self.file,
            "line": self.line,
            "severity": self.severity.value,
            "category": self.category.value,
            "source": self.source.value,
            "rule": self.rule,
            "message": self.message,
            "suggestion": self.suggestion,
            "snippet": snippet,
        }
        if self.confidence is not None:
            d["confidence"] = self.confidence.value
        return d


@dataclass
class FileAnalysis:
    path: str
    language: str
    lines: int
    findings: list[Finding] = field(default_factory=list)
    file_hash: Optional[str] = None

    @property
    def critical_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def warning_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.WARNING)

    @property
    def info_count(self) -> int:
        return sum(1 for f in self.findings if f.severity == Severity.INFO)


@dataclass
class ScanReport:
    root: str
    mode: str  # "quick" or "deep"
    files_scanned: int
    files_skipped: int
    total_findings: int
    critical: int
    warnings: int
    info: int
    file_analyses: list[FileAnalysis] = field(default_factory=list)
    llm_cost_usd: float = 0.0
    timestamp: str = ""

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "mode": self.mode,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "total_findings": self.total_findings,
            "critical": self.critical,
            "warnings": self.warnings,
            "info": self.info,
            "llm_cost_usd": self.llm_cost_usd,
            "timestamp": self.timestamp,
            "files": [
                {
                    "path": fa.path,
                    "language": fa.language,
                    "lines": fa.lines,
                    "findings": [f.to_dict() for f in fa.findings],
                }
                for fa in self.file_analyses
            ],
        }


@dataclass
class CrossFileFinding:
    """A finding that spans two files — only visible with cross-file context."""
    source_file: str
    target_file: str
    line: int
    target_line: Optional[int] = None
    severity: Severity = Severity.WARNING
    category: Category = Category.BUG
    rule: str = ""
    message: str = ""
    suggestion: Optional[str] = None
    confidence: Optional[Confidence] = None

    def to_dict(self) -> dict:
        d = {
            "source_file": self.source_file,
            "target_file": self.target_file,
            "line": self.line,
            "severity": self.severity.value,
            "category": self.category.value,
            "rule": self.rule,
            "message": self.message,
        }
        if self.target_line is not None:
            d["target_line"] = self.target_line
        if self.suggestion:
            d["suggestion"] = self.suggestion
        if self.confidence is not None:
            d["confidence"] = self.confidence.value
        return d


@dataclass
class ProjectAnalysis:
    """Complete project-level analysis result."""
    root: str
    files_analyzed: int
    graph_metrics: dict
    dependency_graph: dict
    per_file_findings: list[FileAnalysis] = field(default_factory=list)
    cross_file_findings: list[CrossFileFinding] = field(default_factory=list)
    synthesis: Optional[dict] = None
    llm_cost_usd: float = 0.0
    timestamp: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat(timespec="seconds")

    def to_dict(self) -> dict:
        return {
            "root": self.root,
            "files_analyzed": self.files_analyzed,
            "graph_metrics": self.graph_metrics,
            "dependency_graph": self.dependency_graph,
            "per_file_findings": [
                {
                    "path": fa.path,
                    "language": fa.language,
                    "lines": fa.lines,
                    "findings": [f.to_dict() for f in fa.findings],
                }
                for fa in self.per_file_findings
            ],
            "cross_file_findings": [cf.to_dict() for cf in self.cross_file_findings],
            "synthesis": self.synthesis,
            "llm_cost_usd": self.llm_cost_usd,
            "timestamp": self.timestamp,
        }


# Fix config
LLM_FIX_MAX_TOKENS = 8192


class FixStatus(Enum):
    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    SKIPPED = "skipped"


class FixSource(Enum):
    DETERMINISTIC = "deterministic"  # rule-based, guaranteed correct
    LLM = "llm"                     # AI-generated, needs review


@dataclass
class Fix:
    file: str
    line: int
    rule: str
    original_code: str       # exact line(s) to replace
    fixed_code: str          # replacement
    explanation: str          # what changed and why
    source: FixSource
    end_line: Optional[int] = None  # last line of range (inclusive), None = single line
    status: FixStatus = FixStatus.PENDING

    def to_dict(self) -> dict:
        d = {
            "file": self.file,
            "line": self.line,
            "rule": self.rule,
            "original_code": self.original_code,
            "fixed_code": self.fixed_code,
            "explanation": self.explanation,
            "source": self.source.value,
            "status": self.status.value,
        }
        if self.end_line is not None:
            d["end_line"] = self.end_line
        return d


@dataclass
class FixReport:
    root: str
    files_fixed: int
    total_fixes: int
    applied: int
    skipped: int
    failed: int
    fixes: list[Fix] = field(default_factory=list)
    llm_cost_usd: float = 0.0
    timestamp: str = ""
    verification: Optional[dict] = None

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now().isoformat(timespec="seconds")

    def to_dict(self) -> dict:
        d = {
            "root": self.root,
            "files_fixed": self.files_fixed,
            "total_fixes": self.total_fixes,
            "applied": self.applied,
            "skipped": self.skipped,
            "failed": self.failed,
            "fixes": [f.to_dict() for f in self.fixes],
            "llm_cost_usd": self.llm_cost_usd,
            "timestamp": self.timestamp,
        }
        if self.verification is not None:
            d["verification"] = self.verification
        return d


# LLM config
LLM_MODEL = "claude-sonnet-4-20250514"
LLM_MAX_TOKENS = 4096  # scan
LLM_DEBUG_MAX_TOKENS = 8192  # debug needs room for code examples
LLM_OPTIMIZE_MAX_TOKENS = 8192  # optimize needs room for before/after
LLM_ANALYZE_MAX_TOKENS = 8192  # cross-file analysis
LLM_SYNTHESIS_MAX_TOKENS = 8192  # project synthesis
LLM_TEMPERATURE = 0.0

# Cost per million tokens (Sonnet 4)
LLM_INPUT_COST_PER_M = 3.0
LLM_OUTPUT_COST_PER_M = 15.0

# Chunking
CHUNK_SIZE = 400  # lines per chunk
CHUNK_OVERLAP = 30  # overlap lines between chunks

# Storage
STORAGE_DIR = Path.home() / ".wiz"
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


def get_api_key() -> Optional[str]:
    return os.environ.get("ANTHROPIC_API_KEY")


def load_ignore_patterns(root: Path) -> list[str]:
    """Load .wizignore file from project root. Returns fnmatch patterns."""
    ignore_file = root / ".wizignore"
    if not ignore_file.exists():
        return []
    patterns = []
    for line in ignore_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def load_project_config(root: Path) -> dict:
    """Load .wiz.toml config file from project root.

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

    config_file = root / ".wiz.toml"
    if not config_file.exists():
        return {}

    try:
        with open(config_file, "rb") as f:
            data = tomllib.load(f)
        return data.get("wiz", {})
    except Exception as e:
        print(f"Warning: could not parse {config_file}: {e}", file=sys.stderr)
        return {}


# Custom rule type: (compiled_pattern, Severity, Category, name, message, suggestion, languages)
CustomRule = tuple


def _is_safe_regex(pattern_str: str) -> bool:
    """Check if a regex pattern is safe from ReDoS attacks.

    Rejects nested quantifiers (e.g., (a+)+) and test-runs the compiled
    pattern against a long string to catch catastrophic backtracking.
    Returns True for patterns that are safe (or merely invalid — invalid
    patterns are handled separately by re.compile error handling).
    """
    # Reject nested quantifiers: a group containing a quantifier, with a
    # quantifier on the group itself — e.g. (a+)+, (x*){2,}
    if re.search(r'\([^)]*[+*?{][^)]*\)[+*?{]', pattern_str):
        return False
    # Test-run: compile and match against a 1000-char string
    try:
        compiled = re.compile(pattern_str)
        compiled.search("a" * 1000)
    except re.error:
        # Invalid regex — let the caller's re.compile() handle the error message
        return True
    except RecursionError:
        return False
    return True


def compile_custom_rules(config: dict) -> list[CustomRule]:
    """Compile custom rules from .wiz.toml config into regex tuples.

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
    import sys as _sys

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
            print(f"  [config] Skipping custom rule #{i}: missing pattern, name, or message",
                  file=_sys.stderr)
            continue

        # ReDoS safety check
        if not _is_safe_regex(pattern_str):
            print(f"  [config] Skipping custom rule '{name}': potentially unsafe regex (ReDoS risk)",
                  file=_sys.stderr)
            continue

        # Compile pattern
        try:
            compiled_pattern = re.compile(pattern_str)
        except re.error as e:
            print(f"  [config] Skipping custom rule '{name}': invalid regex: {e}",
                  file=_sys.stderr)
            continue

        # Parse severity (default: warning)
        severity = severity_map.get(rule.get("severity", "warning"))
        if severity is None:
            print(f"  [config] Skipping custom rule '{name}': invalid severity '{rule.get('severity')}'",
                  file=_sys.stderr)
            continue

        # Parse category (default: bug)
        category = category_map.get(rule.get("category", "bug"))
        if category is None:
            print(f"  [config] Skipping custom rule '{name}': invalid category '{rule.get('category')}'",
                  file=_sys.stderr)
            continue

        suggestion = rule.get("suggestion")
        languages = rule.get("languages")  # None means all languages

        compiled.append((compiled_pattern, severity, category, name, message, suggestion, languages))

    return compiled
