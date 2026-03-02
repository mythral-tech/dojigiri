"""Data structures, enums, paths, and LLM configuration."""

from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Optional
import os


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

MAX_FILE_SIZE = 1_000_000  # 1MB — skip binary/huge files


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
        d = {
            "file": self.file,
            "line": self.line,
            "severity": self.severity.value,
            "category": self.category.value,
            "source": self.source.value,
            "rule": self.rule,
            "message": self.message,
            "suggestion": self.suggestion,
            "snippet": self.snippet,
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


# LLM config
LLM_MODEL = "claude-sonnet-4-20250514"
LLM_MAX_TOKENS = 4096
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
