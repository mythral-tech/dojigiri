"""Core types — enums, dataclasses, and type aliases.

Every module that needs Finding, Severity, ScanReport, etc. imports from here.
This is a leaf module with no dojigiri imports (except .compliance for CWE/NIST
lookups in Finding.to_dict).

Called by: virtually every other module in the package.
Calls into: compliance.py (lazy import in Finding.to_dict only)
Data in → Data out: no I/O; provides shared types.
"""

import logging
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from typing import Optional, TypeAlias

logger = logging.getLogger(__name__)


# ─── Enums ────────────────────────────────────────────────────────────

class Severity(Enum):
    CRITICAL = "critical"
    WARNING = "warning"
    INFO = "info"


# Canonical severity ordering — use instead of ad-hoc dicts
SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}


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


class Confidence(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


class FixStatus(Enum):
    PENDING = "pending"
    APPLIED = "applied"
    FAILED = "failed"
    SKIPPED = "skipped"


class FixSource(Enum):
    DETERMINISTIC = "deterministic"  # rule-based, guaranteed correct
    LLM = "llm"                     # AI-generated, needs review


# ─── Constants tied to types ──────────────────────────────────────────

REDACT_SNIPPET_RULES = {"hardcoded-secret", "aws-credentials"}


# ─── Dataclasses ──────────────────────────────────────────────────────

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
        from .compliance import get_cwe, get_nist
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
        cwe = get_cwe(self.rule)
        if cwe:
            d["cwe"] = cwe
        nist = get_nist(self.rule)
        if nist:
            d["nist"] = nist
        return d


@dataclass
class FileAnalysis:
    path: str
    language: str
    lines: int
    findings: list[Finding] = field(default_factory=list)
    file_hash: Optional[str] = None
    semantics: Optional[object] = None  # semantic.core.FileSemantics (not serialized)

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
    mode: str  # "quick", "deep", or "diff"
    files_scanned: int
    files_skipped: int
    file_analyses: list[FileAnalysis] = field(default_factory=list)
    cross_file_findings: list["CrossFileFinding"] = field(default_factory=list)
    llm_cost_usd: float = 0.0
    timestamp: str = ""

    @property
    def total_findings(self) -> int:
        return (sum(len(fa.findings) for fa in self.file_analyses)
                + len(self.cross_file_findings))

    @property
    def critical(self) -> int:
        return sum(fa.critical_count for fa in self.file_analyses)

    @property
    def warnings(self) -> int:
        return sum(fa.warning_count for fa in self.file_analyses)

    @property
    def info(self) -> int:
        return (sum(fa.info_count for fa in self.file_analyses)
                + sum(1 for cf in self.cross_file_findings
                      if cf.severity == Severity.INFO))

    def to_dict(self) -> dict:
        d = {
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
        if self.cross_file_findings:
            d["cross_file_findings"] = [cf.to_dict() for cf in self.cross_file_findings]
        return d


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


@dataclass
class FixContext:
    """Context passed to all fixers — provides semantic data when available."""
    content: str
    finding: "Finding"
    semantics: Optional[object] = None  # semantic.core.FileSemantics
    type_map: Optional[object] = None   # semantic.types.FileTypeMap
    language: str = "python"


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
    fail_reason: Optional[str] = None  # why the fix failed (for user diagnostics)

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
        if self.fail_reason is not None:
            d["fail_reason"] = self.fail_reason
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


# ─── Analysis result ─────────────────────────────────────────────────

@dataclass
class StaticAnalysisResult:
    """Return type of analyze_file_static — always carries findings + optional semantics."""
    findings: list[Finding]
    semantics: Optional[object] = None   # semantic.core.FileSemantics
    type_map: Optional[object] = None    # semantic.types.FileTypeMap


# ─── Type aliases ────────────────────────────────────────────────────
Findings: TypeAlias = list[Finding]
SourceBytes: TypeAlias = bytes
