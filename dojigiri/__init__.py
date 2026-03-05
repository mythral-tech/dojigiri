"""dojigiri — Static analysis + LLM-powered code audit tool."""

__version__ = "1.1.0"

from .config import (
    Finding,
    FileAnalysis,
    ScanReport,
    Severity,
    Category,
    Source,
    Confidence,
    FixStatus,
    FixSource,
    Fix,
    FixReport,
    CrossFileFinding,
    ProjectAnalysis,
    patch_tree_sitter_for_bundled,
)

# Patch tree-sitter loading for Nuitka bundled mode (no-op if not bundled)
patch_tree_sitter_for_bundled()

__all__ = [
    "__version__",
    "Finding",
    "FileAnalysis",
    "ScanReport",
    "Severity",
    "Category",
    "Source",
    "Confidence",
    "FixStatus",
    "FixSource",
    "Fix",
    "FixReport",
    "CrossFileFinding",
    "ProjectAnalysis",
]
