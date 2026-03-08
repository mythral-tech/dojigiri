"""dojigiri — Static analysis + LLM-powered code audit tool."""

__version__ = "1.1.0"

from .bundling import patch_tree_sitter_for_bundled
from .types import (  # doji:ignore(unused-import)
    Category,
    Confidence,
    CrossFileFinding,
    FileAnalysis,
    Finding,
    Fix,
    FixReport,
    FixSource,
    FixStatus,
    ProjectAnalysis,
    ScanReport,
    Severity,
    Source,
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
