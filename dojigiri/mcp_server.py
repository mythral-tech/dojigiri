"""FastMCP server exposing Dojigiri static analysis tools to AI agents.

Runs as a subprocess via MCP protocol. Provides five tools: doji_scan,
doji_scan_file, doji_fix, doji_explain, and doji_analyze_project.
All tools return concise plain text, not JSON. Errors return as strings.

Called by: external (MCP protocol, e.g. Claude Code)
Calls into: config.py, analyzer.py, mcp_format.py, semantic/explain.py,
            graph/project.py, fixer.py
Data in -> Data out: tool requests (file paths, options) -> formatted text
"""

from __future__ import annotations

import logging
from pathlib import Path

logger = logging.getLogger(__name__)
from typing import Sequence

from mcp.server.fastmcp import FastMCP

from .types import Severity

mcp = FastMCP(
    "dojigiri",
    instructions=(
        "Dojigiri is a static analyzer with 40+ rules, tree-sitter semantic analysis, "
        "taint tracking, null safety, and cross-file analysis. "
        "Use doji_scan for broad scans, doji_scan_file for single files, "
        "doji_fix to preview fixes (then apply with Edit tool), "
        "doji_explain to understand file structure, "
        "doji_analyze_project for cross-file dependency analysis."
    ),
)

_SEVERITY_MAP = {"critical": Severity.CRITICAL, "warning": Severity.WARNING, "info": Severity.INFO}
_SEVERITY_RANK = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}

# ─── Path boundary validation ────────────────────────────────────────
# Default: only allow paths under cwd. Extendable via .doji.toml:
#   [dojigiri]
#   mcp_allowed_roots = ["/other/project", "/data/shared"]

_allowed_roots: list[Path] = [Path.cwd().resolve()]

# Load extra allowed roots from .doji.toml at import time.
# SECURITY: Only allow roots that are subdirectories of cwd to prevent
# a malicious .doji.toml in a scanned project from granting access to
# arbitrary directories (e.g. mcp_allowed_roots = ["/"]).
try:
    from .config import load_project_config as _load_cfg
    _mcp_cfg = _load_cfg(Path.cwd())
    _extra = _mcp_cfg.get("mcp_allowed_roots", [])
    _cwd_resolved = Path.cwd().resolve()
    if isinstance(_extra, list):
        for _r in _extra:
            _resolved = Path(_r).resolve()
            if _resolved.is_relative_to(_cwd_resolved):
                _allowed_roots.append(_resolved)
            else:
                import logging as _logging
                _logging.getLogger(__name__).warning(
                    "Ignoring mcp_allowed_roots entry '%s' — must be under cwd (%s)",
                    _r, _cwd_resolved,
                )
except Exception as _e:
    import logging as _logging
    _logging.getLogger(__name__).debug("MCP config loading failed: %s", _e)


def _configure_allowed_roots(extra_roots: Sequence[str | Path] | None = None) -> None:
    """Reset allowed roots to cwd + validated extras.

    Only accepts roots that are subdirectories of cwd (same security
    boundary as the import-time loader).
    """
    _allowed_roots.clear()
    cwd = Path.cwd().resolve()
    _allowed_roots.append(cwd)
    if extra_roots:
        for r in extra_roots:
            resolved = Path(r).resolve()
            if resolved.is_relative_to(cwd):
                _allowed_roots.append(resolved)
            else:
                import logging as _log
                _log.getLogger(__name__).warning(
                    "Ignoring allowed root '%s' — must be under cwd (%s)", r, cwd,
                )


def _validate_path(path: Path) -> Path:
    """Resolve *path* and verify it falls under an allowed root.

    Returns the resolved path on success.
    Raises ValueError if the path is outside every allowed root.
    """
    resolved = path.resolve()
    for root in _allowed_roots:
        if resolved.is_relative_to(root):
            return resolved
    roots_str = ", ".join(str(r) for r in _allowed_roots)
    raise ValueError(f"Path '{path}' is outside allowed directories: {roots_str}")


def _parse_severity(value: str) -> Severity | str:
    """Parse a severity string. Returns Severity on success, error string on failure."""
    sev = _SEVERITY_MAP.get(value)
    if sev is None:
        return f"Error: invalid min_severity '{value}'. Use: critical, warning, or info"
    return sev


def _read_file(path: str) -> tuple[str, str, str]:
    """Read a file and detect its language. Returns (content, language, filepath_str).

    Raises ValueError with a user-facing message on failure.
    """
    from .discovery import detect_language

    filepath = _validate_path(Path(path))
    if not filepath.is_file():
        raise ValueError(f"Error: '{path}' is not a file")

    lang = detect_language(filepath)
    if not lang:
        raise ValueError(f"Error: unsupported file type '{filepath.suffix}'")

    try:
        content = filepath.read_text(encoding="utf-8", errors="replace")
    except OSError as e:
        raise ValueError(f"Error reading file: {e}")

    return content, lang, str(filepath)


def _collect_files_with_lang(root: Path) -> list[tuple[Path, str]]:
    """Collect analyzable files under root, each paired with its detected language."""
    from .discovery import collect_files_with_lang
    return collect_files_with_lang(root)


def _filter_findings_by_severity(findings: list, min_severity: Severity) -> list:
    """Filter findings to those at or above min_severity."""
    threshold = _SEVERITY_RANK[min_severity]
    return [f for f in findings if _SEVERITY_RANK.get(f.severity, 9) <= threshold]


# ─── Tools ───────────────────────────────────────────────────────────

@mcp.tool()
def doji_scan(
    path: str,
    language: str | None = None,
    diff_only: bool = False,
    diff_ref: str | None = None,
    min_severity: str = "warning",
    ignore_rules: str | None = None,
) -> str:
    """Scan files or directories for bugs, security issues, and code quality problems.

    Args:
        path: File or directory to scan.
        language: Filter by language (python, javascript, typescript, go, rust, java, c, cpp).
        diff_only: If True, only scan git-changed lines vs diff_ref.
        diff_ref: Git ref to diff against (default: main/master). Only used when diff_only=True.
        min_severity: Minimum severity to include: "critical", "warning", or "info".
        ignore_rules: Comma-separated rule names to suppress (e.g. "todo-marker,long-line").
    """
    from .analyzer import scan_quick, scan_diff, filter_report
    from .config import load_project_config, compile_custom_rules
    from .mcp_format import format_scan_report

    sev = _parse_severity(min_severity)
    if isinstance(sev, str):
        return sev

    try:
        root = _validate_path(Path(path))
    except ValueError as e:
        return str(e)
    if not root.exists():
        return f"Error: path '{path}' does not exist"

    scan_root = root if root.is_dir() else root.parent
    project_config = load_project_config(scan_root)
    custom_rules = compile_custom_rules(project_config)

    try:
        if diff_only:
            try:
                report, _ = scan_diff(
                    root,
                    base_ref=diff_ref or None,
                    language_filter=language,
                    custom_rules=custom_rules,
                )
            except ValueError as e:
                return f"Error: {e}"
        else:
            report = scan_quick(
                root,
                language_filter=language,
                custom_rules=custom_rules,
                use_cache=False,
            )
    except Exception as e:  # MCP tool boundary: return user-friendly error
        return f"Error during scan: {e}"

    ignore_set = {r.strip() for r in ignore_rules.split(",")} if ignore_rules else None
    report = filter_report(report, ignore_rules=ignore_set, min_severity=sev)

    return format_scan_report(report)


@mcp.tool()
def doji_scan_file(path: str) -> str:
    """Quick scan of a single file. Faster than doji_scan for one file.

    Args:
        path: Path to the file to scan.
    """
    from .detector import analyze_file_static
    from .mcp_format import format_file_findings

    try:
        content, lang, filepath = _read_file(path)
    except ValueError as e:
        return str(e)

    try:
        findings = analyze_file_static(filepath, content, lang).findings
    except Exception as e:  # MCP tool boundary: return user-friendly error
        return f"Error analyzing file: {e}"

    lines = content.count("\n") + 1
    return format_file_findings(filepath, lang, lines, findings)


@mcp.tool()
def doji_fix(
    path: str,
    rules: str | None = None,
    min_severity: str = "warning",
) -> str:
    """Show available auto-fixes for a file WITHOUT applying them.

    Review the output, then apply fixes yourself using the Edit tool.

    Args:
        path: File or directory to find fixes for.
        rules: Comma-separated rule names to fix (e.g. "bare-except,unused-import").
        min_severity: Minimum severity: "critical", "warning", or "info".
    """
    from .detector import analyze_file_static
    from .fixer import fix_file as fixer_fix_file
    from .types import FixReport
    from .config import load_project_config, compile_custom_rules
    from .mcp_format import format_fix_report

    sev = _parse_severity(min_severity)
    if isinstance(sev, str):
        return sev

    try:
        root = _validate_path(Path(path))
    except ValueError as e:
        return str(e)
    if not root.exists():
        return f"Error: path '{path}' does not exist"

    files = _collect_files_with_lang(root)
    if not files:
        if root.is_file():
            return f"Error: unsupported file type '{root.suffix}'"
        return "No fixable files found."

    fix_root = root if root.is_dir() else root.parent
    project_config = load_project_config(fix_root)
    custom_rules = compile_custom_rules(project_config)
    rules_list = [r.strip() for r in rules.split(",")] if rules else None

    all_fixes = []
    files_fixed = 0
    errors = []

    for filepath, file_lang in files:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError as e:
            errors.append(f"{filepath.name}: {e}")
            continue

        findings = analyze_file_static(str(filepath), content, file_lang,
                                       custom_rules=custom_rules).findings
        findings = _filter_findings_by_severity(findings, sev)
        if not findings:
            continue

        try:
            report = fixer_fix_file(
                str(filepath), content, file_lang, findings,
                use_llm=False, dry_run=True,
                rules=rules_list, custom_rules=custom_rules,
            )
        except (OSError, ValueError, RuntimeError) as e:
            errors.append(f"{filepath.name}: {e}")
            continue

        all_fixes.extend(report.fixes)
        if report.files_fixed > 0:
            files_fixed += 1

    aggregate = FixReport(
        root=str(root),
        files_fixed=files_fixed,
        total_fixes=len(all_fixes),
        applied=0,
        skipped=0,
        failed=0,
        fixes=all_fixes,
    )

    result = format_fix_report(aggregate)
    if errors:
        result += f"\n\nWarnings ({len(errors)} files skipped):"
        for err in errors[:5]:
            result += f"\n  {err}"
    return result


@mcp.tool()
def doji_explain(path: str) -> str:
    """Get a structural explanation of a code file.

    Returns: summary, structure breakdown, design patterns, and learning notes.

    Args:
        path: Path to the file to explain.
    """
    from .detector import analyze_file_static
    from .semantic.explain import explain_file
    from .mcp_format import format_explanation

    try:
        content, lang, filepath = _read_file(path)
    except ValueError as e:
        return str(e)

    # analyze_file_static already runs semantics + type inference internally
    result = analyze_file_static(filepath, content, lang)

    explanation = explain_file(
        content, filepath, lang,
        semantics=result.semantics,
        findings=result.findings,
        type_map=result.type_map,
    )

    return format_explanation(explanation)


@mcp.tool()
def doji_analyze_project(
    path: str,
    language: str | None = None,
    depth: int = 2,
) -> str:
    """Analyze a project for cross-file issues: dependencies, dead code, circular imports.

    Uses graph analysis only (no LLM calls, free and fast).

    Args:
        path: Project directory to analyze.
        language: Filter by language (python, javascript, etc.).
        depth: Dependency traversal depth (default 2).
    """
    from .graph.project import analyze_project
    from .mcp_format import format_project_analysis

    try:
        root = _validate_path(Path(path))
    except ValueError as e:
        return str(e)
    if not root.is_dir():
        return f"Error: '{path}' is not a directory"

    # Clamp depth to prevent excessive graph traversal on large projects
    depth = max(1, min(depth, 10))

    try:
        analysis = analyze_project(
            str(root),
            language_filter=language,
            depth=depth,
            use_llm=False,
        )
    except Exception as e:  # MCP tool boundary: return user-friendly error
        return f"Error analyzing project: {e}"

    return format_project_analysis(analysis)
