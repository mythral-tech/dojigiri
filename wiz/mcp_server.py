"""MCP server exposing wiz static analysis tools to Claude Code.

Start with: python -m wiz mcp
Configure with: python -m wiz setup-claude

Tools:
  wiz_scan         — Scan files/dirs for issues (the workhorse)
  wiz_scan_file    — Quick single-file scan
  wiz_fix          — Show available fixes (dry run, doesn't apply)
  wiz_explain      — Structural explanation of a file
  wiz_analyze_project — Cross-file analysis (deps, dead code, cycles)

All tools return concise text, not JSON. Errors return as strings.
"""

from __future__ import annotations

from pathlib import Path

from mcp.server.fastmcp import FastMCP

mcp = FastMCP(
    "wiz",
    instructions=(
        "Wiz is a static analyzer with 40+ rules, tree-sitter semantic analysis, "
        "taint tracking, null safety, and cross-file analysis. "
        "Use wiz_scan for broad scans, wiz_scan_file for single files, "
        "wiz_fix to preview fixes (then apply with Edit tool), "
        "wiz_explain to understand file structure, "
        "wiz_analyze_project for cross-file dependency analysis."
    ),
)


def _read_file(path: str) -> tuple[str, str, str]:
    """Read a file and detect its language. Returns (content, language, filepath_str).

    Raises a descriptive error string on failure.
    """
    from .analyzer import detect_language

    filepath = Path(path).resolve()
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


@mcp.tool()
def wiz_scan(
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
    from .config import Severity, load_project_config, compile_custom_rules
    from .mcp_format import format_scan_report

    root = Path(path).resolve()
    if not root.exists():
        return f"Error: path '{path}' does not exist"

    # Load project config
    scan_root = root if root.is_dir() else root.parent
    project_config = load_project_config(scan_root)
    custom_rules = compile_custom_rules(project_config)

    try:
        if diff_only:
            try:
                report, resolved_ref = scan_diff(
                    root,
                    base_ref=diff_ref if diff_ref else None,
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
    except Exception as e:
        return f"Error during scan: {e}"

    # Apply filters
    severity_map = {"critical": Severity.CRITICAL, "warning": Severity.WARNING, "info": Severity.INFO}
    sev = severity_map.get(min_severity)
    if min_severity and sev is None:
        return f"Error: invalid min_severity '{min_severity}'. Use: critical, warning, or info"
    ignore_set = set(r.strip() for r in ignore_rules.split(",")) if ignore_rules else None

    report = filter_report(report, ignore_rules=ignore_set, min_severity=sev)

    return format_scan_report(report)


@mcp.tool()
def wiz_scan_file(path: str) -> str:
    """Quick scan of a single file. Faster than wiz_scan for one file.

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
        findings = analyze_file_static(filepath, content, lang)
    except Exception as e:
        return f"Error analyzing file: {e}"

    lines = content.count("\n") + 1
    return format_file_findings(filepath, lang, lines, findings)


@mcp.tool()
def wiz_fix(
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
    from .analyzer import detect_language, collect_files
    from .config import Severity, FixReport, load_project_config, compile_custom_rules
    from .mcp_format import format_fix_report

    root = Path(path).resolve()
    if not root.exists():
        return f"Error: path '{path}' does not exist"

    severity_map = {"critical": Severity.CRITICAL, "warning": Severity.WARNING, "info": Severity.INFO}
    severity_order = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}
    min_sev = severity_map.get(min_severity)
    rules_list = [r.strip() for r in rules.split(",")] if rules else None

    # Load project config
    fix_root = root if root.is_dir() else root.parent
    project_config = load_project_config(fix_root)
    custom_rules = compile_custom_rules(project_config)

    # Collect files
    if root.is_file():
        lang = detect_language(root)
        if not lang:
            return f"Error: unsupported file type '{root.suffix}'"
        files_to_fix = [(root, lang)]
    else:
        collected, _ = collect_files(root)
        files_to_fix = []
        for fp in collected:
            fl = detect_language(fp)
            if fl:
                files_to_fix.append((fp, fl))

    if not files_to_fix:
        return "No fixable files found."

    all_fixes = []
    total_applied = total_skipped = total_failed = files_fixed = 0

    for filepath, file_lang in files_to_fix:
        try:
            content = filepath.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        findings = analyze_file_static(str(filepath), content, file_lang,
                                       custom_rules=custom_rules)

        # Severity filter
        if min_sev:
            min_ord = severity_order[min_sev]
            findings = [f for f in findings if severity_order.get(f.severity, 9) <= min_ord]

        if not findings:
            continue

        try:
            report = fixer_fix_file(
                str(filepath), content, file_lang, findings,
                use_llm=False, dry_run=True,
                rules=rules_list, custom_rules=custom_rules,
            )
        except Exception:
            continue

        all_fixes.extend(report.fixes)
        total_applied += report.applied
        total_skipped += report.skipped
        total_failed += report.failed
        if report.files_fixed > 0:
            files_fixed += 1

    aggregate = FixReport(
        root=str(root),
        files_fixed=files_fixed,
        total_fixes=len(all_fixes),
        applied=total_applied,
        skipped=total_skipped,
        failed=total_failed,
        fixes=all_fixes,
    )

    return format_fix_report(aggregate)


@mcp.tool()
def wiz_explain(path: str) -> str:
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

    # Static analysis for findings context
    findings = analyze_file_static(filepath, content, lang)

    # Extract semantics (optional, graceful fallback)
    semantics = None
    type_map = None
    try:
        from .semantic.core import extract_semantics
        semantics = extract_semantics(content, filepath, lang)
        if semantics:
            from .semantic.lang_config import get_config
            config = get_config(lang)
            if config:
                from .semantic.types import infer_types
                source_bytes = content.encode("utf-8")
                type_map = infer_types(semantics, source_bytes, config)
    except Exception:
        pass  # tree-sitter not installed or other issue

    explanation = explain_file(
        content, filepath, lang,
        semantics=semantics,
        findings=findings,
        type_map=type_map,
    )

    return format_explanation(explanation)


@mcp.tool()
def wiz_analyze_project(
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

    root = Path(path).resolve()
    if not root.is_dir():
        return f"Error: '{path}' is not a directory"

    try:
        analysis = analyze_project(
            str(root),
            language_filter=language,
            depth=depth,
            use_llm=False,
        )
    except Exception as e:
        return f"Error analyzing project: {e}"

    return format_project_analysis(analysis)
