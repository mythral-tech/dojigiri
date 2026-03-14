"""FastMCP server exposing Dojigiri static analysis tools to AI agents.

Orchestrator module with intentionally high coupling — MCP endpoint that
dispatches to all analysis subsystems.

Runs as a subprocess via MCP protocol. Provides six tools: doji_scan,
doji_scan_file, doji_fix, doji_explain, doji_analyze_project, and doji_sca.
Three resources: dojigiri://rules, dojigiri://languages, dojigiri://config.
All tools return concise plain text, not JSON. Errors return as strings.

Called by: external (MCP protocol, e.g. Claude Code)
Calls into: config.py, analyzer.py, mcp_format.py, semantic/explain.py,
            graph/project.py, fixer.py, sca/scanner.py
Data in -> Data out: tool requests (file paths, options) -> formatted text
"""

from __future__ import annotations  # noqa

import logging
from pathlib import Path

logger = logging.getLogger(__name__)
from collections.abc import Sequence

from mcp.server.fastmcp import FastMCP
from mcp.types import ToolAnnotations

from .types import SEVERITY_ORDER, Severity

_READ_ONLY_ANNOTATIONS = ToolAnnotations(readOnlyHint=True, idempotentHint=True)

mcp = FastMCP(
    "dojigiri",
    instructions=(
        "Dojigiri is a static analyzer with 130+ rules, tree-sitter semantic analysis, "
        "taint tracking, null safety, and cross-file analysis. "
        "Resources: dojigiri://rules (all rules with severity/CWE), "
        "dojigiri://languages (supported languages), dojigiri://config (server config). "
        "Read dojigiri://rules to understand available checks before scanning. "
        "Use doji_scan for directories, doji_scan_file for single files. "
        "doji_fix previews fixes (then apply with Edit tool), "
        "doji_explain explains file structure, "
        "doji_analyze_project does cross-file dependency analysis, "
        "doji_sca scans dependencies for known vulnerabilities. "
        "Workflow: read dojigiri://rules first, then scan. "
        "Error behavior: tools raise ValueError on invalid input (isError=true in MCP response)."
    ),
)

_SEVERITY_MAP = {"critical": Severity.CRITICAL, "warning": Severity.WARNING, "info": Severity.INFO}

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
                    _r,
                    _cwd_resolved,
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
                    "Ignoring allowed root '%s' — must be under cwd (%s)",
                    r,
                    cwd,
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


def _parse_severity(value: str) -> Severity:
    """Parse a severity string. Returns Severity on success, raises ValueError on failure."""
    sev = _SEVERITY_MAP.get(value)
    if sev is None:
        raise ValueError(f"Invalid min_severity '{value}'. Use: critical, warning, or info")
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
        raise ValueError(f"Error reading file: {e}") from e

    return content, lang, str(filepath)


def _collect_files_with_lang(root: Path) -> list[tuple[Path, str]]:
    """Collect analyzable files under root, each paired with its detected language."""
    from .discovery import collect_files_with_lang

    return collect_files_with_lang(root)


def _filter_findings_by_severity(findings: list, min_severity: Severity) -> list:
    """Filter findings to those at or above min_severity."""
    threshold = SEVERITY_ORDER[min_severity]
    return [f for f in findings if SEVERITY_ORDER.get(f.severity, 9) <= threshold]


# ─── Tools ───────────────────────────────────────────────────────────


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
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
    from .analyzer import filter_report, scan_diff, scan_quick
    from .config import compile_custom_rules, load_project_config
    from .mcp_format import format_scan_report

    sev = _parse_severity(min_severity)

    root = _validate_path(Path(path))
    if not root.exists():
        raise ValueError(f"Path '{path}' does not exist")

    scan_root = root if root.is_dir() else root.parent
    project_config = load_project_config(scan_root)
    custom_rules = compile_custom_rules(project_config)

    try:
        if diff_only:
            report, _ = scan_diff(  # doji:ignore(taint-flow) — sink uses subprocess list args, no shell
                root,
                base_ref=diff_ref or None,
                language_filter=language,
                custom_rules=custom_rules,
            )
        else:
            report = scan_quick(
                root,
                language_filter=language,
                custom_rules=custom_rules,
                use_cache=False,
            )
    except Exception as e:
        raise ValueError(f"Scan failed: {e}") from e

    ignore_set = {r.strip() for r in ignore_rules.split(",")} if ignore_rules else None
    report = filter_report(report, ignore_rules=ignore_set, min_severity=sev)

    return format_scan_report(report)


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def doji_scan_file(path: str) -> str:
    """Quick scan of a single file. Faster than doji_scan for one file.

    Args:
        path: Path to the file to scan.
    """
    from .detector import analyze_file_static
    from .mcp_format import format_file_findings

    content, lang, filepath = _read_file(path)

    try:
        findings = analyze_file_static(filepath, content, lang).findings
    except Exception as e:
        raise ValueError(f"Analysis failed: {e}") from e

    lines = content.count("\n") + 1
    return format_file_findings(filepath, lang, lines, findings)


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
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
    from .config import compile_custom_rules, load_project_config
    from .detector import analyze_file_static
    from .fixer import fix_file as fixer_fix_file
    from .mcp_format import format_fix_report
    from .types import FixReport

    sev = _parse_severity(min_severity)

    root = _validate_path(Path(path))
    if not root.exists():
        raise ValueError(f"Path '{path}' does not exist")

    files = _collect_files_with_lang(root)
    if not files:
        if root.is_file():
            raise ValueError(f"Unsupported file type '{root.suffix}'")
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

        findings = analyze_file_static(str(filepath), content, file_lang, custom_rules=custom_rules).findings
        findings = _filter_findings_by_severity(findings, sev)
        if not findings:
            continue

        try:
            report = fixer_fix_file(
                str(filepath),
                content,
                file_lang,
                findings,
                use_llm=False,
                dry_run=True,
                rules=rules_list,
                custom_rules=custom_rules,
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


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def doji_explain(path: str) -> str:
    """Get a structural explanation of a code file.

    Returns: summary, structure breakdown, design patterns, and learning notes.

    Args:
        path: Path to the file to explain.
    """
    from .detector import analyze_file_static
    from .mcp_format import format_explanation
    from .semantic.explain import explain_file

    content, lang, filepath = _read_file(path)

    # analyze_file_static already runs semantics + type inference internally
    result = analyze_file_static(filepath, content, lang)

    explanation = explain_file(
        content,
        filepath,
        lang,
        semantics=result.semantics,
        findings=result.findings,
        type_map=result.type_map,
    )

    return format_explanation(explanation)


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
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

    root = _validate_path(Path(path))
    if not root.is_dir():
        raise ValueError(f"'{path}' is not a directory")

    # Clamp depth to prevent excessive graph traversal on large projects
    depth = max(1, min(depth, 10))

    try:
        analysis = analyze_project(
            str(root),
            language_filter=language,
            depth=depth,
            use_llm=False,
        )
    except Exception as e:
        raise ValueError(f"Project analysis failed: {e}") from e

    return format_project_analysis(analysis)


@mcp.tool(annotations=_READ_ONLY_ANNOTATIONS)
def doji_sca(path: str, offline: bool = False) -> str:
    """Scan project dependencies for known vulnerabilities (SCA).

    Args:
        path: Project directory containing package manifests (package.json, requirements.txt, etc.).
        offline: If True, skip network vulnerability lookups and only parse manifests.
    """
    from .sca.scanner import scan_sca

    root = _validate_path(Path(path))
    if not root.is_dir():
        raise ValueError(f"'{path}' is not a directory")

    analyses = scan_sca(root, offline=offline)

    if not analyses:
        return "SCA: No vulnerable dependencies found (or no lockfiles detected)."

    lines = []
    total_findings = 0
    for analysis in analyses:
        lines.append(f"Lockfile: {analysis.path}")
        for finding in analysis.findings:
            sev_tag = finding.severity.value.upper()
            lines.append(f"  [{sev_tag}] {finding.message}")
            if finding.suggestion:
                lines.append(f"    Fix: {finding.suggestion}")
            total_findings += 1
        lines.append("")

    header = f"SCA: {total_findings} vulnerable dependencies in {len(analyses)} lockfile(s)\n"
    return header + "\n".join(lines)


# ─── Resources ────────────────────────────────────────────────────────


@mcp.resource("dojigiri://rules")
def resource_rules() -> str:
    """List all Dojigiri rules with severity, category, and CWE mapping."""
    from .languages import list_all_rules

    rules = list_all_rules()
    lines = [f"Dojigiri Rules ({len(rules)} total)\n"]
    for r in rules:
        cwe = r.get("cwe", "")
        cwe_str = f" [{cwe}]" if cwe else ""
        langs = ", ".join(r["languages"])
        lines.append(f"  {r['name']}  severity={r['severity']}  category={r['category']}  languages={langs}{cwe_str}")
    return "\n".join(lines)


@mcp.resource("dojigiri://languages")
def resource_languages() -> str:
    """List supported languages and their file extensions."""
    from .config import LANGUAGE_EXTENSIONS

    # Group extensions by language
    lang_exts: dict[str, list[str]] = {}
    for ext, lang in sorted(LANGUAGE_EXTENSIONS.items()):
        lang_exts.setdefault(lang, []).append(ext)

    lines = [f"Supported Languages ({len(lang_exts)})\n"]
    for lang in sorted(lang_exts):
        exts = ", ".join(sorted(lang_exts[lang]))
        lines.append(f"  {lang}: {exts}")
    return "\n".join(lines)


@mcp.resource("dojigiri://config")
def resource_config() -> str:
    """Show current MCP server configuration."""
    lines = ["Dojigiri MCP Config\n"]
    lines.append("Allowed roots:")
    for root in _allowed_roots:
        lines.append(f"  {root}")
    lines.append(f"\nTotal allowed roots: {len(_allowed_roots)}")
    return "\n".join(lines)


@mcp.resource("dojigiri://rules/{language}")
def resource_rules_by_language(language: str) -> str:
    """List Dojigiri rules filtered to a specific language."""
    from .languages import list_all_rules

    rules = list_all_rules()
    lang_lower = language.lower()
    filtered = [r for r in rules if lang_lower in r["languages"] or "all" in r["languages"]]
    if not filtered:
        return f"No rules found for language '{language}'."
    lines = [f"Dojigiri Rules for {language} ({len(filtered)} rules)\n"]
    for r in filtered:
        cwe = r.get("cwe", "")
        cwe_str = f" [{cwe}]" if cwe else ""
        lines.append(f"  {r['name']}  severity={r['severity']}  category={r['category']}{cwe_str}")
    return "\n".join(lines)


# ─── Prompts ──────────────────────────────────────────────────────────


@mcp.prompt()
def review_file(path: str) -> str:
    """Comprehensive file review: scan for issues then explain the file structure."""
    return (
        f"Review the file at {path}:\n"
        f"1. Run doji_scan_file on {path} to find bugs, security issues, and quality problems.\n"
        f"2. Run doji_explain on {path} to understand the file's structure and design.\n"
        f"3. Summarize all findings and explain which are most important to fix, and why."
    )


@mcp.prompt()
def security_audit(path: str) -> str:
    """Security-focused audit: SAST scan plus dependency vulnerability check."""
    return (
        f"Perform a security audit of {path}:\n"
        f"1. Run doji_scan on {path} with min_severity='critical' to find security vulnerabilities.\n"
        f"2. Run doji_scan on {path} with min_severity='warning' to catch lower-severity security issues.\n"
        f"3. Run doji_sca on {path} to check dependencies for known CVEs.\n"
        f"4. Provide a prioritized list of security findings with remediation guidance."
    )
