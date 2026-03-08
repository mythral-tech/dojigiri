"""Console output renderer with ANSI severity colors and summary tables.

Formats a ScanReport into human-readable terminal output with color-coded
severities, grouped findings, and summary statistics.

Called by: __main__.py
Calls into: config.py
Data in -> Data out: ScanReport -> stdout (ANSI-colored text)
"""

from __future__ import annotations

import json
import logging
import sys
import textwrap
from collections import Counter
from typing import Any

from .types import (
    Category,
    FileAnalysis,
    Finding,
    FixReport,
    FixSource,
    FixStatus,
    ProjectAnalysis,
    ScanReport,
    Severity,
    Source,
)

logger = logging.getLogger(__name__)


def _ensure_utf8() -> None:
    """Reconfigure stdout for UTF-8 on Windows if possible."""
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except (OSError, ValueError) as e:
            logger.debug("Failed to reconfigure stdout for UTF-8: %s", e)


_ensure_utf8()


# ANSI colors (works in Windows Terminal / modern terminals)
COLORS = {
    "red": "\033[91m",
    "yellow": "\033[93m",
    "blue": "\033[94m",
    "green": "\033[92m",
    "gray": "\033[90m",
    "bold": "\033[1m",
    "dim": "\033[2m",
    "reset": "\033[0m",
}

SEVERITY_STYLE = {
    Severity.CRITICAL: ("red", "CRITICAL"),
    Severity.WARNING: ("yellow", "WARNING "),
    Severity.INFO: ("blue", "INFO    "),
}

SOURCE_LABEL = {
    Source.STATIC: "regex",
    Source.AST: "ast",
    Source.LLM: "llm",
}

# Severity string -> ANSI color name (used by dict-based renderers that work with
# raw severity strings rather than Severity enum values).
_SEVERITY_COLOR_NAME = {"critical": "red", "warning": "yellow", "info": "blue"}


def _c(color: str, text: str) -> str:
    """Wrap text in ANSI color."""
    if not sys.stdout.isatty():
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def print_finding(f: Finding, show_file: bool = True) -> None:
    """Print a single finding."""
    from .compliance import get_cwe

    color, label = SEVERITY_STYLE[f.severity]
    src = SOURCE_LABEL.get(f.source, f.source.value)

    cwe = get_cwe(f.rule)
    cwe_tag = f"  {_c('dim', cwe)}" if cwe else ""

    location = f"{f.file}:{f.line}" if show_file else f"line {f.line}"
    print(f"  {_c(color, label)}  {_c('dim', f'[{src}]')}  {_c('dim', f'[{f.rule}]')}{cwe_tag}  {location}")
    print(f"           {f.message}")
    if f.snippet:
        print(f"           {_c('gray', f.snippet)}")
    if f.suggestion:
        print(f"           {_c('green', '→ ' + f.suggestion)}")
    print()


def print_file_analysis(fa: FileAnalysis) -> None:
    """Print findings for a single file."""
    if not fa.findings:
        return
    counts = []
    if fa.critical_count:
        counts.append(_c("red", f"{fa.critical_count} critical"))
    if fa.warning_count:
        counts.append(_c("yellow", f"{fa.warning_count} warning"))
    if fa.info_count:
        counts.append(_c("blue", f"{fa.info_count} info"))
    summary = ", ".join(counts)

    print(f"\n{_c('bold', fa.path)}  ({fa.language}, {fa.lines} lines)  [{summary}]")
    print("─" * 70)
    for f in fa.findings:
        print_finding(f, show_file=False)


def print_scan_summary(report: ScanReport, duration: float | None = None, classification: str | None = None) -> None:
    """Print the scan summary."""
    if classification:
        print(f"\n{_c('bold', f'// {classification} //')}")
    print()
    print(_c("bold", "═" * 70))
    timing = f" in {duration:.1f}s" if duration is not None else ""
    print(_c("bold", f"  Scan Complete — {report.mode.upper()} mode{timing}"))
    print(_c("bold", "═" * 70))
    print()
    print(f"  Files scanned:  {report.files_scanned}")
    print(f"  Files skipped:  {report.files_skipped}")
    if report.files_scanned == 0:
        print()
        print(f"  {_c('yellow', 'No supported files found.')}")
        print("  Dojigiri scans: Python, JavaScript, TypeScript, C#, Java, Go, Rust, C/C++, and more.")
        print("  Use 'doji init' to create a .doji-ignore, or check your --lang filter.")
    print()
    print(f"  {_c('red', f'Critical:  {report.critical}')}")
    print(f"  {_c('yellow', f'Warnings:  {report.warnings}')}")
    print(f"  {_c('blue', f'Info:      {report.info}')}")
    print(f"  {'─' * 30}")
    print(f"  Total:     {report.total_findings}")

    # Category breakdown
    cat_counts: Counter[Category] = Counter()
    for fa in report.file_analyses:
        for f in fa.findings:
            cat_counts[f.category] += 1
    if cat_counts:
        print()
        cat_labels = [
            (Category.BUG, "Bug"),
            (Category.SECURITY, "Security"),
            (Category.PERFORMANCE, "Performance"),
            (Category.STYLE, "Style"),
            (Category.DEAD_CODE, "Dead code"),
        ]
        parts = [f"{label}: {cat_counts[cat]}" for cat, label in cat_labels if cat_counts[cat]]
        print(f"  By category:  {' | '.join(parts)}")

    if report.llm_cost_usd > 0:
        print(f"\n  LLM cost:  ${report.llm_cost_usd:.4f}")
        if report.llm_models_used:
            # Show short model names (strip date suffixes for readability)
            short_names = []
            for m in report.llm_models_used:
                # "claude-haiku-4-20250514" -> "claude-haiku-4"
                parts = m.rsplit("-", 1)
                if len(parts) == 2 and parts[1].isdigit() and len(parts[1]) == 8:
                    short_names.append(parts[0])
                else:
                    short_names.append(m)
            print(f"  Models:    {', '.join(short_names)}")
        print(f"\n  {_c('dim', 'Note: Findings marked [llm] are AI-generated and may contain')}")
        print(f"  {_c('dim', 'false positives or miss real issues. Not a substitute for')}")
        print(f"  {_c('dim', 'professional security review. See: doji privacy')}")
    if classification:
        print(f"\n{_c('bold', f'// {classification} //')}")
    print()


def print_report(
    report: ScanReport, verbose: bool = False, duration: float | None = None, classification: str | None = None
) -> None:
    """Print full report — file analyses + summary."""
    # Show files with findings (or all files in verbose mode)
    for fa in report.file_analyses:
        if fa.findings or verbose:
            print_file_analysis(fa)

    # Cross-file findings (semantic clones, etc.)
    if report.cross_file_findings:
        print(f"\n{_c('bold', f'Cross-file Findings ({len(report.cross_file_findings)})')}")
        print("-" * 70)
        for cf in report.cross_file_findings:
            print_cross_file_finding(cf.to_dict())

    print_scan_summary(report, duration=duration, classification=classification)


CONFIDENCE_BADGE = {
    "high": ("green", "HIGH"),
    "medium": ("yellow", "MED"),
    "low": ("gray", "LOW"),
}


def _print_debug_finding(f: dict, index: int) -> None:
    """Render a single structured debug/optimize finding."""
    severity = f.get("severity", "info")
    sev_color = _SEVERITY_COLOR_NAME.get(severity, "blue")
    sev_label = severity.upper().ljust(8)

    confidence = f.get("confidence", "medium")
    conf_color, conf_label = CONFIDENCE_BADGE.get(confidence, ("gray", "???"))

    title = f.get("title", "Finding")
    line = f.get("line", "?")
    end_line = f.get("end_line")
    category = f.get("category", "")
    line_range = f"line {line}" + (f"-{end_line}" if end_line else "")

    print(
        f"  {_c(sev_color, sev_label)} {_c(conf_color, f'[{conf_label}]')}  "
        f"{_c('bold', title)}  {_c('dim', f'({line_range}, {category})')}"
    )

    description = f.get("description", "")
    if description:
        print(f"           {description}")

    suggestion = f.get("suggestion", "")
    if suggestion:
        print(f"           {_c('green', '→ ' + suggestion)}")

    code_fix = f.get("code_fix")
    if code_fix:
        print(f"           {_c('dim', 'Fix:')}")
        for code_line in code_fix.splitlines():
            print(f"             {_c('green', code_line)}")
    print()


def _print_llm_analysis_result(
    filepath: str,
    static_findings: list[Finding],
    llm_result: dict | None,
    *,
    title: str,
    static_label: str,
    static_filter: tuple | None = None,
    summary_label: str = "Summary:",
    findings_label_fmt: str = "Claude found {n} issue(s):",
    empty_msg: str = "No additional issues found by Claude.",
) -> None:
    """Shared renderer for LLM subcommand output (debug, optimize).

    Args:
        title: Header prefix (e.g. "Debug", "Optimize").
        static_label: Label for the static findings section.
        static_filter: If set, only show static findings whose category is in this tuple.
        summary_label: Label for the LLM summary line.
        findings_label_fmt: Format string for the findings header ({n} = count).
        empty_msg: Message when LLM returns no findings or quick wins.
    """
    print(f"\n{_c('bold', f'{title}: {filepath}')}")
    print("═" * 70)

    if static_findings:
        filtered = static_findings
        if static_filter:
            filtered = [f for f in static_findings if f.category in static_filter]
        if filtered:
            print(f"\n{_c('bold', static_label)}")
            for f in filtered:
                print_finding(f, show_file=False)

    if llm_result is None:
        print()
        return

    if "raw_markdown" in llm_result:
        print(f"\n{_c('bold', 'Claude analysis:')}")
        print(llm_result["raw_markdown"])
        print()
        return

    # Structured output
    summary = llm_result.get("summary", "")
    findings = llm_result.get("findings", [])
    quick_wins = llm_result.get("quick_wins", [])

    if summary:
        print(f"\n{_c('bold', summary_label)} {summary}")

    if findings:
        print(f"\n{_c('bold', findings_label_fmt.format(n=len(findings)))}")
        for i, f in enumerate(findings, 1):
            _print_debug_finding(f, i)

    if quick_wins:
        print(f"{_c('bold', 'Quick wins:')}")
        for qw in quick_wins:
            print(f"  {_c('green', '→')} {qw}")

    if not findings and not quick_wins:
        print(f"\n  {_c('green', empty_msg)}")
    print()


def print_debug_result(filepath: str, static_findings: list[Finding], llm_result: dict | None = None) -> None:
    """Print debug command output."""
    _print_llm_analysis_result(
        filepath,
        static_findings,
        llm_result,
        title="Debug",
        static_label="Static analysis findings:",
        summary_label="Summary:",
        findings_label_fmt="Claude found {n} issue(s):",
        empty_msg="No additional issues found by Claude.",
    )


def print_optimize_result(filepath: str, static_findings: list[Finding], llm_result: dict | None = None) -> None:
    """Print optimize command output."""
    _print_llm_analysis_result(
        filepath,
        static_findings,
        llm_result,
        title="Optimize",
        static_label="Static analysis (perf-relevant):",
        static_filter=(Category.PERFORMANCE, Category.STYLE),
        summary_label="Assessment:",
        findings_label_fmt="Found {n} optimization(s):",
        empty_msg="Code is well-optimized.",
    )


def print_analysis_json(
    filepath: str, static_findings: list[Finding], llm_result: dict | None, tracker: Any | None = None
) -> None:
    """Print analysis result as JSON to stdout."""
    output = {
        "filepath": filepath,
        "static_findings": [f.to_dict() for f in static_findings] if static_findings else [],
        "llm_result": llm_result,
    }
    if tracker:
        output["cost_usd"] = round(tracker.total_cost, 6)
    print(json.dumps(output, indent=2))


# Keep aliases for backward compatibility
print_debug_json = print_analysis_json
print_optimize_json = print_analysis_json


def print_cost_estimate(total_lines: int, total_files: int, est_tokens: int, est_cost: float) -> None:
    """Print cost estimate for deep scan."""
    print(f"\n{_c('bold', 'Cost Estimate — Deep Scan')}")
    print("─" * 40)
    print(f"  Files to analyze:  {total_files}")
    print(f"  Total lines:       {total_lines:,}")
    print(f"  Est. input tokens: {est_tokens:,}")
    print(f"  Est. output tokens: ~{est_tokens // 4:,}")
    print(f"  {_c('bold', f'Est. cost:           ${est_cost:.4f}')}")
    # Show actual model used for pricing (tiered mode uses Haiku for scan chunks)
    import os as _os

    from .config import LLM_DEEP_MODEL, LLM_SCAN_MODEL, LLM_TIER_MODE

    _tier_mode = _os.environ.get("DOJI_LLM_TIER_MODE", LLM_TIER_MODE)
    _user_model = _os.environ.get("DOJI_LLM_MODEL")
    if _tier_mode == "auto" and not _user_model:
        print(f"\n  Model: {LLM_SCAN_MODEL} (scan) + {LLM_DEEP_MODEL} (deep)")
    elif _user_model:
        print(f"\n  Model: {_user_model}")
    else:
        print(f"\n  Model: {LLM_DEEP_MODEL}")
    print("  (Actual cost may vary based on findings density and cache hits)")
    print()


def print_setup_status(api_key_set: bool, anthropic_installed: bool) -> None:
    """Print setup check results."""
    print(f"\n{_c('bold', 'dojigiri — Environment Check')}")
    print("─" * 40)

    if api_key_set:
        print(f"  ANTHROPIC_API_KEY:  {_c('green', 'set')}")
    else:
        print(f"  ANTHROPIC_API_KEY:  {_c('red', 'not set')}")
        print(f"                      {_c('gray', 'Required for --deep, debug, optimize')}")
        print(f"                      {_c('gray', 'Set: export ANTHROPIC_API_KEY=sk-...')}")

    if anthropic_installed:
        print(f"  anthropic package:  {_c('green', 'installed')}")
    else:
        print(f"  anthropic package:  {_c('red', 'not installed')}")
        print(f"                      {_c('gray', 'Install: pip install anthropic')}")

    print(f"\n  Quick scan (free):  {_c('green', 'always available')}")
    deep_ok = api_key_set and anthropic_installed
    if deep_ok:
        print(f"  Deep scan (paid):   {_c('green', 'ready')}")
    else:
        print(f"  Deep scan (paid):   {_c('red', 'not ready')}")
    print()


# ─── Project analysis rendering ──────────────────────────────────────


def print_graph_summary(graph_dict: dict, metrics_dict: dict) -> None:
    """ASCII dependency graph summary with fan-in/fan-out, hubs, cycles, dead modules."""
    print(f"\n{_c('bold', 'Dependency Graph')}")
    print("=" * 70)

    m = metrics_dict
    print(f"  Files:    {m.get('total_files', 0)}")
    print(f"  Edges:    {m.get('total_edges', 0)}")
    print(f"  Coupling: {m.get('coupling_score', 0):.2%}")
    print(f"  Avg fan-in:  {m.get('avg_fan_in', 0):.1f}")
    print(f"  Avg fan-out: {m.get('avg_fan_out', 0):.1f}")

    max_fi = m.get("max_fan_in", ["", 0])
    max_fo = m.get("max_fan_out", ["", 0])
    if max_fi[0]:
        print(f"  Max fan-in:  {max_fi[0]} ({max_fi[1]})")
    if max_fo[0]:
        print(f"  Max fan-out: {max_fo[0]} ({max_fo[1]})")

    hubs = m.get("hub_files", [])
    if hubs:
        print(f"\n  {_c('yellow', 'Hub files')} (high connectivity):")
        for h in hubs:
            node = graph_dict.get("nodes", {}).get(h, {})
            print(f"    {h}  (in={node.get('fan_in', '?')}, out={node.get('fan_out', '?')})")

    cycles = m.get("circular_deps", [])
    if cycles:
        print(f"\n  {_c('red', f'Circular dependencies ({len(cycles)})')}:")
        for cycle in cycles[:5]:
            print(f"    {' -> '.join(cycle)}")
        if len(cycles) > 5:
            print(f"    ... and {len(cycles) - 5} more")

    dead = m.get("dead_modules", [])
    if dead:
        print(f"\n  {_c('gray', f'Dead modules ({len(dead)})')} (never imported):")
        for d in dead[:10]:
            print(f"    {d}")
        if len(dead) > 10:
            print(f"    ... and {len(dead) - 10} more")

    entries = m.get("entry_points", [])
    if entries:
        print(f"\n  Entry points: {', '.join(entries[:10])}")

    # File listing with edges
    nodes = graph_dict.get("nodes", {})
    if nodes:
        print(f"\n  {_c('bold', 'File dependencies:')}")
        for path, node in sorted(nodes.items()):
            imports = node.get("imports", [])
            fi = node.get("fan_in", 0)
            fo = node.get("fan_out", 0)
            marker = ""
            if node.get("is_hub"):
                marker = f" {_c('yellow', '[HUB]')}"
            print(f"    {path}  (in={fi}, out={fo}){marker}")
            for imp in imports[:5]:
                print(f"      -> {imp}")
            if len(imports) > 5:
                print(f"      ... and {len(imports) - 5} more")
    print()


def print_cross_file_finding(cf: dict) -> None:
    """Print a single cross-file finding: source_file:line -> target_file:line."""
    sev = cf.get("severity", "warning")
    sev_color = _SEVERITY_COLOR_NAME.get(sev, "yellow")
    sev_label = sev.upper().ljust(8)

    source = cf.get("source_file", "?")
    target = cf.get("target_file", "?")
    line = cf.get("line", "?")
    target_line = cf.get("target_line")

    location = f"{source}:{line}"
    if target_line:
        location += f" -> {target}:{target_line}"
    else:
        location += f" -> {target}"

    rule = cf.get("rule", "")
    print(f"  {_c(sev_color, sev_label)}  {_c('dim', f'[{rule}]')}  {location}")
    print(f"           {cf.get('message', '')}")
    suggestion = cf.get("suggestion")
    if suggestion:
        print(f"           {_c('green', '-> ' + suggestion)}")
    print()


def print_project_analysis(analysis: ProjectAnalysis) -> None:
    """Full project analysis report."""
    print(f"\n{_c('bold', '=' * 70)}")
    print(f"{_c('bold', '  Project Analysis')}")
    print(f"{_c('bold', '=' * 70)}")

    # Graph summary
    print_graph_summary(analysis.dependency_graph, analysis.graph_metrics)

    # Cross-file findings
    if analysis.cross_file_findings:
        print(f"{_c('bold', f'Cross-file Findings ({len(analysis.cross_file_findings)})')}")
        print("-" * 70)
        for cf in analysis.cross_file_findings:
            print_cross_file_finding(cf.to_dict())
    else:
        print(f"  {_c('green', 'No cross-file issues found.')}\n")

    # Synthesis
    if analysis.synthesis:
        s = analysis.synthesis
        print(f"{_c('bold', 'Project Synthesis')}")
        print("-" * 70)

        summary = s.get("architecture_summary", "")
        if summary:
            print(f"  {summary}\n")

        score = s.get("health_score", 0)
        if score:
            score_color = "green" if score >= 7 else "yellow" if score >= 4 else "red"
            print(f"  Health score: {_c(score_color, f'{score}/10')}\n")

        issues = s.get("architectural_issues", [])
        if issues:
            print(f"  {_c('bold', 'Architectural issues:')}")
            for issue in issues:
                sev = issue.get("severity", "warning")
                sev_color = _SEVERITY_COLOR_NAME.get(sev, "yellow")
                print(f"    {_c(sev_color, sev.upper())}  {issue.get('title', '')}")
                print(f"            {issue.get('description', '')}")
                affected = issue.get("affected_files", [])
                if affected:
                    print(f"            Files: {', '.join(affected)}")
                suggestion = issue.get("suggestion")
                if suggestion:
                    print(f"            {_c('green', '-> ' + suggestion)}")
                print()

        positives = s.get("positive_patterns", [])
        if positives:
            print(f"  {_c('bold', 'Positive patterns:')}")
            for p in positives:
                print(f"    {_c('green', '+')} {p}")
            print()

        recs = s.get("recommendations", [])
        if recs:
            print(f"  {_c('bold', 'Recommendations:')}")
            for r in recs:
                priority = r.get("priority", "medium")
                p_color = {"high": "red", "medium": "yellow", "low": "blue"}.get(priority, "yellow")
                print(f"    {_c(p_color, f'[{priority.upper()}]')}  {r.get('title', '')}")
                desc = r.get("description", "")
                if desc:
                    print(f"            {desc}")
                print()

    # Cost
    print(f"  Files analyzed: {analysis.files_analyzed}")
    if analysis.llm_cost_usd > 0:
        print(f"  LLM cost: ${analysis.llm_cost_usd:.4f}")
    print()


def print_project_json(analysis: ProjectAnalysis) -> None:
    """JSON output for CI/CD."""
    print(json.dumps(analysis.to_dict(), indent=2))


def print_json(report: ScanReport) -> None:
    """Print report as JSON to stdout (pipe-friendly for CI/CD)."""
    print(json.dumps(report.to_dict(), indent=2))


def print_sarif(report: ScanReport) -> None:
    """Print report in SARIF 2.1.0 format for GitHub Code Scanning."""
    sarif = to_sarif(report)
    print(json.dumps(sarif, indent=2))


def to_sarif(report: ScanReport) -> dict:
    """Convert ScanReport to SARIF 2.1.0 format.

    Delegates to sarif.py for the actual conversion.
    """
    from .sarif import to_sarif as _to_sarif

    return _to_sarif(report)


# ─── Fix report rendering ────────────────────────────────────────────

SOURCE_BADGE = {
    FixSource.DETERMINISTIC: ("green", "deterministic"),
    FixSource.LLM: ("yellow", "llm"),
}

STATUS_BADGE = {
    FixStatus.APPLIED: ("green", "applied"),
    FixStatus.SKIPPED: ("yellow", "skipped"),
    FixStatus.FAILED: ("red", "failed"),
    FixStatus.PENDING: ("gray", "pending"),
}


def print_fix_report(report: FixReport, dry_run: bool = True) -> None:
    """Display fixes with diff-style output."""
    mode = "DRY RUN" if dry_run else "APPLIED"
    print(f"\n{_c('bold', f'Fix Report — {mode}')}")
    print("═" * 70)

    if not report.fixes:
        print(f"\n  {_c('green', 'No fixable issues found.')}")
        print()
        return

    for fix in report.fixes:
        src_color, src_label = SOURCE_BADGE.get(fix.source, ("gray", "unknown"))
        stat_color, stat_label = STATUS_BADGE.get(fix.status, ("gray", "unknown"))

        print(
            f"\n  {_c('bold', f'{fix.file}:{fix.line}')} "
            f"{_c('dim', f'[{fix.rule}]')} "
            f"({_c(src_color, src_label)}) "
            f"[{_c(stat_color, stat_label)}]"
        )

        # Show diff
        if fix.original_code:
            for line in fix.original_code.rstrip("\n").splitlines():
                print(f"  {_c('red', '- ' + line)}")
        if fix.fixed_code:
            for line in fix.fixed_code.rstrip("\n").splitlines():
                print(f"  {_c('green', '+ ' + line)}")
        elif fix.original_code:
            print(f"  {_c('green', '+ (removed)')}")

        print(f"  {_c('dim', fix.explanation)}")
        if fix.status == FixStatus.FAILED and getattr(fix, "fail_reason", None):
            print(f"  {_c('red', '^ ' + fix.fail_reason)}")

    # Summary
    print(f"\n{'─' * 70}")
    parts = []
    if report.applied:
        parts.append(_c("green", f"{report.applied} applied"))
    if report.skipped:
        parts.append(_c("yellow", f"{report.skipped} skipped"))
    if report.failed:
        parts.append(_c("red", f"{report.failed} failed"))
    print(f"  Fixes: {', '.join(parts)}  (total: {report.total_fixes})")

    if report.verification:
        v = report.verification
        print(f"\n{_c('bold', 'Verification:')}")
        if v.get("error"):
            print(f"  {_c('red', v['error'])}")
        else:
            print(f"  Issues resolved:    {_c('green', str(v.get('resolved', 0)))}")
            print(f"  Issues remaining:   {v.get('remaining', 0)}")
            new_count = v.get("new_issues", 0)
            if new_count > 0:
                print(f"  {_c('red', f'New issues introduced: {new_count}')}")
                for nf in v.get("new_findings", [])[:5]:
                    print(f"    line {nf.get('line', '?')}: [{nf.get('rule', '?')}] {nf.get('message', '')}")
            else:
                print(f"  New issues:         {_c('green', '0')}")

    if report.llm_cost_usd > 0:
        print(f"  LLM cost: ${report.llm_cost_usd:.4f}")
    print()


def print_fix_json(report: FixReport) -> None:
    """JSON output for CI/CD."""
    print(json.dumps(report.to_dict(), indent=2))


# ─── Explain output (v1.0.0) ────────────────────────────────────────


def print_explanation(explanation: Any) -> None:
    """Print a FileExplanation in beginner-friendly format."""
    print()
    print(_c("bold", "=" * 70))
    print(_c("bold", f"  Dojigiri Explain: {explanation.filepath}"))
    print(_c("bold", "=" * 70))
    print()

    # Summary
    print(_c("bold", "  What is this file?"))
    print(f"  {explanation.summary}")
    print()

    # Structure
    if explanation.structure:
        print(_c("bold", "  Code Structure"))
        print("  " + "-" * 66)
        for section in explanation.structure:
            print(f"\n  {_c('blue', section.title)}")
            print(f"    {section.content}")
            if section.code_snippet:
                print(f"    {_c('gray', section.code_snippet)}")
        print()

    # Patterns
    if explanation.patterns:
        print(_c("bold", "  Design Patterns Detected"))
        print("  " + "-" * 66)
        for section in explanation.patterns:
            print(f"\n  {_c('green', section.title)}")
            print(f"    {section.content}")
        print()

    # Findings explained
    if explanation.findings_explained:
        print(_c("bold", "  Issues Found (Explained)"))
        print("  " + "-" * 66)
        for section in explanation.findings_explained:
            print(f"\n  {_c('yellow', section.title)}")
            print(textwrap.fill(section.content, width=72, initial_indent="    ", subsequent_indent="    "))
            if section.code_snippet:
                print(f"    {_c('gray', section.code_snippet)}")
        print()

    # Learning notes
    if explanation.learning_notes:
        print(_c("bold", "  Things to Learn From This Code"))
        print("  " + "-" * 66)
        for note in explanation.learning_notes:
            print(f"\n  {_c('green', '*')} {note}")
        print()

    print(_c("dim", "  Generated by Dojigiri — offline code tutorial mode"))
    print()


def print_explain_json(explanation: Any) -> None:
    """Print explanation as JSON."""
    data = {
        "filepath": explanation.filepath,
        "language": explanation.language,
        "summary": explanation.summary,
        "structure": [
            {"title": s.title, "content": s.content, "snippet": s.code_snippet} for s in explanation.structure
        ],
        "patterns": [{"title": s.title, "content": s.content} for s in explanation.patterns],
        "findings_explained": [
            {"title": s.title, "content": s.content, "snippet": s.code_snippet} for s in explanation.findings_explained
        ],
        "learning_notes": explanation.learning_notes,
    }
    print(json.dumps(data, indent=2))


# ─── PR review rendering ─────────────────────────────────────────────


def print_pr_review(review: Any) -> None:
    """Print PR review in terminal-friendly format."""
    from .pr_review import PRReview

    assert isinstance(review, PRReview)

    risk_color = {"Low": "green", "Medium": "yellow", "High": "red", "Critical": "red"}.get(review.risk_level, "yellow")

    print()
    print(_c("bold", "=" * 70))
    print(_c("bold", "  Dojigiri Security Review"))
    print(_c("bold", "=" * 70))
    print()
    print(f"  Base ref:    {review.base_ref}")
    print(f"  Risk level:  {_c(risk_color, review.risk_level)}")
    print(f"  Findings:    {review.summary}")
    print()

    if not review.file_reviews:
        print(f"  {_c('green', 'No security findings on changed lines.')}")
        print()
        return

    for fr in review.file_reviews:
        # File header
        counts = []
        if fr.critical_count:
            counts.append(_c("red", f"{fr.critical_count} critical"))
        if fr.warning_count:
            counts.append(_c("yellow", f"{fr.warning_count} warning"))
        if fr.info_count:
            counts.append(_c("blue", f"{fr.info_count} info"))
        summary = ", ".join(counts)

        print(f"  {_c('bold', fr.path)}  [{summary}]")
        print("  " + "-" * 66)

        # Prefer LLM analysis if available
        if fr.llm_analysis:
            for finding in fr.llm_analysis:
                sev = finding.get("severity", "warning")
                sev_color_name = _SEVERITY_COLOR_NAME.get(sev, "yellow")
                sev_label = sev.upper().ljust(8)
                title = finding.get("title", "Finding")
                line_num = finding.get("line", "?")

                print(f"    {_c(sev_color_name, sev_label)}  {_c('bold', title)}  {_c('dim', f'(line {line_num})')}")

                snippet = finding.get("snippet", "")
                if snippet:
                    for snippet_line in snippet.splitlines():
                        print(f"              {_c('gray', snippet_line)}")

                risk = finding.get("risk", "")
                if risk:
                    print(f"              {risk}")

                fix = finding.get("fix", "")
                if fix:
                    print(f"              {_c('green', 'Fix:')}")
                    for fix_line in fix.splitlines():
                        print(f"                {_c('green', fix_line)}")
                print()
        else:
            # Static-only fallback
            for f in fr.findings:
                color, label = SEVERITY_STYLE[f.severity]
                print(f"    {_c(color, label)}  {_c('dim', f'[{f.rule}]')}  line {f.line}")
                print(f"              {f.message}")
                if f.suggestion:
                    print(f"              {_c('green', '-> ' + f.suggestion)}")
                print()

    # Cost
    if review.llm_cost_usd > 0:
        print(f"  LLM cost: ${review.llm_cost_usd:.4f}")
    print()


def print_pr_review_json(review: Any) -> None:
    """Print PR review as JSON."""
    print(json.dumps(review.to_dict(), indent=2))
