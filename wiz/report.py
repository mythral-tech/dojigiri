"""Console formatting — severity colors, findings display, summaries."""

import json
import sys
from collections import Counter
from .config import Finding, FileAnalysis, ScanReport, Severity, Source, Category


def _ensure_utf8():
    """Reconfigure stdout for UTF-8 on Windows if possible."""
    if sys.platform == "win32" and hasattr(sys.stdout, "reconfigure"):
        try:
            sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        except Exception:
            pass  # If reconfigure fails, continue with default encoding


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


def _c(color: str, text: str) -> str:
    """Wrap text in ANSI color."""
    if not sys.stdout.isatty():
        return text
    return f"{COLORS.get(color, '')}{text}{COLORS['reset']}"


def print_finding(f: Finding, show_file: bool = True):
    """Print a single finding."""
    color, label = SEVERITY_STYLE[f.severity]
    src = SOURCE_LABEL.get(f.source, f.source.value)

    location = f"{f.file}:{f.line}" if show_file else f"line {f.line}"
    print(f"  {_c(color, label)}  {_c('dim', f'[{src}]')}  {_c('dim', f'[{f.rule}]')}  {location}")
    print(f"           {f.message}")
    if f.snippet:
        print(f"           {_c('gray', f.snippet)}")
    if f.suggestion:
        print(f"           {_c('green', '→ ' + f.suggestion)}")
    print()


def print_file_analysis(fa: FileAnalysis):
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


def print_scan_summary(report: ScanReport):
    """Print the scan summary."""
    print()
    print(_c("bold", "═" * 70))
    print(_c("bold", f"  Scan Complete — {report.mode.upper()} mode"))
    print(_c("bold", "═" * 70))
    print()
    print(f"  Files scanned:  {report.files_scanned}")
    print(f"  Files skipped:  {report.files_skipped}")
    print()
    print(f"  {_c('red', f'Critical:  {report.critical}')}")
    print(f"  {_c('yellow', f'Warnings:  {report.warnings}')}")
    print(f"  {_c('blue', f'Info:      {report.info}')}")
    print(f"  {'─' * 30}")
    print(f"  Total:     {report.total_findings}")

    # Category breakdown
    cat_counts = Counter()
    for fa in report.file_analyses:
        for f in fa.findings:
            cat_counts[f.category] += 1
    if cat_counts:
        print()
        cat_labels = [
            (Category.BUG, "Bug"), (Category.SECURITY, "Security"),
            (Category.PERFORMANCE, "Performance"), (Category.STYLE, "Style"),
            (Category.DEAD_CODE, "Dead code"),
        ]
        parts = [f"{label}: {cat_counts[cat]}" for cat, label in cat_labels if cat_counts[cat]]
        print(f"  By category:  {' | '.join(parts)}")

    if report.llm_cost_usd > 0:
        print(f"\n  LLM cost:  ${report.llm_cost_usd:.4f}")
    print()


def print_report(report: ScanReport, verbose: bool = False):
    """Print full report — file analyses + summary."""
    # Show files with findings (or all files in verbose mode)
    for fa in report.file_analyses:
        if fa.findings or verbose:
            print_file_analysis(fa)

    print_scan_summary(report)


def print_debug_result(filepath: str, findings: list[Finding], llm_response: str = ""):
    """Print debug command output."""
    print(f"\n{_c('bold', f'Debug: {filepath}')}")
    print("═" * 70)

    if findings:
        print(f"\n{_c('bold', 'Static analysis findings:')}")
        for f in findings:
            print_finding(f, show_file=False)

    if llm_response:
        print(f"\n{_c('bold', 'Claude analysis:')}")
        print(llm_response)
    print()


def print_optimize_result(filepath: str, llm_response: str):
    """Print optimize command output."""
    print(f"\n{_c('bold', f'Optimize: {filepath}')}")
    print("═" * 70)
    print(f"\n{llm_response}")
    print()


def print_cost_estimate(total_lines: int, total_files: int, est_tokens: int, est_cost: float):
    """Print cost estimate for deep scan."""
    print(f"\n{_c('bold', 'Cost Estimate — Deep Scan')}")
    print("─" * 40)
    print(f"  Files to analyze:  {total_files}")
    print(f"  Total lines:       {total_lines:,}")
    print(f"  Est. input tokens: {est_tokens:,}")
    print(f"  Est. output tokens: ~{est_tokens // 4:,}")
    print(f"  {_c('bold', f'Est. cost:           ${est_cost:.4f}')}")
    print("\n  Model: claude-sonnet-4")
    print("  (Actual cost may vary based on findings density)")
    print()


def print_setup_status(api_key_set: bool, anthropic_installed: bool):
    """Print setup check results."""
    print(f"\n{_c('bold', 'wiz — Environment Check')}")
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


def print_json(report: ScanReport):
    """Print report as JSON to stdout (pipe-friendly for CI/CD)."""
    print(json.dumps(report.to_dict(), indent=2))
