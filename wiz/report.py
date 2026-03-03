"""Console formatting — severity colors, findings display, summaries."""

import json
import sys
import textwrap
from collections import Counter
from .config import (
    Finding, FileAnalysis, ScanReport, Severity, Source, Category,
    ProjectAnalysis, FixReport, FixSource, FixStatus,
)


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


CONFIDENCE_BADGE = {
    "high": ("green", "HIGH"),
    "medium": ("yellow", "MED"),
    "low": ("gray", "LOW"),
}


def _print_debug_finding(f: dict, index: int):
    """Render a single structured debug/optimize finding."""
    severity = f.get("severity", "info")
    sev_color = {"critical": "red", "warning": "yellow", "info": "blue"}.get(severity, "blue")
    sev_label = severity.upper().ljust(8)

    confidence = f.get("confidence", "medium")
    conf_color, conf_label = CONFIDENCE_BADGE.get(confidence, ("gray", "???"))

    title = f.get("title", "Finding")
    line = f.get("line", "?")
    end_line = f.get("end_line")
    category = f.get("category", "")
    line_range = f"line {line}" + (f"-{end_line}" if end_line else "")

    print(f"  {_c(sev_color, sev_label)} {_c(conf_color, f'[{conf_label}]')}  "
          f"{_c('bold', title)}  {_c('dim', f'({line_range}, {category})')}")

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


def print_debug_result(filepath: str, static_findings: list[Finding],
                       llm_result: "Optional[dict]" = None):
    """Print debug command output.

    llm_result can be:
    - dict with 'findings' key → structured output
    - dict with 'raw_markdown' key → raw LLM output (fallback)
    - None → static findings only
    """
    print(f"\n{_c('bold', f'Debug: {filepath}')}")
    print("═" * 70)

    if static_findings:
        print(f"\n{_c('bold', 'Static analysis findings:')}")
        for f in static_findings:
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
        print(f"\n{_c('bold', 'Summary:')} {summary}")

    if findings:
        print(f"\n{_c('bold', f'Claude found {len(findings)} issue(s):')}")
        for i, f in enumerate(findings, 1):
            _print_debug_finding(f, i)

    if quick_wins:
        print(f"{_c('bold', 'Quick wins:')}")
        for qw in quick_wins:
            print(f"  {_c('green', '→')} {qw}")

    if not findings and not quick_wins:
        print(f"\n  {_c('green', 'No additional issues found by Claude.')}")
    print()


def print_optimize_result(filepath: str, static_findings: list[Finding],
                          llm_result: "Optional[dict]" = None):
    """Print optimize command output.

    Same structured/raw_markdown/None handling as debug.
    """
    print(f"\n{_c('bold', f'Optimize: {filepath}')}")
    print("═" * 70)

    if static_findings:
        perf_findings = [f for f in static_findings
                         if f.category in (Category.PERFORMANCE, Category.STYLE)]
        if perf_findings:
            print(f"\n{_c('bold', 'Static analysis (perf-relevant):')}")
            for f in perf_findings:
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
        print(f"\n{_c('bold', 'Assessment:')} {summary}")

    if findings:
        print(f"\n{_c('bold', f'Found {len(findings)} optimization(s):')}")
        for i, f in enumerate(findings, 1):
            _print_debug_finding(f, i)

    if quick_wins:
        print(f"{_c('bold', 'Quick wins:')}")
        for qw in quick_wins:
            print(f"  {_c('green', '→')} {qw}")

    if not findings and not quick_wins:
        print(f"\n  {_c('green', 'Code is well-optimized.')}")
    print()


def print_analysis_json(filepath: str, static_findings: list[Finding],
                        llm_result: "Optional[dict]", tracker=None):
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


# ─── Project analysis rendering ──────────────────────────────────────

def print_graph_summary(graph_dict: dict, metrics_dict: dict):
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


def print_cross_file_finding(cf: dict):
    """Print a single cross-file finding: source_file:line -> target_file:line."""
    sev = cf.get("severity", "warning")
    sev_color = {"critical": "red", "warning": "yellow", "info": "blue"}.get(sev, "yellow")
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


def print_project_analysis(analysis: ProjectAnalysis):
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
                sev_color = {"critical": "red", "warning": "yellow", "info": "blue"}.get(sev, "yellow")
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


def print_project_json(analysis: ProjectAnalysis):
    """JSON output for CI/CD."""
    print(json.dumps(analysis.to_dict(), indent=2))


def print_json(report: ScanReport):
    """Print report as JSON to stdout (pipe-friendly for CI/CD)."""
    print(json.dumps(report.to_dict(), indent=2))


def print_sarif(report: ScanReport):
    """Print report in SARIF 2.1.0 format for GitHub Code Scanning."""
    sarif = to_sarif(report)
    print(json.dumps(sarif, indent=2))


def to_sarif(report: ScanReport) -> dict:
    """Convert ScanReport to SARIF 2.1.0 format.
    
    SARIF (Static Analysis Results Interchange Format) is the standard format
    for GitHub Code Scanning and other result management systems.
    """
    # Map our severity to SARIF levels
    severity_to_level = {
        Severity.CRITICAL: "error",
        Severity.WARNING: "warning",
        Severity.INFO: "note",
    }
    
    # Collect unique rules from all findings
    rules_map = {}
    for fa in report.file_analyses:
        for f in fa.findings:
            if f.rule not in rules_map:
                rules_map[f.rule] = {
                    "id": f.rule,
                    "name": f.message.split(" ")[0],  # First word as short name
                    "shortDescription": {
                        "text": f.message
                    },
                    "fullDescription": {
                        "text": f.message
                    },
                    "defaultConfiguration": {
                        "level": severity_to_level[f.severity]
                    },
                    "properties": {
                        "category": f.category.value,
                        "source": f.source.value,
                    }
                }
    
    # Convert findings to SARIF results
    results = []
    for fa in report.file_analyses:
        for f in fa.findings:
            # Create partial fingerprint for deduplication across runs
            # Use file + rule + line as fingerprint
            fingerprint = f"{f.file}:{f.rule}:{f.line}"
            
            result = {
                "ruleId": f.rule,
                "level": severity_to_level[f.severity],
                "message": {
                    "text": f.message
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file,
                                "uriBaseId": "%SRCROOT%"
                            },
                            "region": {
                                "startLine": f.line,
                                "startColumn": 1
                            }
                        }
                    }
                ],
                "partialFingerprints": {
                    "primaryLocationLineHash": fingerprint
                }
            }
            
            # Add snippet if available (redact secrets)
            snippet = f.to_dict()["snippet"]
            if snippet:
                result["locations"][0]["physicalLocation"]["region"]["snippet"] = {
                    "text": snippet
                }
            
            # Add suggestion as fix if available
            if f.suggestion:
                result["fixes"] = [
                    {
                        "description": {
                            "text": f.suggestion
                        }
                    }
                ]
            
            # Add confidence property if available (LLM findings)
            if f.confidence:
                result["properties"] = {
                    "confidence": f.confidence.value
                }
            
            results.append(result)
    
    # Build SARIF document
    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Wiz",
                        "informationUri": "https://github.com/Inklling/Genesis",
                        "semanticVersion": "1.0.0",
                        "rules": list(rules_map.values())
                    }
                },
                "results": results,
                "properties": {
                    "mode": report.mode,
                    "filesScanned": report.files_scanned,
                    "filesSkipped": report.files_skipped
                }
            }
        ]
    }
    
    return sarif


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


def print_fix_report(report: FixReport, dry_run: bool = True):
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

        print(f"\n  {_c('bold', f'{fix.file}:{fix.line}')} "
              f"{_c('dim', f'[{fix.rule}]')} "
              f"({_c(src_color, src_label)}) "
              f"[{_c(stat_color, stat_label)}]")

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


def print_fix_json(report: FixReport):
    """JSON output for CI/CD."""
    print(json.dumps(report.to_dict(), indent=2))


# ─── Explain output (v1.0.0) ────────────────────────────────────────

def print_explanation(explanation):
    """Print a FileExplanation in beginner-friendly format."""
    print()
    print(_c("bold", "=" * 70))
    print(_c("bold", f"  Wiz Explain: {explanation.filepath}"))
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
            print(textwrap.fill(section.content, width=72,
                                initial_indent="    ", subsequent_indent="    "))
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

    print(_c("dim", "  Generated by Wiz — offline code tutorial mode"))
    print()


def print_explain_json(explanation):
    """Print explanation as JSON."""
    data = {
        "filepath": explanation.filepath,
        "language": explanation.language,
        "summary": explanation.summary,
        "structure": [
            {"title": s.title, "content": s.content, "snippet": s.code_snippet}
            for s in explanation.structure
        ],
        "patterns": [
            {"title": s.title, "content": s.content}
            for s in explanation.patterns
        ],
        "findings_explained": [
            {"title": s.title, "content": s.content, "snippet": s.code_snippet}
            for s in explanation.findings_explained
        ],
        "learning_notes": explanation.learning_notes,
    }
    print(json.dumps(data, indent=2))
