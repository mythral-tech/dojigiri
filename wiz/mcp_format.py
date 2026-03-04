"""AI-friendly output formatting for MCP tool responses.

Transforms wiz dataclasses into concise text optimized for LLM consumption.
No ANSI colors, no JSON nesting — just clean, scannable text.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .config import (
        ScanReport, Finding, FixReport, Fix,
        ProjectAnalysis, CrossFileFinding,
    )
    from .semantic.explain import FileExplanation, ExplainSection

from .config import Severity


# ─── Helpers ──────────────────────────────────────────────────────────

_SEVERITY_ORDER = {Severity.CRITICAL: 0, Severity.WARNING: 1, Severity.INFO: 2}


def _severity_label(s: Severity) -> str:
    return s.value.upper()


def _finding_line(f: Finding) -> str:
    """Format a single finding as one line."""
    line = f"  {f.file}:{f.line} [{f.rule}] {f.message}"
    if f.suggestion:
        line += f"\n    -> {f.suggestion}"
    return line


def _cross_finding_line(cf: CrossFileFinding) -> str:
    """Format a cross-file finding."""
    target = f" -> {cf.target_file}:{cf.target_line}" if cf.target_line else f" -> {cf.target_file}"
    line = f"  {cf.source_file}:{cf.line}{target} [{cf.rule}] {cf.message}"
    if cf.suggestion:
        line += f"\n    -> {cf.suggestion}"
    return line


# ─── Scan report ──────────────────────────────────────────────────────

def format_scan_report(report: ScanReport, max_findings: int = 50) -> str:
    """Format a ScanReport into concise AI-readable text."""
    parts: list[str] = []

    parts.append(f"Scan: {report.root} ({report.files_scanned} files, {report.mode} mode)")
    parts.append(f"Findings: {report.critical} critical, {report.warnings} warning, {report.info} info")

    if report.total_findings == 0:
        parts.append("\nNo issues found.")
        return "\n".join(parts)

    # Collect all findings, sorted by severity
    all_findings: list[Finding] = []
    for fa in report.file_analyses:
        all_findings.extend(fa.findings)
    all_findings.sort(key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))

    # Group by severity
    by_severity: dict[Severity, list[Finding]] = {}
    for f in all_findings:
        by_severity.setdefault(f.severity, []).append(f)

    count = 0
    for severity in [Severity.CRITICAL, Severity.WARNING, Severity.INFO]:
        findings = by_severity.get(severity, [])
        if not findings:
            continue
        parts.append(f"\n{_severity_label(severity)}:")
        for f in findings:
            if count >= max_findings:
                remaining = len(all_findings) - max_findings
                parts.append(f"\n... and {remaining} more (use min_severity to filter)")
                return "\n".join(parts)
            parts.append(_finding_line(f))
            count += 1

    return "\n".join(parts)


# ─── Single file findings ────────────────────────────────────────────

def format_file_findings(
    filepath: str, language: str, lines: int, findings: list[Finding],
) -> str:
    """Format findings for a single file scan."""
    parts: list[str] = []
    parts.append(f"File: {filepath} ({language}, {lines} lines)")

    if not findings:
        parts.append("No issues found.")
        return "\n".join(parts)

    critical = sum(1 for f in findings if f.severity == Severity.CRITICAL)
    warnings = sum(1 for f in findings if f.severity == Severity.WARNING)
    info = sum(1 for f in findings if f.severity == Severity.INFO)
    parts.append(f"Findings: {critical} critical, {warnings} warning, {info} info")

    findings_sorted = sorted(findings, key=lambda f: _SEVERITY_ORDER.get(f.severity, 9))
    for f in findings_sorted[:50]:
        parts.append(_finding_line(f))

    if len(findings) > 50:
        parts.append(f"\n... and {len(findings) - 50} more")

    return "\n".join(parts)


# ─── Fix report ──────────────────────────────────────────────────────

def format_fix_report(report: FixReport) -> str:
    """Format a FixReport showing before/after for each fix."""
    parts: list[str] = []
    parts.append(f"Fixes for {report.root} (dry run):")

    if not report.fixes:
        parts.append("No fixes available.")
        return "\n".join(parts)

    for i, fix in enumerate(report.fixes, 1):
        source = f" ({fix.source.value})" if hasattr(fix, "source") else ""
        parts.append(f"\nFix {i}: {fix.file}:{fix.line} [{fix.rule}]{source}")
        # Show diff-style before/after
        for old_line in fix.original_code.splitlines():
            parts.append(f"  - {old_line}")
        for new_line in fix.fixed_code.splitlines():
            parts.append(f"  + {new_line}")
        if fix.explanation:
            parts.append(f"  Note: {fix.explanation}")

    parts.append(f"\nSummary: {len(report.fixes)} fixes available")
    if report.verification:
        v = report.verification
        parts.append(
            f"Verification: {v.get('resolved', 0)} resolved, "
            f"{v.get('remaining', 0)} remaining, "
            f"{v.get('new_issues', 0)} new"
        )

    return "\n".join(parts)


# ─── Explanation ─────────────────────────────────────────────────────

def _format_section(section: ExplainSection) -> str:
    """Format an ExplainSection."""
    parts = [f"  {section.title}: {section.content}"]
    if section.code_snippet:
        for line in section.code_snippet.splitlines()[:5]:
            parts.append(f"    | {line}")
    return "\n".join(parts)


def format_explanation(explanation: FileExplanation) -> str:
    """Format a FileExplanation into concise text."""
    parts: list[str] = []
    parts.append(f"Explanation: {explanation.filepath} ({explanation.language})")
    parts.append(f"\nSummary: {explanation.summary}")

    if explanation.structure:
        parts.append("\nStructure:")
        for section in explanation.structure:
            parts.append(_format_section(section))

    if explanation.patterns:
        parts.append("\nPatterns:")
        for section in explanation.patterns:
            parts.append(_format_section(section))

    if explanation.findings_explained:
        parts.append("\nFindings:")
        for section in explanation.findings_explained:
            parts.append(_format_section(section))

    if explanation.learning_notes:
        parts.append("\nLearning notes:")
        for note in explanation.learning_notes:
            parts.append(f"  - {note}")

    return "\n".join(parts)


# ─── Project analysis ────────────────────────────────────────────────

def format_project_analysis(analysis: ProjectAnalysis) -> str:
    """Format a ProjectAnalysis into concise text."""
    parts: list[str] = []
    parts.append(f"Project: {analysis.root} ({analysis.files_analyzed} files)")

    # Graph metrics
    metrics = analysis.graph_metrics
    if metrics:
        parts.append("\nMetrics:")
        for key, value in metrics.items():
            parts.append(f"  {key}: {value}")

    # Dependency graph summary
    dep = analysis.dependency_graph
    if dep:
        nodes_raw = dep.get("nodes", {})
        circular = dep.get("circular_deps", [])
        # nodes can be dict[str, dict] (real) or list[dict] (legacy/mock)
        if isinstance(nodes_raw, dict):
            node_list = [{"path": p, **v} if isinstance(v, dict) else {"path": p}
                         for p, v in nodes_raw.items()]
        else:
            node_list = nodes_raw if isinstance(nodes_raw, list) else []
        parts.append(f"\nDependency graph: {len(node_list)} modules")
        if circular:
            parts.append(f"Circular dependencies: {len(circular)}")
            for cycle in circular[:5]:
                parts.append(f"  {' -> '.join(cycle)}")
        # Show high fan-in nodes (most depended on)
        if node_list:
            sorted_nodes = sorted(node_list, key=lambda n: n.get("fan_in", 0) if isinstance(n, dict) else 0, reverse=True)
            top = sorted_nodes[:5]
            if any((n.get("fan_in", 0) if isinstance(n, dict) else 0) > 0 for n in top):
                parts.append("Most depended-on:")
                for n in top:
                    fan_in = n.get("fan_in", 0) if isinstance(n, dict) else 0
                    path = n.get("path", "?") if isinstance(n, dict) else str(n)
                    if fan_in > 0:
                        parts.append(f"  {path} (fan_in={fan_in})")

    # Per-file findings summary
    total_findings = sum(len(fa.findings) for fa in analysis.per_file_findings)
    if total_findings:
        parts.append(f"\nPer-file findings: {total_findings} total")
        # Show files with most findings
        ranked = sorted(analysis.per_file_findings, key=lambda fa: len(fa.findings), reverse=True)
        for fa in ranked[:10]:
            if fa.findings:
                parts.append(f"  {fa.path}: {len(fa.findings)} findings")

    # Cross-file findings
    if analysis.cross_file_findings:
        parts.append(f"\nCross-file findings ({len(analysis.cross_file_findings)}):")
        for cf in analysis.cross_file_findings[:20]:
            parts.append(_cross_finding_line(cf))
        if len(analysis.cross_file_findings) > 20:
            parts.append(f"  ... and {len(analysis.cross_file_findings) - 20} more")

    # Synthesis (LLM summary, if present)
    if analysis.synthesis:
        parts.append("\nSynthesis:")
        for key, value in analysis.synthesis.items():
            if isinstance(value, str):
                parts.append(f"  {key}: {value}")
            elif isinstance(value, list):
                parts.append(f"  {key}:")
                for item in value[:10]:
                    parts.append(f"    - {item}")

    return "\n".join(parts)
