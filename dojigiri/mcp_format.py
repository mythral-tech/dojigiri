"""AI-friendly plain-text formatter for MCP tool responses.

Transforms dojigiri dataclasses into concise text optimized for LLM consumption.
No ANSI colors, no JSON nesting — just clean, scannable text that fits in
a tool-response context window.

Called by: mcp_server.py
Calls into: config.py, semantic/explain.py
Data in -> Data out: ScanReport -> plain text string
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .semantic.explain import ExplainSection, FileExplanation
    from .types import (
        CrossFileFinding,
        Finding,
        FixReport,
        ProjectAnalysis,
        ScanReport,
    )

from .types import SEVERITY_ORDER, Severity

_MAX_FINDINGS = 50
_MAX_CROSS_FILE = 20
_MAX_FAN_IN_DISPLAY = 5
_MAX_CYCLES_DISPLAY = 5
_MAX_FILE_RANKINGS = 10
_SEVERITY_DISPLAY = [Severity.CRITICAL, Severity.WARNING, Severity.INFO]


# ─── Helpers ──────────────────────────────────────────────────────────


def _finding_line(f: Finding) -> str:
    """Format a single finding as one concise line."""
    src = f.source.value if hasattr(f, "source") else "static"
    line = f"  {f.file}:{f.line} [{src}] [{f.rule}] {f.message}"
    if f.suggestion:
        line += f"\n    -> {f.suggestion}"
    return line


def _cross_finding_line(cf: CrossFileFinding) -> str:
    """Format a cross-file finding with source→target locations."""
    target = f" -> {cf.target_file}:{cf.target_line}" if cf.target_line else f" -> {cf.target_file}"
    line = f"  {cf.source_file}:{cf.line}{target} [{cf.rule}] {cf.message}"
    if cf.suggestion:
        line += f"\n    -> {cf.suggestion}"
    return line


def _format_section(section: ExplainSection) -> str:
    """Format an ExplainSection with optional code snippet."""
    parts = [f"  {section.title}: {section.content}"]
    if section.code_snippet:
        for line in section.code_snippet.splitlines()[:5]:
            parts.append(f"    | {line}")
    return "\n".join(parts)


def _normalize_graph_nodes(nodes_raw: dict | list) -> list[dict]:
    """Normalize dependency graph nodes to a flat list of dicts.

    DepGraph.to_dict() returns {path: {language, fan_in, ...}}.
    We normalize to [{path, language, fan_in, ...}] for uniform access.
    """
    if isinstance(nodes_raw, dict):
        return [{"path": path, **attrs} for path, attrs in nodes_raw.items()]
    return list(nodes_raw)


# ─── Scan report ──────────────────────────────────────────────────────


def format_scan_report(report: ScanReport, max_findings: int = _MAX_FINDINGS) -> str:
    """Format a ScanReport into concise AI-readable text."""
    parts: list[str] = []
    parts.append(f"Scan: {report.root} ({report.files_scanned} files, {report.mode} mode)")
    parts.append(f"Findings: {report.critical} critical, {report.warnings} warning, {report.info} info")

    if report.total_findings == 0:
        parts.append("\nNo issues found.")
        return "\n".join(parts)

    all_findings: list[Finding] = []
    for fa in report.file_analyses:
        all_findings.extend(fa.findings)
    all_findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 9))

    by_severity: dict[Severity, list[Finding]] = {}
    for f in all_findings:
        by_severity.setdefault(f.severity, []).append(f)

    count = 0
    for severity in _SEVERITY_DISPLAY:
        findings = by_severity.get(severity, [])
        if not findings:
            continue
        parts.append(f"\n{severity.value.upper()}:")
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
    filepath: str,
    language: str,
    lines: int,
    findings: list[Finding],
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

    findings_sorted = sorted(findings, key=lambda f: SEVERITY_ORDER.get(f.severity, 9))
    for f in findings_sorted[:_MAX_FINDINGS]:
        parts.append(_finding_line(f))

    if len(findings) > _MAX_FINDINGS:
        parts.append(f"\n... and {len(findings) - _MAX_FINDINGS} more")

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
        parts.append(f"\nFix {i}: {fix.file}:{fix.line} [{fix.rule}] ({fix.source.value})")
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


def format_explanation(explanation: FileExplanation) -> str:
    """Format a FileExplanation into concise text."""
    parts: list[str] = []
    parts.append(f"Explanation: {explanation.filepath} ({explanation.language})")
    parts.append(f"\nSummary: {explanation.summary}")

    for label, sections in [
        ("Structure", explanation.structure),
        ("Patterns", explanation.patterns),
        ("Findings", explanation.findings_explained),
    ]:
        if sections:
            parts.append(f"\n{label}:")
            for section in sections:
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

    if analysis.graph_metrics:
        parts.append("\nMetrics:")
        for key, value in analysis.graph_metrics.items():
            parts.append(f"  {key}: {value}")

    dep = analysis.dependency_graph
    if dep:
        nodes = _normalize_graph_nodes(dep.get("nodes", {}))
        circular = dep.get("circular_deps", [])

        parts.append(f"\nDependency graph: {len(nodes)} modules")

        if circular:
            parts.append(f"Circular dependencies: {len(circular)}")
            for cycle in circular[:_MAX_CYCLES_DISPLAY]:
                parts.append(f"  {' -> '.join(cycle)}")

        if nodes:
            by_fan_in = sorted(nodes, key=lambda n: n.get("fan_in", 0), reverse=True)
            top = [n for n in by_fan_in[:_MAX_FAN_IN_DISPLAY] if n.get("fan_in", 0) > 0]
            if top:
                parts.append("Most depended-on:")
                for n in top:
                    parts.append(f"  {n['path']} (fan_in={n['fan_in']})")

    total_findings = sum(len(fa.findings) for fa in analysis.per_file_findings)
    if total_findings:
        parts.append(f"\nPer-file findings: {total_findings} total")
        ranked = sorted(analysis.per_file_findings, key=lambda fa: len(fa.findings), reverse=True)
        for fa in ranked[:_MAX_FILE_RANKINGS]:
            if fa.findings:
                parts.append(f"  {fa.path}: {len(fa.findings)} findings")

    if analysis.cross_file_findings:
        parts.append(f"\nCross-file findings ({len(analysis.cross_file_findings)}):")
        for cf in analysis.cross_file_findings[:_MAX_CROSS_FILE]:
            parts.append(_cross_finding_line(cf))
        overflow = len(analysis.cross_file_findings) - _MAX_CROSS_FILE
        if overflow > 0:
            parts.append(f"  ... and {overflow} more")

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
