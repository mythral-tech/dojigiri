"""Smart prompt builder that uses static analysis findings to focus LLM attention.

Takes static findings and builds targeted micro-queries around specific code
regions, so the LLM reviews only the relevant snippets instead of whole files.
Files with no static findings can skip LLM entirely, saving cost.

Called by: graph/project.py
Calls into: config.py
Data in -> Data out: list[Finding] -> focused prompt string
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional

from .types import Finding


@dataclass
class FocusArea:
    kind: str       # "taint_path", "dead_function", "scope_issue", "smell", "arg_mismatch"
    files: list[str]
    lines: list[int]
    context: str    # detailed description for LLM
    priority: int   # 1 = highest


def build_focus_areas(
    findings: list[Finding],
    taint_findings: Optional[list[Finding]] = None,
    dead_fn_findings: Optional[list[Finding]] = None,
    scope_findings: Optional[list[Finding]] = None,
    smell_findings: Optional[list[Finding]] = None,
) -> list[FocusArea]:
    """Build prioritized focus areas from all static analysis results."""
    areas = []

    # Priority 1: Security / taint findings
    if taint_findings:
        for f in taint_findings:
            areas.append(FocusArea(
                kind="taint_path",
                files=[f.file],
                lines=[f.line],
                context=f"SECURITY: {f.message}. {f.suggestion or ''}",
                priority=1,
            ))

    # Priority 2: Bug findings (arg mismatches, uninitialized vars)
    bug_findings = [f for f in findings if f.rule in ("arg-count-mismatch", "possibly-uninitialized")]
    if scope_findings:
        bug_findings.extend([f for f in scope_findings if f.rule == "possibly-uninitialized"])

    for f in bug_findings:
        areas.append(FocusArea(
            kind="scope_issue" if f.rule == "possibly-uninitialized" else "arg_mismatch",
            files=[f.file],
            lines=[f.line],
            context=f"BUG: {f.message}. {f.suggestion or ''}",
            priority=2,
        ))

    # Priority 3: Dead code
    if dead_fn_findings:
        for f in dead_fn_findings:
            areas.append(FocusArea(
                kind="dead_function",
                files=[f.file],
                lines=[f.line],
                context=f"DEAD CODE: {f.message}. Verify if this is used via dynamic dispatch, decorators, or external entry points.",
                priority=3,
            ))

    # Priority 4: Smells
    if smell_findings:
        for f in smell_findings:
            areas.append(FocusArea(
                kind="smell",
                files=[f.file],
                lines=[f.line],
                context=f"DESIGN: {f.message}. {f.suggestion or ''}",
                priority=4,
            ))

    # Sort by priority
    areas.sort(key=lambda a: a.priority)
    return areas


def build_focused_prompt(focus_areas: list[FocusArea], max_areas: int = 10) -> str:
    """Build a focused LLM prompt from prioritized focus areas.

    Returns empty string if no focus areas — caller should skip LLM.
    """
    if not focus_areas:
        return ""

    areas = focus_areas[:max_areas]

    lines = [
        "Static analysis found these specific concerns. For each one:",
        "1. Verify if the issue is real or a false positive",
        "2. Assess actual severity in context",
        "3. Provide a specific fix if needed",
        "4. Identify any related issues the analyzer missed",
        "",
    ]

    for i, area in enumerate(areas, 1):
        lines.append(f"[{i}] (priority={area.priority}, {area.kind})")
        if area.files:
            lines.append(f"    Files: {', '.join(area.files)}")
        if area.lines:
            lines.append(f"    Lines: {', '.join(str(l) for l in area.lines)}")
        lines.append(f"    {area.context}")
        lines.append("")

    return "\n".join(lines)


# ─── System prompt for focused analysis ──────────────────────────────

FOCUSED_ANALYZE_SYSTEM_PROMPT = """\
You are a senior code reviewer performing targeted verification of static analysis findings.

You receive:
1. Source code of the file
2. Specific findings from static analysis that need human-level verification
3. Optional context files

For each finding, respond with a JSON object:
{{
  "verified_findings": [
    {{
      "original_line": <int>,
      "original_rule": "<rule name>",
      "verdict": "confirmed" | "false_positive" | "needs_context",
      "severity_adjustment": "same" | "higher" | "lower",
      "explanation": "<why this is/isn't a real issue>",
      "fix": "<specific fix if confirmed, or null>",
      "related_issues": ["<any additional issues discovered nearby>"]
    }}
  ],
  "additional_findings": [
    {{
      "line": <int>,
      "severity": "critical" | "warning" | "info",
      "category": "bug" | "security" | "performance" | "style" | "dead_code",
      "rule": "<rule name>",
      "message": "<explanation>",
      "suggestion": "<fix>"
    }}
  ]
}}

Be precise. Only confirm findings you are confident about. Flag false positives clearly.
Return ONLY JSON, no markdown or explanation outside the JSON object."""


# ─── Micro-queries (v1.0.0) ─────────────────────────────────────────

@dataclass
class MicroQuery:
    """A targeted code snippet + question for LLM analysis."""
    snippet: str            # 5-10 lines of code
    question: str           # specific question about this snippet
    finding_rules: list[str]
    priority: int           # 1 = highest
    estimated_tokens: int
    line_start: int = 0
    line_end: int = 0


def build_micro_queries(
    findings: list[Finding],
    content: str,
    semantics=None,
    max_queries: int = 5,
) -> list[MicroQuery]:
    """Build targeted micro-queries from findings — send snippets not whole files.

    Each micro-query contains a 5-10 line snippet centered on a finding,
    plus a specific question. This is 5-10x cheaper than sending the whole file
    and produces more focused results.

    Args:
        findings: Static analysis findings to build queries for.
        content: Full file content.
        semantics: Optional FileSemantics for context.
        max_queries: Maximum number of queries to build.

    Returns:
        List of MicroQuery sorted by priority.
    """
    lines = content.splitlines()
    queries: list[MicroQuery] = []

    # Group findings by line proximity (within 5 lines = same query)
    groups: list[list[Finding]] = []
    sorted_findings = sorted(findings, key=lambda f: (f.severity.value, f.line))

    for f in sorted_findings:
        added = False
        for group in groups:
            if any(abs(f.line - g.line) <= 5 for g in group):
                group.append(f)
                added = True
                break
        if not added:
            groups.append([f])

    # Build a micro-query per group
    priority_map = {
        "critical": 1,
        "warning": 2,
        "info": 3,
    }

    for group in groups:
        if len(queries) >= max_queries:
            break

        # Determine snippet range (centered, 5 lines context each side)
        min_line = min(f.line for f in group)
        max_line = max(f.line for f in group)
        start = max(0, min_line - 6)  # 0-indexed
        end = min(len(lines), max_line + 5)
        snippet = "\n".join(f"{start + i + 1:4d} | {lines[start + i]}" for i in range(end - start))

        rules = list(set(f.rule for f in group))
        messages = "; ".join(set(f.message[:80] for f in group))

        # Build specific question
        question = f"Static analysis flagged: {messages}. "
        if any(f.severity.value == "critical" for f in group):
            question += "Is this a real vulnerability? How should it be fixed?"
        elif any(f.category.value == "security" for f in group):
            question += "Verify if this is exploitable. Suggest a safe alternative."
        elif any(f.category.value == "bug" for f in group):
            question += "Is this actually a bug? What's the correct fix?"
        else:
            question += "Is this a real concern? Suggest improvement if so."

        best_severity = min(f.severity.value for f in group)
        priority = priority_map.get(best_severity, 3)

        est_tokens = len(snippet) // 4 + len(question) // 4 + 200  # overhead

        queries.append(MicroQuery(
            snippet=snippet,
            question=question,
            finding_rules=rules,
            priority=priority,
            estimated_tokens=est_tokens,
            line_start=start + 1,
            line_end=end,
        ))

    queries.sort(key=lambda q: q.priority)
    return queries[:max_queries]
