"""Smart prompt builder that uses static analysis findings to focus LLM attention.

Takes static findings and builds targeted micro-queries around specific code
regions, so the LLM reviews only the relevant snippets instead of whole files.
Files with no static findings can skip LLM entirely, saving cost.

Called by: llm.py
Calls into: nothing
Data in -> Data out: list[Finding] + code -> list[MicroQuery]
"""

from __future__ import annotations

from dataclasses import dataclass

from .types import Finding

# Import sanitizer from llm module (lazy to avoid circular import)
_sanitize_for_prompt = None


def _get_sanitizer():
    global _sanitize_for_prompt
    if _sanitize_for_prompt is None:
        from .llm import _sanitize_for_prompt as _sfp

        _sanitize_for_prompt = _sfp
    return _sanitize_for_prompt


# ─── Micro-queries (v1.0.0) ─────────────────────────────────────────


@dataclass
class MicroQuery:
    """A targeted code snippet + question for LLM analysis."""

    snippet: str  # 5-10 lines of code
    question: str  # specific question about this snippet
    finding_rules: list[str]
    priority: int  # 1 = highest
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

        sanitize = _get_sanitizer()
        rules = list(set(f.rule for f in group))
        messages = "; ".join(set(sanitize(f.message, max_length=80) for f in group))

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

        queries.append(
            MicroQuery(
                snippet=snippet,
                question=question,
                finding_rules=rules,
                priority=priority,
                estimated_tokens=est_tokens,
                line_start=start + 1,
                line_end=end,
            )
        )

    queries.sort(key=lambda q: q.priority)
    return queries[:max_queries]
