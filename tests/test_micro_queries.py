"""Tests for micro-query features in dojigiri.llm_focus."""

import pytest

from dojigiri.config import Finding, Severity, Category, Source
from dojigiri.llm_focus import build_micro_queries, MicroQuery


def _make_finding(
    line: int,
    rule: str = "test-rule",
    message: str = "Test finding",
    severity: Severity = Severity.WARNING,
    category: Category = Category.BUG,
) -> Finding:
    """Helper to create a Finding with sensible defaults."""
    return Finding(
        file="test.py",
        line=line,
        severity=severity,
        category=category,
        source=Source.AST,
        rule=rule,
        message=message,
    )


def _make_content(num_lines: int = 50) -> str:
    """Generate a Python file with numbered lines."""
    return "\n".join(f"line_{i} = {i}" for i in range(1, num_lines + 1))


# ---------------------------------------------------------------------------
# QUERY CONSTRUCTION
# ---------------------------------------------------------------------------

class TestQueryConstruction:
    """Tests for basic micro-query building."""

    def test_single_finding_produces_one_query(self):
        """A single finding produces exactly one MicroQuery."""
        content = _make_content(20)
        findings = [_make_finding(line=10)]
        queries = build_micro_queries(findings, content)

        assert len(queries) == 1
        assert isinstance(queries[0], MicroQuery)
        assert queries[0].snippet  # non-empty snippet
        assert queries[0].question  # non-empty question

    def test_no_findings_produces_empty_list(self):
        """No findings yields an empty query list."""
        content = _make_content(20)
        queries = build_micro_queries([], content)

        assert queries == []

    def test_findings_grouped_by_proximity(self):
        """Findings within 5 lines of each other are grouped into one query."""
        content = _make_content(50)
        findings = [
            _make_finding(line=10, rule="rule-a", message="Issue A"),
            _make_finding(line=12, rule="rule-b", message="Issue B"),
        ]
        queries = build_micro_queries(findings, content)

        # Lines 10 and 12 are within 5 lines -> grouped into one query
        assert len(queries) == 1
        assert "rule-a" in queries[0].finding_rules or "rule-b" in queries[0].finding_rules

    def test_snippet_includes_context_lines(self):
        """The snippet includes 5 lines of context before and after the finding."""
        content = _make_content(30)
        findings = [_make_finding(line=15)]
        queries = build_micro_queries(findings, content)

        assert len(queries) == 1
        # line_start should be around 15-5=10, line_end around 15+5=20
        assert queries[0].line_start <= 10
        assert queries[0].line_end >= 19

    def test_query_contains_finding_message(self):
        """The query question includes the finding's message text."""
        content = _make_content(20)
        findings = [_make_finding(line=10, message="Possible null dereference on 'x'")]
        queries = build_micro_queries(findings, content)

        assert len(queries) == 1
        assert "Possible null dereference" in queries[0].question


# ---------------------------------------------------------------------------
# PRIORITIZATION
# ---------------------------------------------------------------------------

class TestPrioritization:
    """Tests for query priority assignment."""

    def test_critical_findings_priority_one(self):
        """Critical severity findings get priority 1."""
        content = _make_content(20)
        findings = [_make_finding(line=10, severity=Severity.CRITICAL)]
        queries = build_micro_queries(findings, content)

        assert len(queries) == 1
        assert queries[0].priority == 1

    def test_security_findings_priority_one(self):
        """Security category findings with critical severity get priority 1."""
        content = _make_content(20)
        findings = [_make_finding(
            line=10, severity=Severity.CRITICAL, category=Category.SECURITY,
        )]
        queries = build_micro_queries(findings, content)

        assert len(queries) == 1
        assert queries[0].priority == 1

    def test_warning_findings_priority_two(self):
        """Warning severity findings (non-critical) get priority 2."""
        content = _make_content(20)
        findings = [_make_finding(line=10, severity=Severity.WARNING)]
        queries = build_micro_queries(findings, content)

        assert len(queries) == 1
        assert queries[0].priority == 2

    def test_info_findings_priority_three(self):
        """Info severity findings get priority 3."""
        content = _make_content(20)
        findings = [_make_finding(line=10, severity=Severity.INFO)]
        queries = build_micro_queries(findings, content)

        assert len(queries) == 1
        assert queries[0].priority == 3


# ---------------------------------------------------------------------------
# COST CAPPING
# ---------------------------------------------------------------------------

class TestCostCapping:
    """Tests for max_queries limiting and token estimation."""

    def test_max_queries_limits_output(self):
        """max_queries=2 returns at most 2 queries even with more findings."""
        content = _make_content(100)
        # Create findings spread far apart so they form separate groups
        findings = [
            _make_finding(line=10, rule="r1", message="A"),
            _make_finding(line=30, rule="r2", message="B"),
            _make_finding(line=50, rule="r3", message="C"),
            _make_finding(line=70, rule="r4", message="D"),
        ]
        queries = build_micro_queries(findings, content, max_queries=2)

        assert len(queries) <= 2

    def test_max_queries_zero_returns_empty(self):
        """max_queries=0 returns an empty list."""
        content = _make_content(20)
        findings = [_make_finding(line=10)]
        queries = build_micro_queries(findings, content, max_queries=0)

        assert queries == []

    def test_estimated_tokens_calculated(self):
        """Each MicroQuery has a positive estimated_tokens value."""
        content = _make_content(30)
        findings = [_make_finding(line=15)]
        queries = build_micro_queries(findings, content)

        assert len(queries) == 1
        assert queries[0].estimated_tokens > 0


# ---------------------------------------------------------------------------
# EDGE CASES
# ---------------------------------------------------------------------------

class TestEdgeCases:
    """Edge cases in micro-query building."""

    def test_finding_at_line_one(self):
        """A finding at line 1 produces a snippet starting at line 1."""
        content = _make_content(20)
        findings = [_make_finding(line=1)]
        queries = build_micro_queries(findings, content)

        assert len(queries) == 1
        assert queries[0].line_start == 1

    def test_finding_at_last_line(self):
        """A finding at the last line produces a snippet ending at or near the last line."""
        num_lines = 20
        content = _make_content(num_lines)
        findings = [_make_finding(line=num_lines)]
        queries = build_micro_queries(findings, content)

        assert len(queries) == 1
        assert queries[0].line_end <= num_lines

    def test_very_long_line_in_snippet(self):
        """Snippets are constructed even when lines are very long."""
        lines = ["x = 1"] * 9 + ["y = " + "A" * 5000] + ["z = 3"] * 10
        content = "\n".join(lines)
        findings = [_make_finding(line=10)]
        queries = build_micro_queries(findings, content)

        # Should not crash, and should produce a query
        assert len(queries) == 1
        assert queries[0].snippet  # non-empty
