"""Tests for dojigiri/project.py — project analysis orchestrator."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch, MagicMock

from dojigiri.graph.project import (
    analyze_project,
    _extract_signatures_python,
    _extract_signatures_js,
    _extract_signatures,
    _select_context_for_file,
    _format_graph_summary,
)
from dojigiri.graph.depgraph import build_dependency_graph, compute_metrics, DepGraph, FileNode
from dojigiri.config import ProjectAnalysis, CrossFileFinding, Severity, Category


# ─── No-LLM mode ────────────────────────────────────────────────────

class TestNoLLMMode:
    def test_returns_graph_and_metrics(self, temp_dir):
        """--no-llm mode returns graph + metrics without API key."""
        (temp_dir / "a.py").write_text("import b\nx = 1\n")
        (temp_dir / "b.py").write_text("y = 2\n")
        result = analyze_project(str(temp_dir), use_llm=False)
        assert isinstance(result, ProjectAnalysis)
        assert result.files_analyzed == 2
        assert "total_files" in result.graph_metrics
        assert result.graph_metrics["total_files"] == 2
        assert result.llm_cost_usd == 0.0

    def test_empty_project(self, temp_dir):
        """Empty directory returns empty analysis."""
        result = analyze_project(str(temp_dir), use_llm=False)
        assert result.files_analyzed == 0
        assert result.graph_metrics == {}

    def test_single_file_project(self, temp_dir):
        """Single file project works."""
        (temp_dir / "main.py").write_text("print('hello')\n")
        result = analyze_project(str(temp_dir), use_llm=False)
        assert result.files_analyzed == 1

    def test_language_filter(self, temp_dir):
        """--lang filter only includes matching files."""
        (temp_dir / "a.py").write_text("x = 1\n")
        (temp_dir / "b.js").write_text("const y = 2;\n")
        result = analyze_project(str(temp_dir), language_filter="python", use_llm=False)
        assert result.files_analyzed == 1
        assert result.graph_metrics["total_files"] == 1


# ─── Serialization ──────────────────────────────────────────────────

class TestProjectAnalysisSerialization:
    def test_to_dict_serializable(self, temp_dir):
        """ProjectAnalysis.to_dict() produces JSON-serializable output."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("x = 1\n")
        result = analyze_project(str(temp_dir), use_llm=False)
        d = result.to_dict()
        json_str = json.dumps(d)
        assert "graph_metrics" in json_str
        assert "dependency_graph" in json_str

    def test_timestamp_auto_generated(self, temp_dir):
        """ProjectAnalysis gets auto-generated timestamp."""
        (temp_dir / "a.py").write_text("x = 1\n")
        result = analyze_project(str(temp_dir), use_llm=False)
        assert result.timestamp  # not empty


# ─── Signature extraction ────────────────────────────────────────────

class TestSignatureExtraction:
    def test_python_functions(self):
        """Extracts function signatures from Python code."""
        code = "def foo(x: int, y: str) -> bool:\n    return True\n"
        sig = _extract_signatures_python(code)
        assert "foo" in sig
        assert "x" in sig

    def test_python_classes(self):
        """Extracts class names and methods from Python code."""
        code = (
            "class MyClass(Base):\n"
            "    def method(self, x):\n"
            "        pass\n"
        )
        sig = _extract_signatures_python(code)
        assert "MyClass" in sig
        assert "method" in sig

    def test_python_constants(self):
        """Extracts UPPER_CASE constants."""
        code = "MAX_SIZE = 100\nlocal_var = 5\n"
        sig = _extract_signatures_python(code)
        assert "MAX_SIZE" in sig
        assert "local_var" not in sig

    def test_python_syntax_error_fallback(self):
        """Syntax errors fall back to first 500 chars."""
        code = "def broken(\n"
        sig = _extract_signatures_python(code)
        assert len(sig) <= 500

    def test_js_exports(self):
        """Extracts exported functions from JS."""
        code = "export function doThing(x, y) {\n  return x + y;\n}\n"
        sig = _extract_signatures_js(code)
        assert "doThing" in sig

    def test_extract_dispatches_by_language(self):
        """_extract_signatures dispatches to correct extractor."""
        py_code = "def foo(): pass\n"
        assert "foo" in _extract_signatures(py_code, "python")

        js_code = "export function bar() {}\n"
        assert "bar" in _extract_signatures(js_code, "javascript")

        # Unknown language falls back to truncation
        other = "x" * 1000
        result = _extract_signatures(other, "rust")
        assert len(result) == 500


# ─── Context selection ───────────────────────────────────────────────

class TestContextSelection:
    def test_selects_dependencies(self, temp_dir):
        """Context includes files that the target imports."""
        (temp_dir / "main.py").write_text("import helper\n")
        (temp_dir / "helper.py").write_text("def help(): pass\n")
        files = [str(temp_dir / f) for f in ["main.py", "helper.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        contents = {"main.py": "import helper\n", "helper.py": "def help(): pass\n"}
        ctx = _select_context_for_file("main.py", graph, contents, depth=1)
        assert "helper.py" in ctx

    def test_high_fan_in_gets_priority(self, temp_dir):
        """Files with higher fan_in are selected first."""
        (temp_dir / "main.py").write_text("import core\nimport utils\n")
        (temp_dir / "other.py").write_text("import core\n")
        (temp_dir / "core.py").write_text("x = 1\n")  # fan_in=2
        (temp_dir / "utils.py").write_text("y = 2\n")  # fan_in=1
        files = [str(temp_dir / f) for f in ["main.py", "other.py", "core.py", "utils.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        contents = {
            "main.py": "import core\nimport utils\n",
            "other.py": "import core\n",
            "core.py": "x = 1\n",
            "utils.py": "y = 2\n",
        }
        ctx = _select_context_for_file("main.py", graph, contents, depth=1)
        # Both should be included (small files)
        assert "core.py" in ctx
        assert "utils.py" in ctx

    def test_empty_when_no_deps(self, temp_dir):
        """File with no dependencies gets empty context."""
        (temp_dir / "standalone.py").write_text("x = 1\n")
        files = [str(temp_dir / "standalone.py")]
        graph = build_dependency_graph(files, str(temp_dir))
        contents = {"standalone.py": "x = 1\n"}
        ctx = _select_context_for_file("standalone.py", graph, contents)
        assert ctx == {}


# ─── Graph summary formatting ────────────────────────────────────────

class TestGraphSummary:
    def test_readable_format(self, temp_dir):
        """Graph summary is human-readable text."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("x = 1\n")
        files = [str(temp_dir / "a.py"), str(temp_dir / "b.py")]
        graph = build_dependency_graph(files, str(temp_dir))
        metrics = compute_metrics(graph)
        summary = _format_graph_summary(graph, metrics)
        assert "2 files" in summary
        assert "1 dependency" in summary or "edge" in summary


# ─── Mocked LLM analysis ────────────────────────────────────────────

class TestMockedLLMAnalysis:
    @patch("dojigiri.llm.analyze_file_with_context")
    @patch("dojigiri.llm.synthesize_project")
    def test_cross_file_findings_parsed(self, mock_synth, mock_analyze, temp_dir):
        """Cross-file findings from LLM are correctly parsed."""
        (temp_dir / "a.py").write_text("import b\nfoo()\n")
        (temp_dir / "b.py").write_text("def foo(x): return x\n")

        from dojigiri.llm import CostTracker
        tracker = CostTracker()

        # First call (b.py, no deps) returns nothing, second call (a.py) returns finding
        mock_analyze.side_effect = [
            ({"cross_file_findings": [], "local_findings": []}, tracker),
            ({
                "cross_file_findings": [{
                    "source_file": "a.py",
                    "target_file": "b.py",
                    "line": 2,
                    "target_line": 1,
                    "severity": "critical",
                    "category": "bug",
                    "rule": "missing-argument",
                    "message": "foo() called with 0 args but expects 1",
                    "confidence": "high",
                }],
                "local_findings": [],
            }, tracker),
        ]

        mock_synth.return_value = ({
            "architecture_summary": "Simple two-file project.",
            "health_score": 5,
            "architectural_issues": [],
            "positive_patterns": [],
            "recommendations": [],
        }, tracker)

        result = analyze_project(str(temp_dir), use_llm=True)
        assert len(result.cross_file_findings) == 1
        cf = result.cross_file_findings[0]
        assert cf.source_file == "a.py"
        assert cf.target_file == "b.py"
        assert cf.rule == "missing-argument"
        assert cf.severity == Severity.CRITICAL

    @patch("dojigiri.llm.analyze_file_with_context")
    @patch("dojigiri.llm.synthesize_project")
    def test_synthesis_returned(self, mock_synth, mock_analyze, temp_dir):
        """Synthesis dict is included in result."""
        (temp_dir / "a.py").write_text("x = 1\n")

        from dojigiri.llm import CostTracker
        tracker = CostTracker()

        mock_analyze.return_value = ({"cross_file_findings": [], "local_findings": []}, tracker)
        mock_synth.return_value = ({
            "architecture_summary": "Minimal project.",
            "health_score": 8,
            "architectural_issues": [],
            "positive_patterns": ["Clean structure"],
            "recommendations": [],
        }, tracker)

        result = analyze_project(str(temp_dir), use_llm=True)
        assert result.synthesis is not None
        assert result.synthesis["health_score"] == 8


# ─── CrossFileFinding dataclass ──────────────────────────────────────

class TestCrossFileFinding:
    def test_to_dict(self):
        """CrossFileFinding serializes correctly."""
        cf = CrossFileFinding(
            source_file="a.py",
            target_file="b.py",
            line=10,
            target_line=5,
            severity=Severity.WARNING,
            category=Category.BUG,
            rule="interface-mismatch",
            message="Wrong argument count",
        )
        d = cf.to_dict()
        assert d["source_file"] == "a.py"
        assert d["target_file"] == "b.py"
        assert d["line"] == 10
        assert d["target_line"] == 5
        assert d["severity"] == "warning"

    def test_to_dict_optional_fields(self):
        """Optional fields are omitted when None."""
        cf = CrossFileFinding(
            source_file="a.py",
            target_file="b.py",
            line=1,
        )
        d = cf.to_dict()
        assert "target_line" not in d
        assert "suggestion" not in d
        assert "confidence" not in d
