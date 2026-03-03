"""Tests for wiz/depgraph.py — dependency graph engine."""

import pytest
from pathlib import Path

from wiz.graph.depgraph import (
    build_dependency_graph, compute_metrics,
    DepGraph, FileNode, GraphMetrics,
    _resolve_python_imports, _resolve_js_ts_imports,
    _is_entry_point, _detect_cycles,
)


# ─── Python import resolution ────────────────────────────────────────

class TestPythonImportResolution:
    def test_absolute_import(self, temp_dir):
        """import foo → foo.py"""
        (temp_dir / "foo.py").write_text("x = 1\n")
        (temp_dir / "main.py").write_text("import foo\n")
        result = _resolve_python_imports(
            str(temp_dir / "main.py"), "import foo\n", str(temp_dir)
        )
        assert "foo.py" in result

    def test_from_import(self, temp_dir):
        """from foo import bar → foo.py"""
        (temp_dir / "foo.py").write_text("bar = 1\n")
        (temp_dir / "main.py").write_text("from foo import bar\n")
        result = _resolve_python_imports(
            str(temp_dir / "main.py"), "from foo import bar\n", str(temp_dir)
        )
        assert "foo.py" in result

    def test_relative_import(self, temp_dir):
        """from . import utils → utils.py in same dir"""
        pkg = temp_dir / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("")
        (pkg / "utils.py").write_text("x = 1\n")
        (pkg / "main.py").write_text("from . import utils\n")
        result = _resolve_python_imports(
            str(pkg / "main.py"), "from . import utils\n", str(temp_dir)
        )
        assert any("utils.py" in r for r in result)

    def test_parent_relative_import(self, temp_dir):
        """from .. import models → models.py in parent dir"""
        pkg = temp_dir / "pkg"
        sub = pkg / "sub"
        sub.mkdir(parents=True)
        (pkg / "__init__.py").write_text("")
        (sub / "__init__.py").write_text("")
        (pkg / "models.py").write_text("x = 1\n")
        (sub / "main.py").write_text("from .. import models\n")
        result = _resolve_python_imports(
            str(sub / "main.py"), "from .. import models\n", str(temp_dir)
        )
        assert any("models.py" in r for r in result)

    def test_package_init(self, temp_dir):
        """import pkg → pkg/__init__.py"""
        pkg = temp_dir / "pkg"
        pkg.mkdir()
        (pkg / "__init__.py").write_text("x = 1\n")
        (temp_dir / "main.py").write_text("import pkg\n")
        result = _resolve_python_imports(
            str(temp_dir / "main.py"), "import pkg\n", str(temp_dir)
        )
        assert any("__init__.py" in r for r in result)

    def test_dotted_import(self, temp_dir):
        """from foo.bar import X → foo/bar.py"""
        foo = temp_dir / "foo"
        foo.mkdir()
        (foo / "__init__.py").write_text("")
        (foo / "bar.py").write_text("X = 1\n")
        (temp_dir / "main.py").write_text("from foo.bar import X\n")
        result = _resolve_python_imports(
            str(temp_dir / "main.py"), "from foo.bar import X\n", str(temp_dir)
        )
        assert any("bar.py" in r for r in result)

    def test_skip_installed_packages(self, temp_dir):
        """import os, import json → not resolved (not under project root)"""
        (temp_dir / "main.py").write_text("import os\nimport json\n")
        result = _resolve_python_imports(
            str(temp_dir / "main.py"), "import os\nimport json\n", str(temp_dir)
        )
        assert len(result) == 0

    def test_syntax_error_graceful(self, temp_dir):
        """Syntax errors don't crash, just return empty set."""
        result = _resolve_python_imports(
            str(temp_dir / "bad.py"), "def foo(\n", str(temp_dir)
        )
        assert result == set()


# ─── JS/TS import resolution ─────────────────────────────────────────

class TestJsTsImportResolution:
    def test_es_import(self, temp_dir):
        """import X from './utils'"""
        (temp_dir / "utils.js").write_text("export const x = 1;\n")
        (temp_dir / "main.js").write_text("import { x } from './utils';\n")
        result = _resolve_js_ts_imports(
            str(temp_dir / "main.js"),
            "import { x } from './utils';\n",
            str(temp_dir),
        )
        assert "utils.js" in result

    def test_require(self, temp_dir):
        """const X = require('./utils')"""
        (temp_dir / "utils.js").write_text("module.exports = {};\n")
        (temp_dir / "main.js").write_text("const u = require('./utils');\n")
        result = _resolve_js_ts_imports(
            str(temp_dir / "main.js"),
            "const u = require('./utils');\n",
            str(temp_dir),
        )
        assert "utils.js" in result

    def test_skip_node_modules(self, temp_dir):
        """import from 'express' → not resolved"""
        (temp_dir / "main.js").write_text("import express from 'express';\n")
        result = _resolve_js_ts_imports(
            str(temp_dir / "main.js"),
            "import express from 'express';\n",
            str(temp_dir),
        )
        assert len(result) == 0

    def test_extension_resolution(self, temp_dir):
        """import from './utils' resolves to utils.ts"""
        (temp_dir / "utils.ts").write_text("export const x = 1;\n")
        (temp_dir / "main.ts").write_text("import { x } from './utils';\n")
        result = _resolve_js_ts_imports(
            str(temp_dir / "main.ts"),
            "import { x } from './utils';\n",
            str(temp_dir),
        )
        assert "utils.ts" in result


# ─── Graph building ──────────────────────────────────────────────────

class TestGraphBuilding:
    def test_simple_graph(self, temp_dir):
        """A imports B → graph has edge A→B."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("x = 1\n")
        files = [str(temp_dir / "a.py"), str(temp_dir / "b.py")]
        graph = build_dependency_graph(files, str(temp_dir))
        assert "b.py" in graph.nodes["a.py"].imports

    def test_bidirectional_edges(self, temp_dir):
        """A imports B → B.imported_by includes A."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("x = 1\n")
        files = [str(temp_dir / "a.py"), str(temp_dir / "b.py")]
        graph = build_dependency_graph(files, str(temp_dir))
        assert "a.py" in graph.nodes["b.py"].imported_by

    def test_fan_metrics(self, temp_dir):
        """File imported by 2 has fan_in=2."""
        (temp_dir / "a.py").write_text("import c\n")
        (temp_dir / "b.py").write_text("import c\n")
        (temp_dir / "c.py").write_text("x = 1\n")
        files = [str(temp_dir / f) for f in ["a.py", "b.py", "c.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        assert graph.nodes["c.py"].fan_in == 2
        assert graph.nodes["c.py"].fan_out == 0

    def test_hub_detection(self, temp_dir):
        """File with fan_in >= 3 and fan_out >= 3 is a hub."""
        # hub.py imports a, b, c and is imported by d, e, f
        (temp_dir / "hub.py").write_text("import a\nimport b\nimport c\n")
        for name in ["a", "b", "c"]:
            (temp_dir / f"{name}.py").write_text("x = 1\n")
        for name in ["d", "e", "f"]:
            (temp_dir / f"{name}.py").write_text("import hub\n")
        files = [str(temp_dir / f"{n}.py") for n in ["hub", "a", "b", "c", "d", "e", "f"]]
        graph = build_dependency_graph(files, str(temp_dir))
        assert graph.nodes["hub.py"].is_hub

    def test_mixed_languages(self, temp_dir):
        """Python and JS files coexist in graph."""
        (temp_dir / "main.py").write_text("import utils\n")
        (temp_dir / "utils.py").write_text("x = 1\n")
        (temp_dir / "app.js").write_text("import { x } from './helper';\n")
        (temp_dir / "helper.js").write_text("export const x = 1;\n")
        files = [str(temp_dir / f) for f in ["main.py", "utils.py", "app.js", "helper.js"]]
        graph = build_dependency_graph(files, str(temp_dir))
        assert len(graph.nodes) == 4
        assert "utils.py" in graph.nodes["main.py"].imports
        assert "helper.js" in graph.nodes["app.js"].imports


# ─── Cycle detection ─────────────────────────────────────────────────

class TestCycleDetection:
    def test_no_cycles(self, temp_dir):
        """Linear chain: A→B→C has no cycles."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("import c\n")
        (temp_dir / "c.py").write_text("x = 1\n")
        files = [str(temp_dir / f) for f in ["a.py", "b.py", "c.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        assert len(graph.circular_deps) == 0

    def test_simple_cycle(self, temp_dir):
        """A imports B, B imports A → cycle detected."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("import a\n")
        files = [str(temp_dir / "a.py"), str(temp_dir / "b.py")]
        graph = build_dependency_graph(files, str(temp_dir))
        assert len(graph.circular_deps) > 0
        # Cycle should contain both a.py and b.py
        cycle_members = set()
        for cycle in graph.circular_deps:
            cycle_members.update(cycle)
        assert "a.py" in cycle_members
        assert "b.py" in cycle_members

    def test_indirect_cycle(self, temp_dir):
        """A→B→C→A forms a cycle."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("import c\n")
        (temp_dir / "c.py").write_text("import a\n")
        files = [str(temp_dir / f) for f in ["a.py", "b.py", "c.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        assert len(graph.circular_deps) > 0


# ─── Topological sort ────────────────────────────────────────────────

class TestTopologicalSort:
    def test_linear_chain(self, temp_dir):
        """A→B→C: C should come before B, B before A."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("import c\n")
        (temp_dir / "c.py").write_text("x = 1\n")
        files = [str(temp_dir / f) for f in ["a.py", "b.py", "c.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        order = graph.topological_sort()
        # c has no deps → should come first (or at least before b)
        assert order.index("c.py") < order.index("b.py")
        assert order.index("b.py") < order.index("a.py")

    def test_diamond(self, temp_dir):
        """A→B, A→C, B→D, C→D: D should come first."""
        (temp_dir / "a.py").write_text("import b\nimport c\n")
        (temp_dir / "b.py").write_text("import d\n")
        (temp_dir / "c.py").write_text("import d\n")
        (temp_dir / "d.py").write_text("x = 1\n")
        files = [str(temp_dir / f) for f in ["a.py", "b.py", "c.py", "d.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        order = graph.topological_sort()
        assert order.index("d.py") < order.index("b.py")
        assert order.index("d.py") < order.index("c.py")

    def test_graceful_with_cycles(self, temp_dir):
        """Cycles don't crash topo sort — all nodes appear in output."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("import a\n")
        (temp_dir / "c.py").write_text("x = 1\n")
        files = [str(temp_dir / f) for f in ["a.py", "b.py", "c.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        order = graph.topological_sort()
        assert set(order) == {"a.py", "b.py", "c.py"}


# ─── Graph metrics ───────────────────────────────────────────────────

class TestGraphMetrics:
    def test_dead_modules(self, temp_dir):
        """File with fan_in=0 that isn't an entry point is dead."""
        (temp_dir / "used.py").write_text("x = 1\n")
        (temp_dir / "unused.py").write_text("y = 2\n")
        (temp_dir / "main.py").write_text("import used\n")
        files = [str(temp_dir / f) for f in ["used.py", "unused.py", "main.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        metrics = compute_metrics(graph)
        # unused.py has fan_in=0 and isn't an entry point
        assert "unused.py" in metrics.dead_modules
        # main.py is an entry point, shouldn't be dead
        assert "main.py" not in metrics.dead_modules

    def test_coupling_score(self, temp_dir):
        """Coupling score = edges / max_possible_edges."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("x = 1\n")
        files = [str(temp_dir / "a.py"), str(temp_dir / "b.py")]
        graph = build_dependency_graph(files, str(temp_dir))
        metrics = compute_metrics(graph)
        # 1 edge out of max 2 (2*1) → 0.5
        assert metrics.coupling_score == pytest.approx(0.5)

    def test_entry_points(self, temp_dir):
        """__main__.py and test_ files are entry points."""
        (temp_dir / "__main__.py").write_text("print('hi')\n")
        (temp_dir / "test_foo.py").write_text("def test_x(): pass\n")
        (temp_dir / "lib.py").write_text("x = 1\n")
        files = [str(temp_dir / f) for f in ["__main__.py", "test_foo.py", "lib.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        metrics = compute_metrics(graph)
        assert "__main__.py" in metrics.entry_points
        assert "test_foo.py" in metrics.entry_points
        assert "lib.py" not in metrics.entry_points


# ─── Transitive dependencies ─────────────────────────────────────────

class TestTransitiveDeps:
    def test_depth_1(self, temp_dir):
        """Depth 1: only direct imports."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("import c\n")
        (temp_dir / "c.py").write_text("x = 1\n")
        files = [str(temp_dir / f) for f in ["a.py", "b.py", "c.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        deps = graph.get_dependencies("a.py", depth=1)
        assert "b.py" in deps
        assert "c.py" not in deps

    def test_depth_2(self, temp_dir):
        """Depth 2: direct + transitive."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("import c\n")
        (temp_dir / "c.py").write_text("x = 1\n")
        files = [str(temp_dir / f) for f in ["a.py", "b.py", "c.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        deps = graph.get_dependencies("a.py", depth=2)
        assert "b.py" in deps
        assert "c.py" in deps

    def test_depth_limit(self, temp_dir):
        """Depth is respected even with deeper chains."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("import c\n")
        (temp_dir / "c.py").write_text("import d\n")
        (temp_dir / "d.py").write_text("x = 1\n")
        files = [str(temp_dir / f) for f in ["a.py", "b.py", "c.py", "d.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        deps = graph.get_dependencies("a.py", depth=2)
        assert "b.py" in deps
        assert "c.py" in deps
        assert "d.py" not in deps


# ─── Serialization ───────────────────────────────────────────────────

class TestSerialization:
    def test_to_dict_roundtrip(self, temp_dir):
        """Graph serializes to dict with expected keys."""
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("x = 1\n")
        files = [str(temp_dir / "a.py"), str(temp_dir / "b.py")]
        graph = build_dependency_graph(files, str(temp_dir))
        d = graph.to_dict()
        assert "root" in d
        assert "nodes" in d
        assert "circular_deps" in d
        assert "a.py" in d["nodes"]
        assert "b.py" in d["nodes"]["a.py"]["imports"]

    def test_empty_graph(self):
        """Empty graph serializes cleanly."""
        graph = DepGraph(root="/empty")
        d = graph.to_dict()
        assert d == {"root": "/empty", "nodes": {}, "circular_deps": []}
        metrics = compute_metrics(graph)
        assert metrics.total_files == 0
        assert metrics.total_edges == 0
        assert metrics.coupling_score == 0.0


# ─── Entry point detection ───────────────────────────────────────────

class TestEntryPointDetection:
    def test_main_files(self):
        assert _is_entry_point("__main__.py")
        assert _is_entry_point("main.py")
        assert _is_entry_point("app.py")

    def test_test_files(self):
        assert _is_entry_point("test_foo.py")
        assert _is_entry_point("foo_test.py")

    def test_regular_files(self):
        assert not _is_entry_point("utils.py")
        assert not _is_entry_point("models.py")

    def test_init_files(self):
        assert _is_entry_point("__init__.py")

    def test_js_entry_points(self):
        assert _is_entry_point("index.js")
        assert _is_entry_point("index.ts")


# ─── Metrics to_dict ─────────────────────────────────────────────────

class TestMetricsDict:
    def test_metrics_serializable(self, temp_dir):
        """GraphMetrics.to_dict() produces JSON-serializable dict."""
        import json
        (temp_dir / "a.py").write_text("import b\n")
        (temp_dir / "b.py").write_text("x = 1\n")
        files = [str(temp_dir / "a.py"), str(temp_dir / "b.py")]
        graph = build_dependency_graph(files, str(temp_dir))
        metrics = compute_metrics(graph)
        d = metrics.to_dict()
        # Should be JSON-serializable
        json_str = json.dumps(d)
        assert "total_files" in json_str
        assert "coupling_score" in json_str


# ─── Rank by importance ──────────────────────────────────────────────

class TestRankByImportance:
    def test_most_imported_ranks_first(self, temp_dir):
        """File imported by most others should rank highest."""
        (temp_dir / "a.py").write_text("import core\n")
        (temp_dir / "b.py").write_text("import core\n")
        (temp_dir / "c.py").write_text("import core\n")
        (temp_dir / "core.py").write_text("x = 1\n")
        files = [str(temp_dir / f) for f in ["a.py", "b.py", "c.py", "core.py"]]
        graph = build_dependency_graph(files, str(temp_dir))
        ranked = graph.rank_by_importance()
        # core.py has fan_in=3, should be first
        assert ranked[0][0] == "core.py"
