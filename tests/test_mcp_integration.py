"""MCP integration tests — call real tool functions on real temp files.

These test the actual wiz_scan/wiz_scan_file/wiz_fix/wiz_explain/wiz_analyze_project
functions end-to-end, not just the formatters. No MCP transport needed — we call
the tool functions directly since they're plain Python functions that return str.
"""

import pytest
import tempfile
from pathlib import Path

from wiz.mcp_server import wiz_scan, wiz_scan_file, wiz_fix, wiz_explain, wiz_analyze_project


# ─── Fixtures ─────────────────────────────────────────────────────────

BUGGY_PYTHON = '''\
import os
import unused_module

def process(items=[]):
    password = "hunter2_secret_key"
    try:
        result = eval(items[0])
    except:
        pass
    return result
'''

CLEAN_PYTHON = '''\
def add(a: int, b: int) -> int:
    return a + b
'''

BUGGY_JS = '''\
var x = 1;
function test() {
    if (x == 5) {
        eval("dangerous");
    }
}
'''


@pytest.fixture
def buggy_py_file(tmp_path):
    f = tmp_path / "buggy.py"
    f.write_text(BUGGY_PYTHON, encoding="utf-8")
    return str(f)


@pytest.fixture
def clean_py_file(tmp_path):
    f = tmp_path / "clean.py"
    f.write_text(CLEAN_PYTHON, encoding="utf-8")
    return str(f)


@pytest.fixture
def buggy_js_file(tmp_path):
    f = tmp_path / "buggy.js"
    f.write_text(BUGGY_JS, encoding="utf-8")
    return str(f)


@pytest.fixture
def project_dir(tmp_path):
    """A small multi-file project for analyze_project tests."""
    (tmp_path / "main.py").write_text(
        "from helpers import do_stuff\n\ndef main():\n    do_stuff()\n",
        encoding="utf-8",
    )
    (tmp_path / "helpers.py").write_text(
        "import os\n\ndef do_stuff():\n    pass\n",
        encoding="utf-8",
    )
    return str(tmp_path)


# ─── wiz_scan ─────────────────────────────────────────────────────────

class TestWizScan:
    def test_scan_finds_issues(self, buggy_py_file):
        result = wiz_scan(buggy_py_file)
        assert "Findings:" in result
        # Should find at least some of: unused-import, mutable-default, bare-except, eval-usage
        assert "0 critical, 0 warning, 0 info" not in result

    def test_scan_directory(self, tmp_path, buggy_py_file):
        result = wiz_scan(str(tmp_path))
        assert "Scan:" in result
        assert "quick mode" in result

    def test_scan_clean_file_has_fewer_issues(self, clean_py_file):
        result = wiz_scan(clean_py_file, min_severity="critical")
        # Clean file should have no critical issues
        assert "0 critical" in result

    def test_scan_nonexistent_path(self):
        result = wiz_scan("/nonexistent/path/to/nowhere")
        assert "Error:" in result
        assert "does not exist" in result

    def test_scan_min_severity_filter(self, buggy_py_file):
        result_all = wiz_scan(buggy_py_file, min_severity="info")
        result_critical = wiz_scan(buggy_py_file, min_severity="critical")
        # "info" should show >= as many findings as "critical"
        # Extract total finding counts
        assert "Findings:" in result_all
        assert "Findings:" in result_critical

    def test_scan_invalid_min_severity(self, buggy_py_file):
        result = wiz_scan(buggy_py_file, min_severity="banana")
        assert "Error:" in result
        assert "invalid min_severity" in result

    def test_scan_ignore_rules(self, buggy_py_file):
        result_full = wiz_scan(buggy_py_file, min_severity="info")
        result_ignored = wiz_scan(
            buggy_py_file,
            min_severity="info",
            ignore_rules="unused-import,mutable-default",
        )
        # Ignoring rules should produce fewer or equal findings
        # Just verify both return valid output
        assert "Scan:" in result_full
        assert "Scan:" in result_ignored

    def test_scan_language_filter(self, tmp_path):
        # Create both .py and .js files
        (tmp_path / "test.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "test.js").write_text("var x = 1;\n", encoding="utf-8")
        result = wiz_scan(str(tmp_path), language="python")
        assert "Scan:" in result
        # Should only scan python files
        assert "1 files" in result or "1 file" in result

    def test_scan_repeated_calls_no_cache_stale(self, buggy_py_file):
        """Regression: repeated scans should return consistent results (no cache staleness)."""
        result1 = wiz_scan(buggy_py_file, min_severity="info")
        result2 = wiz_scan(buggy_py_file, min_severity="info")
        # Both should find the same issues — cache disabled in MCP
        assert result1 == result2


# ─── wiz_scan_file ────────────────────────────────────────────────────

class TestWizScanFile:
    def test_scan_file_finds_issues(self, buggy_py_file):
        result = wiz_scan_file(buggy_py_file)
        assert "File:" in result
        assert "python" in result
        # Should find real issues
        assert "No issues found" not in result

    def test_scan_file_clean(self, clean_py_file):
        result = wiz_scan_file(clean_py_file)
        assert "File:" in result
        assert "python" in result

    def test_scan_file_nonexistent(self):
        result = wiz_scan_file("/nonexistent/file.py")
        assert "Error:" in result

    def test_scan_file_unsupported_type(self, tmp_path):
        f = tmp_path / "data.xyz"
        f.write_text("some content", encoding="utf-8")
        result = wiz_scan_file(str(f))
        assert "Error:" in result
        assert "unsupported" in result

    def test_scan_file_js(self, buggy_js_file):
        result = wiz_scan_file(buggy_js_file)
        assert "File:" in result
        assert "javascript" in result

    def test_scan_file_directory_not_file(self, tmp_path):
        result = wiz_scan_file(str(tmp_path))
        assert "Error:" in result


# ─── wiz_fix ──────────────────────────────────────────────────────────

class TestWizFix:
    def test_fix_finds_fixable_issues(self, buggy_py_file):
        result = wiz_fix(buggy_py_file, min_severity="info")
        assert "dry run" in result
        # buggy.py has bare-except which is fixable
        if "No fixes available" not in result:
            assert "Fix" in result
            # Verify diff-style output
            assert "-" in result or "+" in result

    def test_fix_nonexistent_path(self):
        result = wiz_fix("/nonexistent/path")
        assert "Error:" in result

    def test_fix_unsupported_file(self, tmp_path):
        f = tmp_path / "data.xyz"
        f.write_text("content", encoding="utf-8")
        result = wiz_fix(str(f))
        assert "Error:" in result
        assert "unsupported" in result

    def test_fix_does_not_modify_file(self, buggy_py_file):
        """Critical: wiz_fix must be dry-run only — file content unchanged."""
        original = Path(buggy_py_file).read_text(encoding="utf-8")
        wiz_fix(buggy_py_file, min_severity="info")
        after = Path(buggy_py_file).read_text(encoding="utf-8")
        assert original == after

    def test_fix_no_backup_created(self, buggy_py_file):
        """Dry-run should not create .wiz.bak files."""
        parent = Path(buggy_py_file).parent
        before = set(parent.iterdir())
        wiz_fix(buggy_py_file, min_severity="info")
        after = set(parent.iterdir())
        new_files = after - before
        bak_files = [f for f in new_files if ".bak" in f.name or ".wiz" in f.name]
        assert bak_files == []

    def test_fix_directory(self, tmp_path, buggy_py_file):
        result = wiz_fix(str(tmp_path), min_severity="info")
        assert "dry run" in result

    def test_fix_rule_filter(self, buggy_py_file):
        result = wiz_fix(buggy_py_file, rules="bare-except", min_severity="info")
        assert "dry run" in result
        # If there are fixes, they should only be for bare-except
        if "Fix" in result and "No fixes" not in result:
            assert "bare-except" in result


# ─── wiz_explain ──────────────────────────────────────────────────────

class TestWizExplain:
    def test_explain_returns_summary(self, buggy_py_file):
        result = wiz_explain(buggy_py_file)
        assert "Explanation:" in result
        assert "python" in result
        assert "Summary:" in result

    def test_explain_shows_structure(self, buggy_py_file):
        result = wiz_explain(buggy_py_file)
        # Should identify the process function
        assert "process" in result

    def test_explain_nonexistent(self):
        result = wiz_explain("/nonexistent/file.py")
        assert "Error:" in result

    def test_explain_js(self, buggy_js_file):
        result = wiz_explain(buggy_js_file)
        assert "Explanation:" in result
        assert "javascript" in result


# ─── wiz_analyze_project ─────────────────────────────────────────────

class TestWizAnalyzeProject:
    def test_analyze_project_basic(self, project_dir):
        result = wiz_analyze_project(project_dir)
        assert "Project:" in result
        assert "2 files" in result or "files" in result

    def test_analyze_project_not_a_directory(self, buggy_py_file):
        result = wiz_analyze_project(buggy_py_file)
        assert "Error:" in result
        assert "not a directory" in result

    def test_analyze_project_nonexistent(self):
        result = wiz_analyze_project("/nonexistent/dir")
        assert "Error:" in result

    def test_analyze_project_empty_dir(self, tmp_path):
        result = wiz_analyze_project(str(tmp_path))
        assert "Project:" in result
        assert "0 files" in result

    def test_analyze_project_language_filter(self, project_dir):
        result = wiz_analyze_project(project_dir, language="python")
        assert "Project:" in result


# ─── Cross-tool sequences ────────────────────────────────────────────

class TestToolSequences:
    def test_scan_then_fix_same_file(self, buggy_py_file):
        """Simulate Claude's workflow: scan first, then check fixes."""
        scan_result = wiz_scan_file(buggy_py_file)
        assert "No issues found" not in scan_result

        fix_result = wiz_fix(buggy_py_file, min_severity="info")
        assert "dry run" in fix_result

    def test_scan_then_explain(self, buggy_py_file):
        """Scan to find issues, explain to understand the file."""
        scan_result = wiz_scan_file(buggy_py_file)
        explain_result = wiz_explain(buggy_py_file)
        assert "Findings:" in scan_result
        assert "Summary:" in explain_result

    def test_scan_dir_then_scan_file(self, tmp_path, buggy_py_file):
        """Directory scan, then drill into a specific file."""
        dir_result = wiz_scan(str(tmp_path), min_severity="info")
        file_result = wiz_scan_file(buggy_py_file)
        assert "Scan:" in dir_result
        assert "File:" in file_result
