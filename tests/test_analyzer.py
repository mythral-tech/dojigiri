"""Tests for analyzer module - file collection and scanning."""

import os
import sys
import pytest
from pathlib import Path
from dojigiri.discovery import (
    detect_language,
    should_skip_dir,
    should_skip_file,
    collect_files,
)
from dojigiri.analyzer import (
    filter_report,
    diff_reports,
    get_changed_lines,
    _find_git_root,
    _HUNK_RE,
)
from dojigiri.types import Severity, Finding, Category, Source


def test_detect_language():
    """Test language detection from file extensions."""
    assert detect_language(Path("test.py")) == "python"
    assert detect_language(Path("test.js")) == "javascript"
    assert detect_language(Path("test.ts")) == "typescript"
    assert detect_language(Path("test.go")) == "go"
    assert detect_language(Path("test.rs")) == "rust"
    assert detect_language(Path("test.java")) == "java"
    assert detect_language(Path("test.txt")) is None
    assert detect_language(Path("README.md")) is None


def test_detect_language_case_insensitive():
    """Test that language detection is case-insensitive."""
    assert detect_language(Path("test.PY")) == "python"
    assert detect_language(Path("test.JS")) == "javascript"


def test_should_skip_dir():
    """Test directory skipping logic."""
    assert should_skip_dir(".git")
    assert should_skip_dir(".svn")
    assert should_skip_dir("node_modules")
    assert should_skip_dir("__pycache__")
    assert should_skip_dir(".mypy_cache")
    assert should_skip_dir("venv")
    assert should_skip_dir(".hidden")  # Starts with .
    
    assert not should_skip_dir("src")
    assert not should_skip_dir("lib")
    assert not should_skip_dir("tests")


def test_should_skip_file(temp_dir):
    """Test file skipping logic."""
    # Create test files
    normal_file = temp_dir / "test.py"
    normal_file.write_text("print('hello')")
    
    lockfile = temp_dir / "package-lock.json"
    lockfile.write_text("{}")
    
    huge_file = temp_dir / "huge.py"
    huge_file.write_bytes(b"x" * 2_000_000)  # 2MB
    
    empty_file = temp_dir / "empty.py"
    empty_file.write_text("")
    
    # Test skipping logic
    assert not should_skip_file(normal_file)
    assert should_skip_file(lockfile)  # In SKIP_FILES
    assert should_skip_file(huge_file)  # Too large
    assert should_skip_file(empty_file)  # Empty
    assert should_skip_file(temp_dir / "test.txt")  # Unsupported extension


def test_collect_files_single_file(temp_dir):
    """Test collecting a single file."""
    test_file = temp_dir / "test.py"
    test_file.write_text("print('hello')")
    
    files, skipped = collect_files(test_file)
    
    assert len(files) == 1
    assert files[0] == test_file
    assert skipped == 0


def test_collect_files_directory(temp_dir):
    """Test collecting files from a directory."""
    # Create directory structure
    (temp_dir / "src").mkdir()
    (temp_dir / "src" / "main.py").write_text("code")
    (temp_dir / "src" / "utils.py").write_text("code")
    (temp_dir / "test.js").write_text("code")
    (temp_dir / "README.md").write_text("docs")  # Should be skipped
    
    files, skipped = collect_files(temp_dir)
    
    assert len(files) == 3  # 2 Python + 1 JavaScript
    assert skipped >= 1  # At least the README


def test_collect_files_skip_dirs(temp_dir):
    """Test that skipped directories are not traversed."""
    # Create directory structure with skip dirs
    (temp_dir / "src").mkdir()
    (temp_dir / "src" / "main.py").write_text("code")
    
    (temp_dir / "node_modules").mkdir()
    (temp_dir / "node_modules" / "lib.js").write_text("code")
    
    (temp_dir / "__pycache__").mkdir()
    (temp_dir / "__pycache__" / "cache.pyc").write_bytes(b"cache")
    
    files, skipped = collect_files(temp_dir)
    
    # Should only find src/main.py, not files in skip dirs
    assert len(files) == 1
    assert files[0].name == "main.py"


def test_collect_files_with_language_filter(temp_dir):
    """Test collecting files with language filter."""
    (temp_dir / "test.py").write_text("python")
    (temp_dir / "test.js").write_text("javascript")
    (temp_dir / "test.go").write_text("go")
    
    # Filter for Python only
    files, skipped = collect_files(temp_dir, language_filter="python")
    assert len(files) == 1
    assert files[0].suffix == ".py"
    
    # Filter for JavaScript
    files, skipped = collect_files(temp_dir, language_filter="javascript")
    assert len(files) == 1
    assert files[0].suffix == ".js"


def test_collect_files_with_wizignore(temp_dir):
    """Test that .doji-ignore patterns are respected."""
    # Create .doji-ignore
    (temp_dir / ".doji-ignore").write_text("*.log\ntest_*\n")
    
    # Create files
    (temp_dir / "main.py").write_text("code")
    (temp_dir / "test_foo.py").write_text("code")
    (temp_dir / "debug.log").write_text("log")
    
    files, skipped = collect_files(temp_dir)
    
    # Should only find main.py
    assert len(files) == 1
    assert files[0].name == "main.py"


def test_filter_report_ignore_rules(sample_scan_report):
    """Test filtering report by ignored rules."""
    # Add some findings with different rules
    from dojigiri.types import FileAnalysis
    findings = [
        Finding("test.py", 1, Severity.CRITICAL, Category.BUG, Source.STATIC, "rule1", "msg1"),
        Finding("test.py", 2, Severity.WARNING, Category.BUG, Source.STATIC, "rule2", "msg2"),
        Finding("test.py", 3, Severity.INFO, Category.STYLE, Source.STATIC, "rule3", "msg3"),
    ]
    fa = FileAnalysis("test.py", "python", 100, findings)
    sample_scan_report.file_analyses = [fa]

    # Filter out rule2
    filtered = filter_report(sample_scan_report, ignore_rules={"rule2"})
    
    all_findings = []
    for fa in filtered.file_analyses:
        all_findings.extend(fa.findings)
    
    rules = {f.rule for f in all_findings}
    assert "rule1" in rules
    assert "rule2" not in rules
    assert "rule3" in rules


def test_filter_report_min_severity(sample_scan_report):
    """Test filtering report by minimum severity."""
    from dojigiri.types import FileAnalysis
    findings = [
        Finding("test.py", 1, Severity.CRITICAL, Category.BUG, Source.STATIC, "r1", "msg1"),
        Finding("test.py", 2, Severity.WARNING, Category.BUG, Source.STATIC, "r2", "msg2"),
        Finding("test.py", 3, Severity.INFO, Category.STYLE, Source.STATIC, "r3", "msg3"),
    ]
    fa = FileAnalysis("test.py", "python", 100, findings)
    sample_scan_report.file_analyses = [fa]
    
    # Filter to only show warnings and above
    filtered = filter_report(sample_scan_report, min_severity=Severity.WARNING)
    
    all_findings = []
    for fa in filtered.file_analyses:
        all_findings.extend(fa.findings)
    
    severities = {f.severity for f in all_findings}
    assert Severity.CRITICAL in severities
    assert Severity.WARNING in severities
    assert Severity.INFO not in severities


def test_filter_report_updates_counts(sample_scan_report):
    """Test that filtering updates the computed counts."""
    from dojigiri.types import FileAnalysis
    findings = [
        Finding("test.py", 1, Severity.CRITICAL, Category.BUG, Source.STATIC, "r1", "msg1"),
        Finding("test.py", 2, Severity.WARNING, Category.BUG, Source.STATIC, "r2", "msg2"),
        Finding("test.py", 3, Severity.INFO, Category.STYLE, Source.STATIC, "r3", "msg3"),
    ]
    fa = FileAnalysis("test.py", "python", 100, findings)
    sample_scan_report.file_analyses = [fa]

    # Verify pre-filter counts (computed properties)
    assert sample_scan_report.total_findings == 3
    assert sample_scan_report.critical == 1

    # Filter to only warnings and above
    filtered = filter_report(sample_scan_report, min_severity=Severity.WARNING)

    assert filtered.total_findings == 2
    assert filtered.critical == 1
    assert filtered.warnings == 1
    assert filtered.info == 0


def test_diff_reports_removes_known_findings(sample_scan_report):
    """Test that diff_reports filters out findings in baseline."""
    from dojigiri.types import FileAnalysis
    
    # Current report has 3 findings
    current_findings = [
        Finding("test.py", 10, Severity.WARNING, Category.BUG, Source.STATIC, "rule1", "msg1"),
        Finding("test.py", 25, Severity.INFO, Category.STYLE, Source.STATIC, "rule2", "msg2"),
        Finding("test.py", 50, Severity.CRITICAL, Category.SECURITY, Source.STATIC, "rule3", "msg3"),
    ]
    fa = FileAnalysis("test.py", "python", 100, current_findings)
    sample_scan_report.file_analyses = [fa]

    # Baseline has 2 of these findings (line 10 and 50)
    baseline_dict = {
        "files": [
            {
                "path": "test.py",
                "findings": [
                    {"line": 10, "rule": "rule1"},  # Same bucket as line 10 (10//5 = 2)
                    {"line": 51, "rule": "rule3"},  # Same bucket as line 50 (50//5 = 10, 51//5 = 10)
                ]
            }
        ]
    }
    
    # Apply diff
    diffed = diff_reports(sample_scan_report, baseline_dict)
    
    # Should only have the finding at line 25 (rule2)
    all_findings = []
    for fa in diffed.file_analyses:
        all_findings.extend(fa.findings)
    
    assert len(all_findings) == 1
    assert all_findings[0].rule == "rule2"
    assert all_findings[0].line == 25


def test_diff_reports_preserves_new_findings(sample_scan_report):
    """Test that diff_reports preserves findings not in baseline."""
    from dojigiri.types import FileAnalysis
    
    # Current report has findings
    current_findings = [
        Finding("test.py", 15, Severity.WARNING, Category.BUG, Source.STATIC, "new_rule", "new issue"),
        Finding("other.py", 20, Severity.INFO, Category.STYLE, Source.STATIC, "style_rule", "style"),
    ]
    fa1 = FileAnalysis("test.py", "python", 100, [current_findings[0]])
    fa2 = FileAnalysis("other.py", "python", 50, [current_findings[1]])
    sample_scan_report.file_analyses = [fa1, fa2]

    # Baseline has different findings (different file or rule)
    baseline_dict = {
        "files": [
            {
                "path": "test.py",
                "findings": [
                    {"line": 10, "rule": "old_rule"},  # Different rule
                ]
            }
        ]
    }
    
    # Apply diff
    diffed = diff_reports(sample_scan_report, baseline_dict)
    
    # Should preserve both findings (different from baseline)
    all_findings = []
    for fa in diffed.file_analyses:
        all_findings.extend(fa.findings)
    
    assert len(all_findings) == 2
    rules = {f.rule for f in all_findings}
    assert "new_rule" in rules
    assert "style_rule" in rules


def test_diff_reports_uses_bucket_matching(sample_scan_report):
    """Test that diff_reports uses 5-line bucket matching."""
    from dojigiri.types import FileAnalysis
    
    # Current finding at line 12
    current_findings = [
        Finding("test.py", 12, Severity.WARNING, Category.BUG, Source.STATIC, "rule1", "msg"),
    ]
    fa = FileAnalysis("test.py", "python", 100, current_findings)
    sample_scan_report.file_analyses = [fa]

    # Baseline has same rule at line 14 (both in bucket 2: 12//5=2, 14//5=2)
    baseline_dict = {
        "files": [
            {
                "path": "test.py",
                "findings": [
                    {"line": 14, "rule": "rule1"},  # Within 5-line bucket
                ]
            }
        ]
    }
    
    # Apply diff - should filter out the finding (same bucket + rule)
    diffed = diff_reports(sample_scan_report, baseline_dict)
    
    all_findings = []
    for fa in diffed.file_analyses:
        all_findings.extend(fa.findings)
    
    assert len(all_findings) == 0  # Filtered out


def test_diff_reports_empty_baseline(sample_scan_report):
    """Test diff_reports with empty baseline (all findings are new)."""
    from dojigiri.types import FileAnalysis
    
    current_findings = [
        Finding("test.py", 10, Severity.WARNING, Category.BUG, Source.STATIC, "rule1", "msg1"),
        Finding("test.py", 20, Severity.INFO, Category.STYLE, Source.STATIC, "rule2", "msg2"),
    ]
    fa = FileAnalysis("test.py", "python", 100, current_findings)
    sample_scan_report.file_analyses = [fa]

    # Empty baseline
    baseline_dict = {"files": []}
    
    # Apply diff
    diffed = diff_reports(sample_scan_report, baseline_dict)
    
    # Should preserve all findings
    all_findings = []
    for fa in diffed.file_analyses:
        all_findings.extend(fa.findings)
    
    assert len(all_findings) == 2


def test_diff_reports_updates_counts(sample_scan_report):
    """Test that diff_reports updates totals correctly."""
    from dojigiri.types import FileAnalysis
    
    current_findings = [
        Finding("test.py", 10, Severity.CRITICAL, Category.BUG, Source.STATIC, "r1", "msg1"),
        Finding("test.py", 20, Severity.WARNING, Category.BUG, Source.STATIC, "r2", "msg2"),
        Finding("test.py", 30, Severity.INFO, Category.STYLE, Source.STATIC, "r3", "msg3"),
    ]
    fa = FileAnalysis("test.py", "python", 100, current_findings)
    sample_scan_report.file_analyses = [fa]

    # Baseline has the critical and info findings
    baseline_dict = {
        "files": [
            {
                "path": "test.py",
                "findings": [
                    {"line": 10, "rule": "r1"},  # Critical
                    {"line": 30, "rule": "r3"},  # Info
                ]
            }
        ]
    }
    
    # Apply diff
    diffed = diff_reports(sample_scan_report, baseline_dict)
    
    # Should only have the warning
    assert diffed.total_findings == 1
    assert diffed.critical == 0
    assert diffed.warnings == 1
    assert diffed.info == 0


# ─── Git diff scanning tests ─────────────────────────────────────────


def test_hunk_regex_single_line():
    """Test hunk regex matches single line addition."""
    m = _HUNK_RE.match("@@ -10,0 +15 @@")
    assert m is not None
    assert m.group(1) == "15"
    assert m.group(2) is None  # single line, no count


def test_hunk_regex_multi_line():
    """Test hunk regex matches multi-line hunk."""
    m = _HUNK_RE.match("@@ -10,5 +20,3 @@ def foo():")
    assert m is not None
    assert m.group(1) == "20"
    assert m.group(2) == "3"


def test_hunk_regex_zero_count():
    """Test hunk regex with zero count (pure deletion)."""
    m = _HUNK_RE.match("@@ -10,3 +12,0 @@")
    assert m is not None
    assert m.group(1) == "12"
    assert m.group(2) == "0"


def test_find_git_root():
    """Test git root detection from Genesis directory."""
    root = _find_git_root(Path(__file__).parent)
    assert root is not None
    assert (root / ".git").is_dir()


def test_get_changed_lines_untracked(temp_dir):
    """Untracked file returns empty set (all lines treated as changed)."""
    fake_file = temp_dir / "new_file.py"
    fake_file.write_text("x = 1\n")
    # temp_dir is not a git repo, so this should return empty
    result = get_changed_lines(temp_dir, "HEAD", fake_file)
    assert result == set()


class TestDiffScanCLI:
    def test_diff_help(self):
        """--diff flag appears in scan help."""
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, "-m", "dojigiri", "scan", "--help"],
            capture_output=True, text=True, timeout=10,
        )
        assert "--diff" in result.stdout

    def test_diff_scan_runs(self):
        """doji scan . --diff runs without error in the Genesis repo."""
        import subprocess, sys
        result = subprocess.run(
            [sys.executable, "-m", "dojigiri", "scan", "dojigiri/", "--diff"],
            capture_output=True, timeout=30,
            cwd=str(Path(__file__).parent.parent),
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        assert result.returncode in (0, 2)  # 0=clean, 2=critical found
        assert "DIFF" in stdout

    def test_diff_scan_json(self):
        """doji scan . --diff --output json produces valid JSON."""
        import subprocess, sys, json as json_mod
        result = subprocess.run(
            [sys.executable, "-m", "dojigiri", "scan", "dojigiri/", "--diff", "--output", "json"],
            capture_output=True, timeout=30,
            cwd=str(Path(__file__).parent.parent),
        )
        stdout = result.stdout.decode("utf-8", errors="replace")
        assert result.returncode in (0, 2)
        data = json_mod.loads(stdout)
        assert data["mode"] == "diff"


# ─── Symlink protection tests ────────────────────────────────────────


@pytest.mark.skipif(sys.platform == "win32", reason="Symlinks require special privileges on Windows")
def test_collect_files_skips_symlinks(temp_dir):
    """Test that symlinked files are skipped during collection."""
    # Create a real file
    (temp_dir / "real.py").write_text("x = 1\n")
    # Create a symlink to a file outside the project
    target = temp_dir.parent / "outside_target.py"
    target.write_text("secret = 'nope'\n")
    link = temp_dir / "link.py"
    link.symlink_to(target)

    files, skipped = collect_files(temp_dir)

    file_names = [f.name for f in files]
    assert "real.py" in file_names
    assert "link.py" not in file_names
    assert skipped >= 1

    # Cleanup
    target.unlink()


# ─── Sensitive file exclusion tests ──────────────────────────────────


def test_should_skip_sensitive_files(temp_dir):
    """Test that sensitive file patterns are correctly identified for skipping."""
    sensitive_names = [".env", "secrets.json", "credentials.json", "id_rsa"]
    for name in sensitive_names:
        f = temp_dir / name
        f.write_text("sensitive data")
        assert should_skip_file(f), f"{name} should be skipped"


def test_collect_files_excludes_sensitive(temp_dir):
    """Test that collect_files excludes sensitive files."""
    (temp_dir / "main.py").write_text("x = 1\n")
    (temp_dir / ".env").write_text("SECRET=abc\n")
    (temp_dir / "secrets.json").write_text('{"key": "value"}\n')
    # .pem wouldn't be collected anyway (wrong extension), but test the pattern
    (temp_dir / "server.key").write_text("-----BEGIN RSA PRIVATE KEY-----\n")

    files, skipped = collect_files(temp_dir)
    file_names = [f.name for f in files]
    assert "main.py" in file_names
    assert ".env" not in file_names
    assert "secrets.json" not in file_names
    assert "server.key" not in file_names
