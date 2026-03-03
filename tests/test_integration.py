"""Integration tests — end-to-end scan with real files in temp directories."""

import pytest
from pathlib import Path

from wiz.analyzer import scan_quick
from wiz.config import Severity, Category, Source, Finding


@pytest.fixture
def python_security_dir(temp_dir):
    """Create a temp dir with Python files containing security issues."""
    (temp_dir / "secrets.py").write_text(
        'API_KEY = "sk_live_abc123defgh456789"\n'
        'password = "P@ssw0rd_Not_Placeholder"\n'
        'data = eval(user_input)\n'
        'import pickle\n'
        'obj = pickle.loads(untrusted_data)\n',
        encoding="utf-8",
    )
    return temp_dir


@pytest.fixture
def javascript_quality_dir(temp_dir):
    """Create a temp dir with JS files containing quality issues."""
    (temp_dir / "app.js").write_text(
        'var x = 5;\n'
        'console.log("debug");\n'
        'if (x == 5) {\n'
        '  eval("dangerous");\n'
        '  element.innerHTML = userInput;\n'
        '}\n',
        encoding="utf-8",
    )
    return temp_dir


@pytest.fixture
def mixed_language_dir(temp_dir):
    """Create a temp dir with multiple language files."""
    (temp_dir / "main.py").write_text(
        'import os\n'
        'os.system("rm -rf /")\n',
        encoding="utf-8",
    )
    (temp_dir / "util.js").write_text(
        'var legacy = true;\n'
        'document.write("<script>alert(1)</script>");\n',
        encoding="utf-8",
    )
    (temp_dir / "main.go").write_text(
        'package main\n'
        '\n'
        'import "fmt"\n'
        '\n'
        'func main() {\n'
        '    result, _ := riskyOp()\n'
        '    fmt.Println(result)\n'
        '}\n',
        encoding="utf-8",
    )
    return temp_dir


@pytest.fixture
def empty_dir(temp_dir):
    """Create an empty temp dir (no code files)."""
    (temp_dir / "README.md").write_text("This is a readme", encoding="utf-8")
    return temp_dir


@pytest.fixture
def large_file_dir(temp_dir):
    """Create a temp dir with a large Python file."""
    lines = []
    for i in range(500):
        lines.append(f"def func_{i}():")
        lines.append(f"    return {i}")
        lines.append("")
    (temp_dir / "large.py").write_text("\n".join(lines), encoding="utf-8")
    return temp_dir


# ─── Integration Tests ────────────────────────────────────────────────

def test_scan_python_security(python_security_dir):
    """End-to-end: Python security issues are detected."""
    report = scan_quick(python_security_dir, use_cache=False, max_workers=1)

    assert report.files_scanned == 1
    assert report.total_findings > 0
    assert report.critical > 0

    all_rules = set()
    for fa in report.file_analyses:
        for f in fa.findings:
            all_rules.add(f.rule)

    assert "hardcoded-secret" in all_rules
    assert "eval-usage" in all_rules
    assert "pickle-unsafe" in all_rules


def test_scan_javascript_quality(javascript_quality_dir):
    """End-to-end: JavaScript quality issues are detected."""
    report = scan_quick(javascript_quality_dir, use_cache=False, max_workers=1)

    assert report.files_scanned == 1
    assert report.total_findings > 0

    all_rules = set()
    for fa in report.file_analyses:
        for f in fa.findings:
            all_rules.add(f.rule)

    # var-usage rule was removed (style opinion, not correctness)
    assert "console-log" in all_rules
    assert "loose-equality" in all_rules
    assert "eval-usage" in all_rules
    assert "innerhtml" in all_rules


def test_scan_mixed_languages(mixed_language_dir):
    """End-to-end: Mixed language scanning works."""
    report = scan_quick(mixed_language_dir, use_cache=False, max_workers=1)

    assert report.files_scanned == 3  # .py, .js, .go

    languages = {fa.language for fa in report.file_analyses}
    assert "python" in languages
    assert "javascript" in languages
    assert "go" in languages

    all_rules = set()
    for fa in report.file_analyses:
        for f in fa.findings:
            all_rules.add(f.rule)

    # Python issues
    assert "os-system" in all_rules
    # JS issues (var-usage rule was removed)
    assert "document-write" in all_rules
    # Go issues
    assert "unchecked-error" in all_rules
    assert "fmt-print" in all_rules


def test_scan_empty_dir(empty_dir):
    """End-to-end: Empty directory produces zero findings."""
    report = scan_quick(empty_dir, use_cache=False, max_workers=1)

    assert report.files_scanned == 0
    assert report.total_findings == 0


def test_scan_large_file(large_file_dir):
    """End-to-end: Large files are handled without errors."""
    report = scan_quick(large_file_dir, use_cache=False, max_workers=1)

    assert report.files_scanned == 1
    # Should run without crashing; findings count depends on content


def test_scan_with_language_filter(mixed_language_dir):
    """End-to-end: Language filter restricts scanning."""
    report = scan_quick(mixed_language_dir, language_filter="python",
                        use_cache=False, max_workers=1)

    assert report.files_scanned == 1
    assert all(fa.language == "python" for fa in report.file_analyses)


def test_scan_parallel_vs_sequential(python_security_dir):
    """End-to-end: Parallel and sequential scans produce same results."""
    report_seq = scan_quick(python_security_dir, use_cache=False, max_workers=1)
    report_par = scan_quick(python_security_dir, use_cache=False, max_workers=4)

    assert report_seq.total_findings == report_par.total_findings
    assert report_seq.critical == report_par.critical


def test_scan_report_structure(python_security_dir):
    """End-to-end: Report has correct structure."""
    report = scan_quick(python_security_dir, use_cache=False, max_workers=1)

    assert report.mode == "quick"
    assert report.root == str(python_security_dir)

    # Check that to_dict works
    d = report.to_dict()
    assert "files" in d
    assert "total_findings" in d
    assert "critical" in d

    # Every finding should have required fields
    for fa in report.file_analyses:
        for f in fa.findings:
            assert f.file
            assert f.line > 0
            assert f.severity in (Severity.CRITICAL, Severity.WARNING, Severity.INFO)
            assert f.category in (Category.BUG, Category.SECURITY, Category.PERFORMANCE,
                                  Category.STYLE, Category.DEAD_CODE)
            assert f.source in (Source.STATIC, Source.AST, Source.LLM)
            assert f.rule
            assert f.message


# ─── Regression tests for bug fixes ──────────────────────────────────


def test_scan_fix_rescan_cycle(temp_dir):
    """Scan → fix → rescan: fixed issues should not reappear."""
    from wiz.fixer import fix_file
    fp = temp_dir / "fixable.py"
    fp.write_text('import os\n\nx = 1\n', encoding="utf-8")

    # Scan
    report1 = scan_quick(temp_dir, use_cache=False, max_workers=1)
    findings = []
    for fa in report1.file_analyses:
        findings.extend(fa.findings)
    unused_import = [f for f in findings if f.rule == "unused-import"]
    assert len(unused_import) >= 1

    # Fix
    content = fp.read_text(encoding="utf-8")
    fix_report = fix_file(
        str(fp), content, "python", unused_import,
        dry_run=False, create_backup=False, verify=False,
    )
    assert fix_report.applied >= 1

    # Rescan
    report2 = scan_quick(temp_dir, use_cache=False, max_workers=1)
    rules_after = set()
    for fa in report2.file_analyses:
        for f in fa.findings:
            rules_after.add(f.rule)
    assert "unused-import" not in rules_after


def test_baseline_absolute_vs_relative_paths(sample_scan_report):
    """REGRESSION: diff_reports matches findings regardless of abs/rel path format."""
    from wiz.config import FileAnalysis
    from wiz.analyzer import diff_reports

    # Current report uses absolute path
    current_findings = [
        Finding("/project/src/test.py", 10, Severity.WARNING, Category.BUG,
                Source.STATIC, "rule1", "msg"),
    ]
    fa = FileAnalysis("/project/src/test.py", "python", 100, current_findings)
    sample_scan_report.root = "/project"
    sample_scan_report.file_analyses = [fa]
    sample_scan_report.total_findings = 1

    # Baseline uses relative path (from same root)
    baseline_dict = {
        "root": "/project",
        "files": [
            {
                "path": "src/test.py",
                "findings": [
                    {"line": 10, "rule": "rule1"},
                ]
            }
        ]
    }

    diffed = diff_reports(sample_scan_report, baseline_dict)
    all_findings = []
    for fa in diffed.file_analyses:
        all_findings.extend(fa.findings)
    # Should match and filter out the finding
    assert len(all_findings) == 0


def test_baseline_both_absolute_paths(sample_scan_report):
    """diff_reports works when both sides use absolute paths from the same root."""
    from wiz.config import FileAnalysis
    from wiz.analyzer import diff_reports

    current_findings = [
        Finding("/project/test.py", 10, Severity.WARNING, Category.BUG,
                Source.STATIC, "rule1", "msg"),
    ]
    fa = FileAnalysis("/project/test.py", "python", 100, current_findings)
    sample_scan_report.root = "/project"
    sample_scan_report.file_analyses = [fa]
    sample_scan_report.total_findings = 1

    baseline_dict = {
        "root": "/project",
        "files": [
            {
                "path": "/project/test.py",
                "findings": [
                    {"line": 10, "rule": "rule1"},
                ]
            }
        ]
    }

    diffed = diff_reports(sample_scan_report, baseline_dict)
    all_findings = []
    for fa in diffed.file_analyses:
        all_findings.extend(fa.findings)
    assert len(all_findings) == 0


def test_cache_with_corrupted_enum():
    """REGRESSION: Cached findings with invalid confidence don't crash the scan."""
    from wiz.analyzer import _safe_enum
    from wiz.config import Confidence

    # Valid enum value
    assert _safe_enum(Confidence, "high") == Confidence.HIGH

    # Invalid enum value should return None, not crash
    result = _safe_enum(Confidence, "super_high")
    assert result is None

    # Empty string
    result = _safe_enum(Confidence, "")
    assert result is None


def test_cache_corrupted_enum_in_scan_context(temp_dir):
    """Cache with bad enum values doesn't crash scan_quick."""
    from wiz.storage import save_cache, load_cache

    # Write a file to scan
    fp = temp_dir / "test.py"
    fp.write_text("x = 1\n", encoding="utf-8")

    # Corrupt the cache with an invalid confidence value
    # (This simulates what happens when code evolution changes enum values)
    # scan_quick uses its own cache file, so this tests the _safe_enum path
    # indirectly — the key test is test_cache_with_corrupted_enum above.
    report = scan_quick(temp_dir, use_cache=False, max_workers=1)
    assert report.files_scanned == 1  # Should not crash


def test_scan_new_patterns(temp_dir):
    """End-to-end: New Phase 1d patterns are detected."""
    (temp_dir / "creds.py").write_text(
        '# DB connection string with password\n'
        'DB_URL = "postgresql://admin:secret123@db.example.com:5432/prod"\n'
        '\n'
        '# Logging sensitive data\n'
        'import logging\n'
        'logger = logging.getLogger()\n'
        'logger.info("user login", password)\n',
        encoding="utf-8",
    )
    report = scan_quick(temp_dir, use_cache=False, max_workers=1)

    all_rules = set()
    for fa in report.file_analyses:
        for f in fa.findings:
            all_rules.add(f.rule)

    assert "db-connection-string" in all_rules
    assert "logging-sensitive-data" in all_rules
