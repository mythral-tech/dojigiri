"""Integration tests — end-to-end scan with real files in temp directories."""

import pytest
from pathlib import Path

from wiz.analyzer import scan_quick
from wiz.config import Severity, Category, Source


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

    assert "var-usage" in all_rules
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
    # JS issues
    assert "var-usage" in all_rules
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
