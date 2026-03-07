"""Tests for config module - data structures, enums, and utilities."""

import pytest
import os
from pathlib import Path
from dojigiri.types import (
    Finding, FileAnalysis, ScanReport,
    Severity, Category, Source,
)
from dojigiri.config import (
    get_api_key, load_ignore_patterns,
    LANGUAGE_EXTENSIONS,
    _is_safe_regex, compile_custom_rules,
)


def test_severity_enum():
    """Test Severity enum values."""
    assert Severity.CRITICAL.value == "critical"
    assert Severity.WARNING.value == "warning"
    assert Severity.INFO.value == "info"


def test_category_enum():
    """Test Category enum values."""
    assert Category.BUG.value == "bug"
    assert Category.SECURITY.value == "security"
    assert Category.PERFORMANCE.value == "performance"
    assert Category.STYLE.value == "style"
    assert Category.DEAD_CODE.value == "dead_code"


def test_source_enum():
    """Test Source enum values."""
    assert Source.STATIC.value == "static"
    assert Source.AST.value == "ast"
    assert Source.LLM.value == "llm"


def test_language_extensions():
    """Test that common language extensions are mapped correctly."""
    assert LANGUAGE_EXTENSIONS[".py"] == "python"
    assert LANGUAGE_EXTENSIONS[".js"] == "javascript"
    assert LANGUAGE_EXTENSIONS[".ts"] == "typescript"
    assert LANGUAGE_EXTENSIONS[".go"] == "go"
    assert LANGUAGE_EXTENSIONS[".rs"] == "rust"
    assert LANGUAGE_EXTENSIONS[".java"] == "java"


def test_finding_creation():
    """Test Finding dataclass instantiation."""
    finding = Finding(
        file="test.py",
        line=42,
        severity=Severity.WARNING,
        category=Category.BUG,
        source=Source.STATIC,
        rule="test-rule",
        message="Test message",
        suggestion="Fix it",
        snippet="code snippet",
    )
    
    assert finding.file == "test.py"
    assert finding.line == 42
    assert finding.severity == Severity.WARNING
    assert finding.category == Category.BUG
    assert finding.source == Source.STATIC
    assert finding.rule == "test-rule"
    assert finding.message == "Test message"
    assert finding.suggestion == "Fix it"
    assert finding.snippet == "code snippet"


def test_finding_to_dict():
    """Test Finding.to_dict() serialization."""
    finding = Finding(
        file="test.py",
        line=10,
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        source=Source.AST,
        rule="security-rule",
        message="Security issue",
        suggestion="Fix now",
        snippet="bad code",
    )
    
    result = finding.to_dict()
    
    assert result["file"] == "test.py"
    assert result["line"] == 10
    assert result["severity"] == "critical"
    assert result["category"] == "security"
    assert result["source"] == "ast"
    assert result["rule"] == "security-rule"
    assert result["message"] == "Security issue"
    assert result["suggestion"] == "Fix now"
    assert result["snippet"] == "bad code"


def test_finding_optional_fields():
    """Test Finding with optional fields as None."""
    finding = Finding(
        file="test.py",
        line=1,
        severity=Severity.INFO,
        category=Category.STYLE,
        source=Source.STATIC,
        rule="style-rule",
        message="Style issue",
    )
    
    assert finding.suggestion is None
    assert finding.snippet is None
    
    result = finding.to_dict()
    assert result["suggestion"] is None
    assert result["snippet"] is None


def test_file_analysis_creation():
    """Test FileAnalysis dataclass instantiation."""
    findings = [
        Finding("test.py", 1, Severity.CRITICAL, Category.BUG, Source.STATIC, "r1", "msg1"),
        Finding("test.py", 2, Severity.WARNING, Category.BUG, Source.STATIC, "r2", "msg2"),
        Finding("test.py", 3, Severity.INFO, Category.STYLE, Source.STATIC, "r3", "msg3"),
    ]
    
    fa = FileAnalysis(
        path="test.py",
        language="python",
        lines=100,
        findings=findings,
        file_hash="abc123",
    )
    
    assert fa.path == "test.py"
    assert fa.language == "python"
    assert fa.lines == 100
    assert len(fa.findings) == 3
    assert fa.file_hash == "abc123"


def test_file_analysis_counts():
    """Test FileAnalysis severity count properties."""
    findings = [
        Finding("test.py", 1, Severity.CRITICAL, Category.BUG, Source.STATIC, "r1", "msg1"),
        Finding("test.py", 2, Severity.CRITICAL, Category.BUG, Source.STATIC, "r2", "msg2"),
        Finding("test.py", 3, Severity.WARNING, Category.BUG, Source.STATIC, "r3", "msg3"),
        Finding("test.py", 4, Severity.WARNING, Category.BUG, Source.STATIC, "r4", "msg4"),
        Finding("test.py", 5, Severity.WARNING, Category.BUG, Source.STATIC, "r5", "msg5"),
        Finding("test.py", 6, Severity.INFO, Category.STYLE, Source.STATIC, "r6", "msg6"),
    ]
    
    fa = FileAnalysis("test.py", "python", 100, findings)
    
    assert fa.critical_count == 2
    assert fa.warning_count == 3
    assert fa.info_count == 1


def test_file_analysis_empty_findings():
    """Test FileAnalysis with no findings."""
    fa = FileAnalysis("test.py", "python", 50)
    
    assert len(fa.findings) == 0
    assert fa.critical_count == 0
    assert fa.warning_count == 0
    assert fa.info_count == 0


def test_scan_report_creation():
    """Test ScanReport dataclass instantiation."""
    fa = FileAnalysis("test.py", "python", 100, [])
    
    report = ScanReport(
        root="/project",
        mode="quick",
        files_scanned=10,
        files_skipped=5,
        total_findings=25,
        critical=5,
        warnings=15,
        info=5,
        file_analyses=[fa],
        llm_cost_usd=0.25,
        timestamp="2024-01-01T00:00:00",
    )
    
    assert report.root == "/project"
    assert report.mode == "quick"
    assert report.files_scanned == 10
    assert report.files_skipped == 5
    assert report.total_findings == 25
    assert report.critical == 5
    assert report.warnings == 15
    assert report.info == 5
    assert len(report.file_analyses) == 1
    assert report.llm_cost_usd == 0.25
    assert report.timestamp == "2024-01-01T00:00:00"


def test_scan_report_to_dict():
    """Test ScanReport.to_dict() serialization."""
    finding = Finding("test.py", 1, Severity.CRITICAL, Category.BUG, Source.STATIC, "r1", "msg1")
    fa = FileAnalysis("test.py", "python", 50, [finding])
    
    report = ScanReport(
        root="/project",
        mode="deep",
        files_scanned=5,
        files_skipped=2,
        total_findings=10,
        critical=3,
        warnings=5,
        info=2,
        file_analyses=[fa],
        llm_cost_usd=1.50,
        timestamp="2024-01-01T12:00:00",
    )
    
    result = report.to_dict()
    
    assert result["root"] == "/project"
    assert result["mode"] == "deep"
    assert result["files_scanned"] == 5
    assert result["files_skipped"] == 2
    assert result["total_findings"] == 10
    assert result["critical"] == 3
    assert result["warnings"] == 5
    assert result["info"] == 2
    assert result["llm_cost_usd"] == 1.50
    assert result["timestamp"] == "2024-01-01T12:00:00"
    assert len(result["files"]) == 1
    assert result["files"][0]["path"] == "test.py"
    assert result["files"][0]["language"] == "python"
    assert result["files"][0]["lines"] == 50
    assert len(result["files"][0]["findings"]) == 1


def test_get_api_key_not_set():
    """Test get_api_key when environment variable is not set."""
    # Save original value
    original = os.environ.get("ANTHROPIC_API_KEY")
    
    # Remove env var
    if "ANTHROPIC_API_KEY" in os.environ:
        del os.environ["ANTHROPIC_API_KEY"]
    
    assert get_api_key() is None
    
    # Restore original
    if original:
        os.environ["ANTHROPIC_API_KEY"] = original


def test_get_api_key_set():
    """Test get_api_key when environment variable is set."""
    # Save original value
    original = os.environ.get("ANTHROPIC_API_KEY")
    
    # Set test value
    os.environ["ANTHROPIC_API_KEY"] = "test-key-12345"
    
    assert get_api_key() == "test-key-12345"
    
    # Restore original
    if original:
        os.environ["ANTHROPIC_API_KEY"] = original
    else:
        del os.environ["ANTHROPIC_API_KEY"]


def test_load_ignore_patterns_no_file(temp_dir):
    """Test load_ignore_patterns when .doji-ignore doesn't exist."""
    patterns = load_ignore_patterns(temp_dir)
    assert patterns == []


def test_load_ignore_patterns_with_patterns(temp_dir):
    """Test load_ignore_patterns with a .doji-ignore file."""
    wizignore = temp_dir / ".doji-ignore"
    wizignore.write_text(
        "*.log\n"
        "test_*.py\n"
        "# This is a comment\n"
        "\n"  # empty line
        "node_modules/\n"
        "*.tmp\n",
        encoding="utf-8"
    )
    
    patterns = load_ignore_patterns(temp_dir)
    
    assert "*.log" in patterns
    assert "test_*.py" in patterns
    assert "node_modules/" in patterns
    assert "*.tmp" in patterns
    # Comments and empty lines should be excluded
    assert "# This is a comment" not in patterns
    assert "" not in patterns


def test_load_ignore_patterns_whitespace_handling(temp_dir):
    """Test that load_ignore_patterns strips whitespace."""
    wizignore = temp_dir / ".doji-ignore"
    wizignore.write_text(
        "  *.log  \n"
        "\t*.tmp\t\n"
        "  # comment with spaces  \n"
        "   \n",  # line with only spaces
        encoding="utf-8"
    )
    
    patterns = load_ignore_patterns(temp_dir)
    
    assert "*.log" in patterns
    assert "*.tmp" in patterns
    assert len(patterns) == 2


def test_finding_to_dict_redacts_secret_snippet():
    """Test that Finding.to_dict() redacts snippets for secret-related rules."""
    finding = Finding(
        file="test.py",
        line=5,
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        source=Source.STATIC,
        rule="hardcoded-secret",
        message="Hardcoded secret detected",
        snippet='password = "super_secret_123"',
    )
    result = finding.to_dict()
    assert result["snippet"] == "[REDACTED]"
    # Internal snippet is still available
    assert finding.snippet == 'password = "super_secret_123"'


def test_finding_to_dict_redacts_aws_credentials():
    """Test that aws-credentials rule snippets are also redacted."""
    finding = Finding(
        file="config.py",
        line=10,
        severity=Severity.CRITICAL,
        category=Category.SECURITY,
        source=Source.STATIC,
        rule="aws-credentials",
        message="AWS credentials found",
        snippet="AKIAIOSFODNN7EXAMPLE",
    )
    result = finding.to_dict()
    assert result["snippet"] == "[REDACTED]"


def test_finding_to_dict_preserves_normal_snippet():
    """Test that non-secret findings keep their snippet intact."""
    finding = Finding(
        file="test.py",
        line=1,
        severity=Severity.WARNING,
        category=Category.BUG,
        source=Source.STATIC,
        rule="bare-except",
        message="Bare except clause",
        snippet="except:\n    pass",
    )
    result = finding.to_dict()
    assert result["snippet"] == "except:\n    pass"


def test_scan_report_default_values():
    """Test ScanReport default field values."""
    report = ScanReport(
        root="/test",
        mode="quick",
        files_scanned=1,
        files_skipped=0,
        total_findings=0,
        critical=0,
        warnings=0,
        info=0,
    )
    
    assert report.file_analyses == []
    assert report.llm_cost_usd == 0.0
    assert report.timestamp == ""


# ─── ReDoS protection tests ──────────────────────────────────────────


def test_redos_pattern_rejected():
    """Test that nested-quantifier patterns are rejected as ReDoS risk."""
    # Classic ReDoS: (a+)+ causes catastrophic backtracking
    assert _is_safe_regex("(a+)+") is False
    # Nested quantifier with * after group
    assert _is_safe_regex("(x*)*") is False


def test_safe_pattern_accepted():
    """Test that normal regex patterns pass the safety check."""
    assert _is_safe_regex(r"TODO|FIXME|HACK") is True
    assert _is_safe_regex(r"password\s*=\s*['\"]") is True
    assert _is_safe_regex(r"\beval\s*\(") is True
    # Lazy quantifiers are safe and must not be rejected
    assert _is_safe_regex(r"<.*?>" ) is True
    assert _is_safe_regex(r"\w+?") is True
    assert _is_safe_regex(r"'.*?'") is True
    # Grouped patterns with quantifiers on the group (no internal quantifier)
    assert _is_safe_regex(r"(error|warning|info)+") is True
    assert _is_safe_regex(r"(ab)+") is True


def test_redos_rejected_in_compile_custom_rules(caplog):
    """Test that compile_custom_rules skips ReDoS-prone rules."""
    config = {
        "rules": [{
            "pattern": "(a+)+",
            "name": "redos-rule",
            "message": "This is unsafe",
        }]
    }
    with caplog.at_level("WARNING", logger="dojigiri.config"):
        rules = compile_custom_rules(config)
    assert len(rules) == 0
    assert "ReDoS" in caplog.text
