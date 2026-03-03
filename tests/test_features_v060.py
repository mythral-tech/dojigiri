"""Tests for Wiz v0.6.0 features: custom rules, fix verification,
parallel deep scan, pre-commit hooks."""

import os
import re
import stat
import subprocess
import sys
import tempfile
import threading
from pathlib import Path
from unittest.mock import patch, MagicMock

import pytest

from wiz.config import (
    Finding, FileAnalysis, Fix, FixReport, FixSource, FixStatus,
    Severity, Category, Source, Confidence,
    compile_custom_rules, load_project_config,
)
from wiz.detector import run_regex_checks, analyze_file_static
from wiz.llm import CostTracker


# ═══════════════════════════════════════════════════════════════════════
# Feature 2: Custom Rules — 9 tests
# ═══════════════════════════════════════════════════════════════════════

class TestCompileCustomRules:
    """Tests for compile_custom_rules()."""

    def test_compile_valid_rule(self):
        """Valid rule compiles into a tuple with correct fields."""
        config = {
            "rules": [{
                "pattern": "NOCOMMIT",
                "severity": "critical",
                "category": "bug",
                "name": "nocommit-marker",
                "message": "NOCOMMIT marker found",
            }]
        }
        rules = compile_custom_rules(config)
        assert len(rules) == 1
        pattern, severity, category, name, message, suggestion, languages = rules[0]
        assert pattern.pattern == "NOCOMMIT"
        assert severity == Severity.CRITICAL
        assert category == Category.BUG
        assert name == "nocommit-marker"
        assert message == "NOCOMMIT marker found"
        assert suggestion is None
        assert languages is None

    def test_compile_defaults(self):
        """Severity defaults to warning, category to bug."""
        config = {
            "rules": [{
                "pattern": "FIXME",
                "name": "fixme-marker",
                "message": "FIXME found",
            }]
        }
        rules = compile_custom_rules(config)
        assert len(rules) == 1
        _, severity, category, _, _, _, _ = rules[0]
        assert severity == Severity.WARNING
        assert category == Category.BUG

    def test_compile_with_languages(self):
        """Rules with languages filter compile correctly."""
        config = {
            "rules": [{
                "pattern": "debugger",
                "name": "debugger-stmt",
                "message": "debugger statement",
                "languages": ["javascript", "typescript"],
            }]
        }
        rules = compile_custom_rules(config)
        assert len(rules) == 1
        assert rules[0][6] == ["javascript", "typescript"]

    def test_compile_with_suggestion(self):
        """Rules with suggestion field compile correctly."""
        config = {
            "rules": [{
                "pattern": "TODO",
                "name": "todo-custom",
                "message": "TODO found",
                "suggestion": "Resolve before merging",
            }]
        }
        rules = compile_custom_rules(config)
        assert rules[0][5] == "Resolve before merging"

    def test_invalid_regex_skipped(self, capsys):
        """Rules with invalid regex are skipped with warning."""
        config = {
            "rules": [{
                "pattern": "[invalid",
                "name": "bad-rule",
                "message": "Bad regex",
            }]
        }
        rules = compile_custom_rules(config)
        assert len(rules) == 0
        captured = capsys.readouterr()
        assert "invalid regex" in captured.err

    def test_missing_required_fields_skipped(self, capsys):
        """Rules missing required fields are skipped."""
        config = {
            "rules": [
                {"pattern": "X"},  # missing name and message
                {"name": "y", "message": "Y"},  # missing pattern
            ]
        }
        rules = compile_custom_rules(config)
        assert len(rules) == 0

    def test_invalid_severity_skipped(self, capsys):
        """Rules with invalid severity are skipped."""
        config = {
            "rules": [{
                "pattern": "X",
                "name": "x",
                "message": "X",
                "severity": "fatal",
            }]
        }
        rules = compile_custom_rules(config)
        assert len(rules) == 0

    def test_empty_rules_list(self):
        """Empty rules list returns empty."""
        assert compile_custom_rules({}) == []
        assert compile_custom_rules({"rules": []}) == []

    def test_custom_rule_detection(self):
        """Custom rule fires during static analysis."""
        config = {
            "rules": [{
                "pattern": "NOCOMMIT",
                "severity": "critical",
                "category": "bug",
                "name": "nocommit-marker",
                "message": "NOCOMMIT marker found",
            }]
        }
        custom_rules = compile_custom_rules(config)
        code = "x = 1  # NOCOMMIT\ny = 2\n"
        findings = run_regex_checks(code, "test.py", "python", custom_rules=custom_rules)
        nocommit = [f for f in findings if f.rule == "nocommit-marker"]
        assert len(nocommit) == 1
        assert nocommit[0].line == 1
        assert nocommit[0].severity == Severity.CRITICAL


class TestCustomRulesCoexistence:
    """Custom rules should work alongside builtin rules."""

    def test_custom_and_builtin_both_fire(self):
        """Both custom and builtin rules fire on the same file."""
        custom_rules = compile_custom_rules({
            "rules": [{
                "pattern": "MARKER",
                "name": "custom-marker",
                "message": "Custom marker",
            }]
        })
        # Code with both a builtin issue (eval) and custom marker
        code = "x = eval('1+1')  # MARKER\n"
        findings = analyze_file_static("test.py", code, "python", custom_rules=custom_rules)
        rules_found = {f.rule for f in findings}
        assert "custom-marker" in rules_found
        assert "eval-usage" in rules_found

    def test_language_filter_respected(self):
        """Custom rule with languages=['python'] doesn't fire on JavaScript."""
        custom_rules = compile_custom_rules({
            "rules": [{
                "pattern": "PYONLY",
                "name": "py-rule",
                "message": "Python only",
                "languages": ["python"],
            }]
        })
        code = "// PYONLY marker\n"
        findings = run_regex_checks(code, "test.js", "javascript", custom_rules=custom_rules)
        assert all(f.rule != "py-rule" for f in findings)


# ═══════════════════════════════════════════════════════════════════════
# Feature 4: Fix Verification — 7 tests
# ═══════════════════════════════════════════════════════════════════════

class TestFixVerification:
    """Tests for verify_fixes() and verification integration."""

    def test_no_new_issues(self, tmp_path):
        """File with fixed issue shows resolved count and no new issues."""
        from wiz.fixer import verify_fixes

        filepath = tmp_path / "test.py"
        filepath.write_text("x = 1\nprint(x)\n", encoding="utf-8")

        pre_findings = [Finding(
            file=str(filepath), line=1, severity=Severity.WARNING,
            category=Category.BUG, source=Source.STATIC,
            rule="some-rule", message="Some issue",
        )]

        result = verify_fixes(str(filepath), "python", pre_findings)
        assert result["new_issues"] == 0
        assert isinstance(result["resolved"], int)
        assert "error" not in result

    def test_detects_new_issue(self, tmp_path):
        """File that introduces a new issue is detected."""
        from wiz.fixer import verify_fixes

        filepath = tmp_path / "test.py"
        # Write code that has a known issue (eval)
        filepath.write_text("x = eval('1+1')\n", encoding="utf-8")

        # Pre-findings: only had a different issue
        pre_findings = [Finding(
            file=str(filepath), line=50, severity=Severity.WARNING,
            category=Category.DEAD_CODE, source=Source.AST,
            rule="unused-import", message="Unused import",
        )]

        result = verify_fixes(str(filepath), "python", pre_findings)
        assert result["new_issues"] > 0

    def test_counts_resolved(self, tmp_path):
        """Pre-findings that no longer appear are counted as resolved."""
        from wiz.fixer import verify_fixes

        filepath = tmp_path / "clean.py"
        filepath.write_text("x = 1\n", encoding="utf-8")

        pre_findings = [
            Finding(file=str(filepath), line=1, severity=Severity.WARNING,
                    category=Category.BUG, source=Source.STATIC,
                    rule="fake-issue", message="Fake"),
            Finding(file=str(filepath), line=10, severity=Severity.WARNING,
                    category=Category.BUG, source=Source.STATIC,
                    rule="another-fake", message="Another"),
        ]

        result = verify_fixes(str(filepath), "python", pre_findings)
        assert result["resolved"] == 2

    def test_unreadable_file(self, tmp_path):
        """Verify handles unreadable file gracefully."""
        from wiz.fixer import verify_fixes

        result = verify_fixes("/nonexistent/file.py", "python", [])
        assert "error" in result

    def test_dry_run_skips_verification(self, tmp_path):
        """Dry-run mode should not produce verification."""
        from wiz.fixer import fix_file as fixer_fix_file

        filepath = tmp_path / "test.py"
        filepath.write_text("import unused_mod\nx = 1\n", encoding="utf-8")

        findings = analyze_file_static(str(filepath),
                                       filepath.read_text(encoding="utf-8"), "python")

        report = fixer_fix_file(
            str(filepath), filepath.read_text(encoding="utf-8"), "python",
            findings, dry_run=True,
        )
        assert report.verification is None

    def test_report_serialization(self):
        """FixReport with verification serializes correctly."""
        report = FixReport(
            root="test.py", files_fixed=1, total_fixes=1,
            applied=1, skipped=0, failed=0,
            verification={"resolved": 2, "remaining": 0, "new_issues": 0, "new_findings": []},
        )
        d = report.to_dict()
        assert "verification" in d
        assert d["verification"]["resolved"] == 2

    def test_report_without_verification(self):
        """FixReport without verification omits field from dict."""
        report = FixReport(
            root="test.py", files_fixed=0, total_fixes=0,
            applied=0, skipped=0, failed=0,
        )
        d = report.to_dict()
        assert "verification" not in d


# ═══════════════════════════════════════════════════════════════════════
# Feature 1: Parallel Deep Scan — 5 tests
# ═══════════════════════════════════════════════════════════════════════

class TestCostTrackerThreadSafety:
    """Tests for thread-safe CostTracker."""

    def test_add_is_thread_safe(self):
        """Concurrent add() calls produce correct totals."""
        tracker = CostTracker()
        threads = []

        def add_tokens():
            for _ in range(1000):
                tracker.add(10, 5)

        for _ in range(10):
            t = threading.Thread(target=add_tokens)
            threads.append(t)
            t.start()

        for t in threads:
            t.join()

        assert tracker.total_input_tokens == 100_000  # 10 threads * 1000 * 10
        assert tracker.total_output_tokens == 50_000   # 10 threads * 1000 * 5

    def test_total_cost_consistent(self):
        """total_cost is consistent after concurrent adds."""
        tracker = CostTracker()
        tracker.add(1_000_000, 500_000)
        expected = (1_000_000 / 1_000_000) * 3.0 + (500_000 / 1_000_000) * 15.0
        assert abs(tracker.total_cost - expected) < 0.001

    def test_has_lock_attribute(self):
        """CostTracker has a threading lock."""
        tracker = CostTracker()
        assert hasattr(tracker, '_lock')
        assert isinstance(tracker._lock, type(threading.Lock()))


class TestParallelDeepScan:
    """Tests for scan_deep max_workers parameter."""

    def test_scan_deep_accepts_max_workers(self):
        """scan_deep() accepts max_workers parameter."""
        import inspect
        from wiz.analyzer import scan_deep
        sig = inspect.signature(scan_deep)
        assert "max_workers" in sig.parameters

    def test_scan_deep_sequential_fallback(self, tmp_path):
        """scan_deep with max_workers=1 works (sequential mode)."""
        from wiz.analyzer import scan_deep
        test_file = tmp_path / "test.py"
        test_file.write_text("x = 1\n", encoding="utf-8")

        # Mock the LLM to avoid actual API calls
        with patch("wiz.analyzer.analyze_chunk", return_value=[]):
            with patch("wiz.analyzer.chunk_file", return_value=[]):
                report = scan_deep(tmp_path, max_workers=1, use_cache=False)
                assert report.files_scanned >= 0


# ═══════════════════════════════════════════════════════════════════════
# Feature 3: Pre-commit Hook — 10 tests
# ═══════════════════════════════════════════════════════════════════════

class TestHookInstall:
    """Tests for hook install/uninstall."""

    @pytest.fixture
    def git_repo(self, tmp_path):
        """Create a minimal git repo."""
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)
        return tmp_path

    def test_install_creates_hook(self, git_repo):
        """install_hook creates pre-commit file."""
        from wiz.hooks import install_hook, HOOK_MARKER
        msg = install_hook(git_repo)
        hook = git_repo / ".git" / "hooks" / "pre-commit"
        assert hook.exists()
        content = hook.read_text(encoding="utf-8")
        assert HOOK_MARKER in content
        assert "Installed" in msg

    def test_install_idempotent(self, git_repo):
        """Installing twice updates existing hook."""
        from wiz.hooks import install_hook
        install_hook(git_repo)
        msg = install_hook(git_repo)
        assert "Updated" in msg

    def test_uninstall_removes_hook(self, git_repo):
        """uninstall_hook removes wiz hook."""
        from wiz.hooks import install_hook, uninstall_hook
        install_hook(git_repo)
        msg = uninstall_hook(git_repo)
        hook = git_repo / ".git" / "hooks" / "pre-commit"
        assert not hook.exists()
        assert "Removed" in msg

    def test_uninstall_no_hook(self, git_repo):
        """uninstall_hook raises FileNotFoundError when no hook exists."""
        from wiz.hooks import uninstall_hook
        with pytest.raises(FileNotFoundError):
            uninstall_hook(git_repo)

    def test_foreign_hook_blocked(self, git_repo):
        """install_hook refuses to overwrite foreign hook without --force."""
        from wiz.hooks import install_hook
        hook = git_repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho foreign\n", encoding="utf-8")
        with pytest.raises(FileExistsError):
            install_hook(git_repo, force=False)

    def test_force_overwrites_foreign(self, git_repo):
        """install_hook with force=True overwrites foreign hook."""
        from wiz.hooks import install_hook, HOOK_MARKER
        hook = git_repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho foreign\n", encoding="utf-8")
        install_hook(git_repo, force=True)
        content = hook.read_text(encoding="utf-8")
        assert HOOK_MARKER in content

    def test_uninstall_refuses_foreign(self, git_repo):
        """uninstall_hook refuses to remove foreign hook."""
        from wiz.hooks import uninstall_hook
        hook = git_repo / ".git" / "hooks" / "pre-commit"
        hook.write_text("#!/bin/sh\necho foreign\n", encoding="utf-8")
        with pytest.raises(PermissionError):
            uninstall_hook(git_repo)

    def test_not_git_repo(self, tmp_path):
        """install_hook raises FileNotFoundError for non-git directory."""
        from wiz.hooks import install_hook
        with pytest.raises(FileNotFoundError):
            install_hook(tmp_path)

    def test_hook_script_content(self, git_repo):
        """Hook script contains wiz scan command."""
        from wiz.hooks import install_hook
        install_hook(git_repo)
        hook = git_repo / ".git" / "hooks" / "pre-commit"
        content = hook.read_text(encoding="utf-8")
        assert "wiz scan" in content
        assert "--diff" in content

    def test_hook_is_executable(self, git_repo):
        """Hook file has executable permission on Unix."""
        from wiz.hooks import install_hook
        install_hook(git_repo)
        hook = git_repo / ".git" / "hooks" / "pre-commit"
        if sys.platform != "win32":
            assert hook.stat().st_mode & stat.S_IEXEC


class TestHookCLI:
    """Tests for 'wiz hook' CLI subcommand."""

    def test_hook_install_cli(self, tmp_path):
        """CLI 'hook install' command works."""
        # Create git repo
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        result = subprocess.run(
            [sys.executable, "-m", "wiz", "hook", "install"],
            capture_output=True, text=True, cwd=str(tmp_path),
        )
        assert result.returncode == 0
        assert "Installed" in result.stdout

    def test_hook_uninstall_cli(self, tmp_path):
        """CLI 'hook uninstall' command works."""
        git_dir = tmp_path / ".git" / "hooks"
        git_dir.mkdir(parents=True)

        # Install first
        subprocess.run(
            [sys.executable, "-m", "wiz", "hook", "install"],
            capture_output=True, text=True, cwd=str(tmp_path),
        )
        # Then uninstall
        result = subprocess.run(
            [sys.executable, "-m", "wiz", "hook", "uninstall"],
            capture_output=True, text=True, cwd=str(tmp_path),
        )
        assert result.returncode == 0
        assert "Removed" in result.stdout


# ═══════════════════════════════════════════════════════════════════════
# Integration: Custom Rules with TOML config
# ═══════════════════════════════════════════════════════════════════════

class TestCustomRulesToml:
    """End-to-end test: load from .wiz.toml, detect custom rule."""

    def test_e2e_toml_custom_rule(self, tmp_path):
        """Load custom rule from .wiz.toml and detect it in a file."""
        toml_content = '''\
[wiz]

[[wiz.rules]]
pattern = "NOCOMMIT"
severity = "critical"
category = "bug"
name = "nocommit-marker"
message = "NOCOMMIT marker found"
'''
        (tmp_path / ".wiz.toml").write_text(toml_content, encoding="utf-8")

        py_file = tmp_path / "test.py"
        py_file.write_text("x = 1  # NOCOMMIT\n", encoding="utf-8")

        config = load_project_config(tmp_path)
        custom_rules = compile_custom_rules(config)
        assert len(custom_rules) == 1

        findings = analyze_file_static(
            str(py_file), py_file.read_text(encoding="utf-8"), "python",
            custom_rules=custom_rules,
        )
        nocommit = [f for f in findings if f.rule == "nocommit-marker"]
        assert len(nocommit) == 1
        assert nocommit[0].severity == Severity.CRITICAL
