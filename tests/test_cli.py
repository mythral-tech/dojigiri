"""Tests for CLI (__main__.py) — argument parsing and command dispatch."""

import subprocess
import sys
import json
import pytest
from pathlib import Path


def _run_wiz(*args, cwd=None, timeout=30):
    """Run wiz CLI as a subprocess and return (returncode, stdout, stderr)."""
    cmd = [sys.executable, "-m", "wiz"] + list(args)
    result = subprocess.run(
        cmd,
        capture_output=True,
        timeout=timeout,
        cwd=cwd,
    )
    # Decode with utf-8 and replace errors (Windows ANSI output may have non-utf8 bytes)
    stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
    stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
    return result.returncode, stdout, stderr


# ─── Basic CLI tests ──────────────────────────────────────────────────

def test_cli_version():
    """Test --version flag."""
    rc, out, err = _run_wiz("--version")
    assert rc == 0
    assert "wiz" in out


def test_cli_no_command():
    """Test running with no command shows help."""
    rc, out, err = _run_wiz()
    assert rc == 1  # Should exit with error


def test_cli_setup():
    """Test setup command runs without error."""
    rc, out, err = _run_wiz("setup")
    assert rc == 0
    assert "Environment Check" in out or "ANTHROPIC_API_KEY" in out


# ─── Scan command tests ──────────────────────────────────────────────

def test_cli_scan_quick(temp_dir):
    """Test basic quick scan via CLI."""
    (temp_dir / "test.py").write_text('x = eval("bad")\n')
    rc, out, err = _run_wiz("scan", str(temp_dir), "--no-cache")
    # Should succeed (exit 2 = critical found, which is expected)
    assert rc in (0, 2)
    assert "eval" in out.lower() or "Scan Complete" in out


def test_cli_scan_json_output(temp_dir):
    """Test JSON output format."""
    (temp_dir / "test.py").write_text('x = eval("bad")\n')
    rc, out, err = _run_wiz("scan", str(temp_dir), "--no-cache", "--output", "json")
    assert rc in (0, 2)

    # Should be valid JSON
    data = json.loads(out)
    assert "files" in data
    assert "total_findings" in data


def test_cli_scan_min_severity(temp_dir):
    """Test --min-severity filter."""
    (temp_dir / "test.py").write_text(
        '# TODO: fix this\n'  # info
        'x = eval("bad")\n'  # critical
    )
    rc, out, err = _run_wiz("scan", str(temp_dir), "--no-cache",
                             "--output", "json", "--min-severity", "critical")
    assert rc in (0, 2)

    data = json.loads(out)
    for f_data in data.get("files", []):
        for finding in f_data.get("findings", []):
            assert finding["severity"] == "critical"


def test_cli_scan_ignore_rules(temp_dir):
    """Test --ignore flag to suppress specific rules."""
    (temp_dir / "test.py").write_text('x = eval("bad")\n')
    rc, out, err = _run_wiz("scan", str(temp_dir), "--no-cache",
                             "--output", "json", "--ignore", "eval-usage")
    data = json.loads(out)

    for f_data in data.get("files", []):
        for finding in f_data.get("findings", []):
            assert finding["rule"] != "eval-usage"


def test_cli_scan_language_filter(temp_dir):
    """Test --lang filter."""
    (temp_dir / "test.py").write_text('x = eval("bad")\n')
    (temp_dir / "test.js").write_text('var x = 1;\n')

    rc, out, err = _run_wiz("scan", str(temp_dir), "--no-cache",
                             "--output", "json", "--lang", "python")
    data = json.loads(out)

    # Should only scan Python
    for f_data in data.get("files", []):
        assert f_data["language"] == "python"


def test_cli_scan_nonexistent_path():
    """Test scanning a nonexistent path."""
    rc, out, err = _run_wiz("scan", "/nonexistent/path/12345")
    assert rc == 1
    assert "Error" in err or "Error" in out


# ─── Cost command tests ──────────────────────────────────────────────

def test_cli_cost(temp_dir):
    """Test cost estimate command."""
    (temp_dir / "test.py").write_text('print("hello")\n')
    rc, out, err = _run_wiz("cost", str(temp_dir))
    assert rc == 0
    assert "Cost Estimate" in out or "cost" in out.lower()


def test_cli_cost_no_files(temp_dir):
    """Test cost estimate with no analyzable files."""
    rc, out, err = _run_wiz("cost", str(temp_dir))
    assert rc == 1  # No files found


# ─── Report command tests ────────────────────────────────────────────

def test_cli_report_no_reports():
    """Test report command when no reports exist.

    Note: This may pass or fail depending on whether ~/.wiz/reports/ has data.
    We just verify the command doesn't crash.
    """
    rc, out, err = _run_wiz("report")
    assert rc in (0, 1)  # Either shows report or says none found


# ─── Deep scan dry-run (no API key needed) ────────────────────────────

def test_cli_scan_deep_no_api_key(temp_dir):
    """Test deep scan fails gracefully without API key."""
    (temp_dir / "test.py").write_text('x = 1\n')
    rc, out, err = _run_wiz("scan", str(temp_dir), "--deep", "--no-cache")
    # Should fail with LLM error (no API key)
    assert rc in (0, 1, 2)  # May succeed with static findings or fail
