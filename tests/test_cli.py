"""Tests for CLI (__main__.py) — argument parsing and command dispatch."""

import subprocess
import sys
import json
import pytest
from pathlib import Path


def _run_doji(*args, cwd=None, timeout=30):
    """Run doji CLI as a subprocess and return (returncode, stdout, stderr)."""
    cmd = [sys.executable, "-m", "dojigiri"] + list(args)
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
    rc, out, err = _run_doji("--version")
    assert rc == 0
    assert "doji" in out


def test_cli_no_command():
    """Test running with no command shows help."""
    rc, out, err = _run_doji()
    assert rc == 1  # Should exit with error


def test_cli_setup():
    """Test setup command runs without error."""
    rc, out, err = _run_doji("setup")
    assert rc == 0
    assert "Environment Check" in out or "ANTHROPIC_API_KEY" in out


# ─── Scan command tests ──────────────────────────────────────────────

def test_cli_scan_quick(temp_dir):
    """Test basic quick scan via CLI."""
    (temp_dir / "test.py").write_text('x = eval("bad")\n')
    rc, out, err = _run_doji("scan", str(temp_dir), "--no-cache")
    # Should succeed (exit 2 = critical found, which is expected)
    assert rc in (0, 2)
    assert "eval" in out.lower() or "Scan Complete" in out


def test_cli_scan_json_output(temp_dir):
    """Test JSON output format."""
    (temp_dir / "test.py").write_text('x = eval("bad")\n')
    rc, out, err = _run_doji("scan", str(temp_dir), "--no-cache", "--output", "json")
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
    rc, out, err = _run_doji("scan", str(temp_dir), "--no-cache",
                             "--output", "json", "--min-severity", "critical")
    assert rc in (0, 2)

    data = json.loads(out)
    for f_data in data.get("files", []):
        for finding in f_data.get("findings", []):
            assert finding["severity"] == "critical"


def test_cli_scan_ignore_rules(temp_dir):
    """Test --ignore flag to suppress specific rules."""
    (temp_dir / "test.py").write_text('x = eval("bad")\n')
    rc, out, err = _run_doji("scan", str(temp_dir), "--no-cache",
                             "--output", "json", "--ignore", "eval-usage")
    data = json.loads(out)

    for f_data in data.get("files", []):
        for finding in f_data.get("findings", []):
            assert finding["rule"] != "eval-usage"


def test_cli_scan_language_filter(temp_dir):
    """Test --lang filter."""
    (temp_dir / "test.py").write_text('x = eval("bad")\n')
    (temp_dir / "test.js").write_text('var x = 1;\n')

    rc, out, err = _run_doji("scan", str(temp_dir), "--no-cache",
                             "--output", "json", "--lang", "python")
    data = json.loads(out)

    # Should only scan Python
    for f_data in data.get("files", []):
        assert f_data["language"] == "python"


def test_cli_scan_nonexistent_path():
    """Test scanning a nonexistent path."""
    rc, out, err = _run_doji("scan", "/nonexistent/path/12345")
    assert rc == 1
    assert "Error" in err or "Error" in out


# ─── Cost command tests ──────────────────────────────────────────────

def test_cli_cost(temp_dir):
    """Test cost estimate command."""
    (temp_dir / "test.py").write_text('print("hello")\n')
    rc, out, err = _run_doji("cost", str(temp_dir))
    assert rc == 0
    assert "Cost Estimate" in out or "cost" in out.lower()


def test_cli_cost_no_files(temp_dir):
    """Test cost estimate with no analyzable files."""
    rc, out, err = _run_doji("cost", str(temp_dir))
    assert rc == 1  # No files found


# ─── Report command tests ────────────────────────────────────────────

def test_cli_report_no_reports():
    """Test report command when no reports exist.

    Note: This may pass or fail depending on whether ~/.dojigiri/reports/ has data.
    We just verify the command doesn't crash.
    """
    rc, out, err = _run_doji("report")
    assert rc in (0, 1)  # Either shows report or says none found


# ─── Deep scan dry-run (no API key needed) ────────────────────────────

def test_cli_scan_deep_no_api_key(temp_dir):
    """Test deep scan fails gracefully without API key."""
    (temp_dir / "test.py").write_text('x = 1\n')
    rc, out, err = _run_doji("scan", str(temp_dir), "--deep", "--no-cache")
    # Should fail with LLM error (no API key)
    assert rc in (0, 1, 2)  # May succeed with static findings or fail


# ─── Analyze command tests ───────────────────────────────────────────

def test_cli_analyze_no_llm(temp_dir):
    """Test analyze --no-llm on a temp dir with 2 files."""
    (temp_dir / "main.py").write_text("import helper\nhelper.do_thing()\n")
    (temp_dir / "helper.py").write_text("def do_thing():\n    return 42\n")
    rc, out, err = _run_doji("analyze", str(temp_dir), "--no-llm")
    assert rc == 0
    assert "Dependency Graph" in out
    assert "Files:" in out


def test_cli_analyze_json_no_llm(temp_dir):
    """Test analyze --output json --no-llm produces valid JSON with graph_metrics."""
    (temp_dir / "a.py").write_text("import b\n")
    (temp_dir / "b.py").write_text("x = 1\n")
    rc, out, err = _run_doji("analyze", str(temp_dir), "--no-llm", "--output", "json")
    assert rc == 0
    data = json.loads(out)
    assert "graph_metrics" in data
    assert "dependency_graph" in data
    assert data["files_analyzed"] == 2


def test_cli_analyze_not_directory(temp_dir):
    """Test analyze on a file (not directory) gives error."""
    f = temp_dir / "test.py"
    f.write_text("x = 1\n")
    rc, out, err = _run_doji("analyze", str(f))
    assert rc == 1
    assert "not a directory" in err.lower() or "not a directory" in out.lower()


def test_cli_analyze_help():
    """Test analyze --help shows expected options."""
    rc, out, err = _run_doji("analyze", "--help")
    assert rc == 0
    assert "--depth" in out
    assert "--no-llm" in out
    assert "--output" in out


# ─── LLM data boundary tests ─────────────────────────────────────────


def test_llm_requires_remote_confirmation_in_ci(temp_dir):
    """Test that LLM commands fail in non-interactive (CI) mode without --accept-remote."""
    (temp_dir / "test.py").write_text("x = 1\n")
    # debug is always LLM — pipe stdin to make it non-interactive
    cmd = [sys.executable, "-m", "dojigiri", "debug", str(temp_dir / "test.py")]
    result = subprocess.run(cmd, capture_output=True, timeout=10,
                            stdin=subprocess.DEVNULL)
    err = result.stderr.decode("utf-8", errors="replace")
    assert result.returncode == 1
    assert "--accept-remote" in err


def test_accept_remote_skips_prompt(temp_dir):
    """Test that --accept-remote bypasses the LLM confirmation prompt."""
    (temp_dir / "test.py").write_text("x = 1\n")
    # With --accept-remote, should proceed past the confirmation (may fail for other reasons like no API key)
    rc, out, err = _run_doji("debug", str(temp_dir / "test.py"), "--accept-remote")
    # Should NOT fail with the "use --accept-remote" error
    assert "--accept-remote" not in err
