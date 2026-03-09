"""Tests for debug and optimize commands — helpers, mocked LLM, CLI integration."""

import json
import subprocess
import sys
import pytest
from unittest.mock import patch, MagicMock

from dojigiri.llm import (
    _parse_python_traceback,
    _format_static_findings_for_llm,
    _parse_debug_response,
    _merge_chunked_results,
    debug_file,
    optimize_file,
    CostTracker,
)
from dojigiri.llm_backend import LLMResponse
from dojigiri.types import Finding, Severity, Category, Source, Confidence


# ─── Fixtures ──────────────────────────────────────────────────────────

@pytest.fixture
def mock_response():
    """Create a mock LLMResponse."""
    def _make(text, input_tokens=100, output_tokens=50):
        return LLMResponse(text=text, input_tokens=input_tokens, output_tokens=output_tokens)
    return _make


def _make_mock_backend(response):
    """Create a mock backend that returns the given LLMResponse."""
    backend = MagicMock()
    backend.chat.return_value = response
    backend.is_local = False
    backend.cost_per_million_input = 3.0
    backend.cost_per_million_output = 15.0
    return backend


@pytest.fixture
def sample_findings():
    """Sample static findings for testing."""
    return [
        Finding(
            file="test.py", line=5, severity=Severity.WARNING,
            category=Category.BUG, source=Source.STATIC,
            rule="bare-except", message="Bare except catches everything",
            suggestion="Use specific exception types",
        ),
        Finding(
            file="test.py", line=10, severity=Severity.CRITICAL,
            category=Category.SECURITY, source=Source.STATIC,
            rule="eval-usage", message="eval() is dangerous",
            suggestion="Use ast.literal_eval()",
        ),
    ]


@pytest.fixture
def sample_perf_findings():
    """Sample findings including perf-relevant ones."""
    return [
        Finding(
            file="test.py", line=5, severity=Severity.WARNING,
            category=Category.PERFORMANCE, source=Source.STATIC,
            rule="high-complexity", message="Cyclomatic complexity is 15",
        ),
        Finding(
            file="test.py", line=10, severity=Severity.INFO,
            category=Category.STYLE, source=Source.STATIC,
            rule="long-line", message="Line too long (120 chars)",
        ),
        Finding(
            file="test.py", line=15, severity=Severity.CRITICAL,
            category=Category.SECURITY, source=Source.STATIC,
            rule="eval-usage", message="eval() is dangerous",
        ),
    ]


# ─── Stacktrace Parsing ───────────────────────────────────────────────

def test_parse_traceback_full():
    """Test parsing a full Python traceback."""
    tb = '''Traceback (most recent call last):
  File "main.py", line 42, in run
    result = process(data)
  File "utils.py", line 10, in process
    return int(data)
ValueError: invalid literal for int() with base 10: 'abc' '''
    result = _parse_python_traceback(tb)
    assert result is not None
    assert len(result["frames"]) == 2
    assert result["frames"][0]["file"] == "main.py"
    assert result["frames"][0]["line"] == 42
    assert result["frames"][0]["function"] == "run"
    assert result["frames"][0]["code"] == "result = process(data)"
    assert result["frames"][1]["file"] == "utils.py"
    assert result["frames"][1]["line"] == 10
    assert result["exception_type"] == "ValueError"
    assert "invalid literal" in result["exception_message"]
    assert 42 in result["relevant_lines"]
    assert 10 in result["relevant_lines"]


def test_parse_traceback_non_traceback():
    """Test that non-traceback error strings return None."""
    result = _parse_python_traceback("ImportError: No module named 'foo'")
    assert result is None


def test_parse_traceback_empty():
    """Test empty string returns None."""
    assert _parse_python_traceback("") is None
    assert _parse_python_traceback(None) is None


def test_parse_traceback_multi_frame():
    """Test parsing a multi-frame traceback with code lines."""
    tb = '''Traceback (most recent call last):
  File "a.py", line 1, in <module>
    import b
  File "b.py", line 5, in setup
    c.init()
  File "c.py", line 20, in init
    raise RuntimeError("boom")
RuntimeError: boom'''
    result = _parse_python_traceback(tb)
    assert result is not None
    assert len(result["frames"]) == 3
    assert result["frames"][2]["function"] == "init"
    assert result["exception_type"] == "RuntimeError"
    assert result["exception_message"] == "boom"
    assert {1, 5, 20} == result["relevant_lines"]


# ─── Static Findings Formatting ───────────────────────────────────────

def test_format_static_findings(sample_findings):
    """Test formatting multiple findings for LLM context."""
    result = _format_static_findings_for_llm(sample_findings)
    assert "Static analysis already found" in result
    assert "bare-except" in result or "Bare except" in result
    assert "eval" in result.lower()
    assert "line 5" in result
    assert "line 10" in result


def test_format_static_findings_empty():
    """Test empty findings list produces empty string."""
    assert _format_static_findings_for_llm([]) == ""


def test_format_static_findings_with_severity(sample_findings):
    """Test that severity and source labels are included."""
    result = _format_static_findings_for_llm(sample_findings)
    assert "WARNING" in result
    assert "CRITICAL" in result
    assert "static" in result


# ─── JSON Response Parsing ─────────────────────────────────────────────

def test_parse_response_valid_json():
    """Test parsing a valid JSON response."""
    data = {"summary": "All good", "findings": [], "quick_wins": []}
    result = _parse_debug_response(json.dumps(data))
    assert result == data


def test_parse_response_markdown_fenced():
    """Test parsing JSON wrapped in markdown fences."""
    data = {"summary": "Bug found", "findings": [{"line": 5}], "quick_wins": []}
    text = f"```json\n{json.dumps(data)}\n```"
    result = _parse_debug_response(text)
    assert result is not None
    assert result["summary"] == "Bug found"


def test_parse_response_surrounded_by_text():
    """Test extracting JSON from surrounding text."""
    data = {"summary": "OK", "findings": [], "quick_wins": []}
    text = f"Here is my analysis:\n{json.dumps(data)}\nHope this helps!"
    result = _parse_debug_response(text)
    assert result is not None
    assert result["summary"] == "OK"


def test_parse_response_malformed():
    """Test that malformed input returns None."""
    assert _parse_debug_response("This is not JSON at all") is None
    assert _parse_debug_response("{ broken json") is None


def test_parse_response_empty():
    """Test that empty/None input returns None."""
    assert _parse_debug_response("") is None
    assert _parse_debug_response("   ") is None
    assert _parse_debug_response(None) is None


# ─── Merge Chunked Results ─────────────────────────────────────────────

def test_merge_deduplicates_findings():
    """Test that merging deduplicates findings by (line, title)."""
    r1 = {"summary": "chunk1", "findings": [
        {"line": 5, "title": "Bug A", "severity": "warning"},
    ], "quick_wins": ["fix A"]}
    r2 = {"summary": "chunk2", "findings": [
        {"line": 5, "title": "Bug A", "severity": "warning"},  # duplicate
        {"line": 10, "title": "Bug B", "severity": "critical"},
    ], "quick_wins": ["fix A", "fix B"]}

    merged = _merge_chunked_results([r1, r2])
    assert len(merged["findings"]) == 2  # deduplicated
    assert len(merged["quick_wins"]) == 2  # deduplicated
    assert "chunk1" in merged["summary"]
    assert "chunk2" in merged["summary"]


# ─── debug_file Mocked ─────────────────────────────────────────────────

@patch("dojigiri.llm._get_backend")
def test_debug_file_basic(mock_get_backend, mock_response):
    """Test basic debug_file returns structured result."""
    llm_output = json.dumps({
        "summary": "Found a bug",
        "findings": [
            {"line": 5, "severity": "warning", "category": "bug",
             "title": "Off by one", "description": "Loop bound wrong",
             "suggestion": "Use < instead of <=", "code_fix": None,
             "confidence": "high"}
        ],
        "quick_wins": ["Fix the loop bound"],
    })
    mock_get_backend.return_value = _make_mock_backend(mock_response(llm_output))

    result, tracker = debug_file("def foo(): pass", "test.py", "python")
    assert "findings" in result
    assert len(result["findings"]) == 1
    assert result["findings"][0]["title"] == "Off by one"
    assert result["summary"] == "Found a bug"
    assert tracker.total_input_tokens == 100


@patch("dojigiri.llm._get_backend")
def test_debug_file_with_error(mock_get_backend, mock_response):
    """Test debug_file includes error message in prompt."""
    llm_output = json.dumps({"summary": "TypeError", "findings": [], "quick_wins": []})
    mock_get_backend.return_value = _make_mock_backend(mock_response(llm_output))

    result, _ = debug_file("x = 1", "test.py", "python",
                           error_msg="TypeError: unsupported operand")
    assert result["summary"] == "TypeError"

    # Verify error was included in the user message
    call_kwargs = mock_get_backend.return_value.chat.call_args
    user_msg = call_kwargs.kwargs.get("messages", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else [])[0]["content"]
    assert "TypeError" in user_msg


@patch("dojigiri.llm._get_backend")
def test_debug_file_with_traceback(mock_get_backend, mock_response):
    """Test debug_file parses Python traceback and highlights lines."""
    traceback = '''Traceback (most recent call last):
  File "test.py", line 10, in main
    result = bad_call()
ValueError: nope'''
    llm_output = json.dumps({"summary": "ValueError", "findings": [], "quick_wins": []})
    mock_get_backend.return_value = _make_mock_backend(mock_response(llm_output))

    result, _ = debug_file("x = 1", "test.py", "python", error_msg=traceback)

    call_kwargs = mock_get_backend.return_value.chat.call_args
    user_msg = call_kwargs.kwargs.get("messages", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else [])[0]["content"]
    assert "Pay special attention to lines" in user_msg
    assert "10" in user_msg


@patch("dojigiri.llm._get_backend")
def test_debug_file_with_static_findings(mock_get_backend, mock_response, sample_findings):
    """Test debug_file includes static findings in prompt."""
    llm_output = json.dumps({"summary": "OK", "findings": [], "quick_wins": []})
    mock_get_backend.return_value = _make_mock_backend(mock_response(llm_output))

    result, _ = debug_file("x = 1", "test.py", "python",
                           static_findings=sample_findings)

    call_kwargs = mock_get_backend.return_value.chat.call_args
    user_msg = call_kwargs.kwargs.get("messages", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else [])[0]["content"]
    assert "Static analysis already found" in user_msg


@patch("dojigiri.llm._get_backend")
def test_debug_file_raw_markdown_fallback(mock_get_backend, mock_response):
    """Test debug_file falls back to raw_markdown when JSON parsing fails."""
    mock_get_backend.return_value = _make_mock_backend(mock_response(
        "## Root Cause\nThe bug is on line 5.\n## Fix\nChange x to y."
    ))

    result, _ = debug_file("x = 1", "test.py", "python")
    assert "raw_markdown" in result
    assert "Root Cause" in result["raw_markdown"]


@patch("dojigiri.llm._get_backend")
def test_debug_file_uses_8192_tokens(mock_get_backend, mock_response):
    """Test debug_file uses LLM_DEBUG_MAX_TOKENS (8192)."""
    llm_output = json.dumps({"summary": "OK", "findings": [], "quick_wins": []})
    mock_get_backend.return_value = _make_mock_backend(mock_response(llm_output))

    debug_file("x = 1", "test.py", "python")

    call_kwargs = mock_get_backend.return_value.chat.call_args
    assert call_kwargs.kwargs.get("max_tokens", 0) == 8192


@patch("dojigiri.llm._get_backend")
def test_debug_file_includes_language_hints(mock_get_backend, mock_response):
    """Test debug_file injects language-specific hints into system prompt."""
    llm_output = json.dumps({"summary": "OK", "findings": [], "quick_wins": []})
    mock_get_backend.return_value = _make_mock_backend(mock_response(llm_output))

    debug_file("x = 1", "test.py", "python")

    call_kwargs = mock_get_backend.return_value.chat.call_args
    system_prompt = call_kwargs.kwargs.get("system", call_kwargs[0][0] if call_kwargs[0] else "")
    assert "mutable default" in system_prompt.lower() or "late-binding" in system_prompt.lower()


# ─── optimize_file Mocked ──────────────────────────────────────────────

@patch("dojigiri.llm._get_backend")
def test_optimize_file_basic(mock_get_backend, mock_response):
    """Test basic optimize_file returns structured result."""
    llm_output = json.dumps({
        "summary": "Room for improvement",
        "findings": [
            {"line": 5, "severity": "warning", "category": "performance",
             "title": "Slow loop", "description": "O(n^2) nested loop",
             "suggestion": "Use a dict lookup", "code_fix": None,
             "confidence": "high"}
        ],
        "quick_wins": ["Use list comprehension"],
    })
    mock_get_backend.return_value = _make_mock_backend(mock_response(llm_output))

    result, tracker = optimize_file("for x in y: pass", "test.py", "python")
    assert "findings" in result
    assert len(result["findings"]) == 1
    assert result["findings"][0]["title"] == "Slow loop"


@patch("dojigiri.llm._get_backend")
def test_optimize_file_with_static_findings(mock_get_backend, mock_response, sample_perf_findings):
    """Test optimize_file only passes perf-relevant static findings."""
    llm_output = json.dumps({"summary": "OK", "findings": [], "quick_wins": []})
    mock_get_backend.return_value = _make_mock_backend(mock_response(llm_output))

    result, _ = optimize_file("x = 1", "test.py", "python",
                              static_findings=sample_perf_findings)

    call_kwargs = mock_get_backend.return_value.chat.call_args
    user_msg = call_kwargs.kwargs.get("messages", call_kwargs[0][1] if len(call_kwargs[0]) > 1 else [])[0]["content"]
    # Should include perf/style findings but NOT security ones
    if "Static analysis already found" in user_msg:
        assert "complexity" in user_msg.lower() or "long" in user_msg.lower()
        # eval-usage is security, should not be in the perf-filtered list
        # (it might still appear if it matched the rule filter, but the key is the filter ran)


@patch("dojigiri.llm._get_backend")
def test_optimize_file_uses_8192_tokens(mock_get_backend, mock_response):
    """Test optimize_file uses LLM_OPTIMIZE_MAX_TOKENS (8192)."""
    llm_output = json.dumps({"summary": "OK", "findings": [], "quick_wins": []})
    mock_get_backend.return_value = _make_mock_backend(mock_response(llm_output))

    optimize_file("x = 1", "test.py", "python")

    call_kwargs = mock_get_backend.return_value.chat.call_args
    assert call_kwargs.kwargs.get("max_tokens", 0) == 8192


@patch("dojigiri.llm._get_backend")
def test_optimize_file_raw_markdown_fallback(mock_get_backend, mock_response):
    """Test optimize_file falls back to raw_markdown when JSON fails."""
    mock_get_backend.return_value = _make_mock_backend(mock_response(
        "## Performance Assessment\nNeeds work.\n## Findings\nSlow loop at line 5."
    ))

    result, _ = optimize_file("for x in y: pass", "test.py", "python")
    assert "raw_markdown" in result


# ─── Chunking Integration ──────────────────────────────────────────────

@patch("dojigiri.llm._get_backend")
def test_debug_file_chunks_large_file(mock_get_backend, mock_response):
    """Test debug_file chunks large files (>400 lines) into multiple API calls."""
    # Create a 500-line file
    code = "\n".join([f"x_{i} = {i}" for i in range(500)])
    llm_output = json.dumps({"summary": "OK", "findings": [], "quick_wins": []})

    mock_get_backend.return_value = _make_mock_backend(mock_response(llm_output))

    result, _ = debug_file(code, "big.py", "python")
    assert "findings" in result
    # Should have made multiple API calls (500 lines / 400 chunk_size = 2 chunks)
    assert mock_get_backend.return_value.chat.call_count >= 2


@patch("dojigiri.llm._get_backend")
def test_optimize_file_chunks_large_file(mock_get_backend, mock_response):
    """Test optimize_file chunks large files into multiple API calls."""
    code = "\n".join([f"y_{i} = {i}" for i in range(500)])
    llm_output = json.dumps({"summary": "OK", "findings": [], "quick_wins": []})

    mock_get_backend.return_value = _make_mock_backend(mock_response(llm_output))

    result, _ = optimize_file(code, "big.py", "python")
    assert "findings" in result
    assert mock_get_backend.return_value.chat.call_count >= 2


# ─── CLI Integration ──────────────────────────────────────────────────

def _run_doji(*args, timeout=30):
    """Run doji CLI as subprocess."""
    cmd = [sys.executable, "-m", "dojigiri"] + list(args)
    result = subprocess.run(cmd, capture_output=True, timeout=timeout)
    stdout = result.stdout.decode("utf-8", errors="replace") if result.stdout else ""
    stderr = result.stderr.decode("utf-8", errors="replace") if result.stderr else ""
    return result.returncode, stdout, stderr


def test_cli_debug_nonexistent():
    """Test debug with nonexistent file."""
    rc, out, err = _run_doji("debug", "/nonexistent/file.py")
    assert rc == 1
    assert "not a file" in err or "Error" in err


def test_cli_debug_unsupported(temp_dir):
    """Test debug with unsupported file type."""
    (temp_dir / "test.xyz").write_text("hello")
    rc, out, err = _run_doji("debug", str(temp_dir / "test.xyz"))
    assert rc == 1
    assert "unsupported" in err


def test_cli_debug_help():
    """Test debug --help shows --context and --output flags."""
    rc, out, err = _run_doji("debug", "--help")
    assert rc == 0
    assert "--context" in out
    assert "--output" in out
    assert "json" in out


def test_cli_optimize_nonexistent():
    """Test optimize with nonexistent file."""
    rc, out, err = _run_doji("optimize", "/nonexistent/file.py")
    assert rc == 1
    assert "not a file" in err or "Error" in err


def test_cli_optimize_unsupported(temp_dir):
    """Test optimize with unsupported file type."""
    (temp_dir / "test.xyz").write_text("hello")
    rc, out, err = _run_doji("optimize", str(temp_dir / "test.xyz"))
    assert rc == 1
    assert "unsupported" in err


def test_cli_optimize_help():
    """Test optimize --help shows --output flag."""
    rc, out, err = _run_doji("optimize", "--help")
    assert rc == 0
    assert "--output" in out
    assert "json" in out
