"""Tests for llm module — mocked Anthropic client, JSON recovery, cost tracking."""

import json
import pytest
from unittest.mock import patch, MagicMock

from wiz.llm import (
    analyze_chunk,
    _recover_truncated_json,
    CostTracker,
    LLMError,
    _api_call_with_retry,
)
from wiz.chunker import Chunk
from wiz.config import Severity, Category, Source, Confidence


# ─── Fixtures ─────────────────────────────────────────────────────────

@pytest.fixture
def sample_chunk():
    """Create a sample code chunk for testing."""
    return Chunk(
        content='def hello():\n    print("world")',
        start_line=1,
        end_line=2,
        chunk_index=0,
        total_chunks=1,
        filepath="test.py",
        language="python",
    )


@pytest.fixture
def mock_response():
    """Create a mock Anthropic API response."""
    def _make(text, input_tokens=100, output_tokens=50):
        resp = MagicMock()
        resp.content = [MagicMock(text=text)]
        resp.usage.input_tokens = input_tokens
        resp.usage.output_tokens = output_tokens
        return resp
    return _make


# ─── CostTracker ──────────────────────────────────────────────────────

def test_cost_tracker_initial():
    """Test CostTracker starts at zero."""
    ct = CostTracker()
    assert ct.total_input_tokens == 0
    assert ct.total_output_tokens == 0
    assert ct.total_cost == 0.0


def test_cost_tracker_accumulates():
    """Test CostTracker accumulates across multiple calls."""
    ct = CostTracker()
    ct.add(1000, 200)
    ct.add(500, 100)
    assert ct.total_input_tokens == 1500
    assert ct.total_output_tokens == 300
    assert ct.total_cost > 0


def test_cost_tracker_cost_formula():
    """Test CostTracker uses correct cost formula."""
    ct = CostTracker()
    ct.add(1_000_000, 1_000_000)
    # Input: 1M * $3/M = $3; Output: 1M * $15/M = $15
    assert ct.total_cost == pytest.approx(18.0)


# ─── JSON Recovery ────────────────────────────────────────────────────

def test_recover_valid_json():
    """Test recovery of valid truncated JSON array."""
    text = '[{"line": 1, "rule": "test"}, {"line": 2, "rule": "test2"'
    result = _recover_truncated_json(text)
    assert result is not None
    assert len(result) == 1  # Only first complete object recovered
    assert result[0]["line"] == 1


def test_recover_truncated_json_array():
    """Test recovery when array is cut mid-object."""
    complete = json.dumps([
        {"line": 1, "severity": "warning", "rule": "r1", "message": "m1"},
        {"line": 5, "severity": "info", "rule": "r2", "message": "m2"},
    ])
    # Truncate in the middle of the second object
    truncated = complete[:complete.rfind('"m2"')]
    result = _recover_truncated_json(truncated)
    assert result is not None
    assert len(result) == 1  # Only first object recovered


def test_recover_empty_array():
    """Test recovery returns None for empty truncated array."""
    result = _recover_truncated_json("[")
    assert result is None


def test_recover_not_array():
    """Test recovery returns None for non-array JSON."""
    result = _recover_truncated_json('{"key": "value"}')
    assert result is None


def test_recover_complete_array():
    """Test that a complete array is returned as-is."""
    text = '[{"line": 1, "rule": "test"}]'
    result = _recover_truncated_json(text)
    assert result is not None
    assert len(result) == 1


def test_recover_no_complete_objects():
    """Test recovery returns None when no complete objects exist."""
    result = _recover_truncated_json('[{"line": 1, "rul')
    assert result is None


# ─── analyze_chunk with mocked API ────────────────────────────────────

@patch("wiz.llm._get_client")
def test_analyze_chunk_valid_json(mock_get_client, sample_chunk, mock_response):
    """Test analyze_chunk with valid JSON response."""
    findings_json = json.dumps([
        {
            "line": 1,
            "severity": "warning",
            "category": "bug",
            "rule": "test-rule",
            "message": "Test issue",
            "suggestion": "Fix it",
            "confidence": "high",
        }
    ])
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_response(findings_json)
    mock_get_client.return_value = mock_client

    ct = CostTracker()
    findings = analyze_chunk(sample_chunk, ct)

    assert len(findings) == 1
    assert findings[0].rule == "test-rule"
    assert findings[0].severity == Severity.WARNING
    assert findings[0].source == Source.LLM
    assert findings[0].confidence == Confidence.HIGH
    assert ct.total_input_tokens == 100
    assert ct.total_output_tokens == 50


@patch("wiz.llm._get_client")
def test_analyze_chunk_empty_array(mock_get_client, sample_chunk, mock_response):
    """Test analyze_chunk with empty findings."""
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_response("[]")
    mock_get_client.return_value = mock_client

    ct = CostTracker()
    findings = analyze_chunk(sample_chunk, ct)

    assert len(findings) == 0


@patch("wiz.llm._get_client")
def test_analyze_chunk_malformed_json(mock_get_client, sample_chunk, mock_response):
    """Test analyze_chunk with completely malformed response."""
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_response("not json at all")
    mock_get_client.return_value = mock_client

    ct = CostTracker()
    findings = analyze_chunk(sample_chunk, ct)

    assert len(findings) == 0  # Should gracefully return empty


@patch("wiz.llm._get_client")
def test_analyze_chunk_truncated_json(mock_get_client, sample_chunk, mock_response):
    """Test analyze_chunk with truncated JSON (recovery should work)."""
    # Two objects, second is truncated
    text = '[{"line": 1, "severity": "warning", "category": "bug", "rule": "r1", "message": "m1", "suggestion": "s1", "confidence": "high"}, {"line": 2, "sev'
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_response(text)
    mock_get_client.return_value = mock_client

    ct = CostTracker()
    findings = analyze_chunk(sample_chunk, ct)

    # Should recover at least the first finding
    assert len(findings) >= 1
    assert findings[0].rule == "r1"


@patch("wiz.llm._get_client")
def test_analyze_chunk_markdown_fences(mock_get_client, sample_chunk, mock_response):
    """Test analyze_chunk strips markdown code fences."""
    text = '```json\n[{"line": 1, "severity": "info", "category": "style", "rule": "r1", "message": "m1", "confidence": "low"}]\n```'
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_response(text)
    mock_get_client.return_value = mock_client

    ct = CostTracker()
    findings = analyze_chunk(sample_chunk, ct)

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.LOW


@patch("wiz.llm._get_client")
def test_analyze_chunk_confidence_default(mock_get_client, sample_chunk, mock_response):
    """Test that missing confidence field defaults to MEDIUM."""
    text = json.dumps([{
        "line": 1,
        "severity": "warning",
        "category": "bug",
        "rule": "r1",
        "message": "m1",
        # no confidence field
    }])
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_response(text)
    mock_get_client.return_value = mock_client

    ct = CostTracker()
    findings = analyze_chunk(sample_chunk, ct)

    assert len(findings) == 1
    assert findings[0].confidence == Confidence.MEDIUM


@patch("wiz.llm._get_client")
def test_analyze_chunk_line_offset(mock_get_client, mock_response):
    """Test that line numbers are adjusted for chunk offset."""
    chunk = Chunk(
        content="code here",
        start_line=100,
        end_line=150,
        chunk_index=1,  # Not first chunk
        total_chunks=3,
        filepath="test.py",
        language="python",
    )
    text = json.dumps([{
        "line": 10,
        "severity": "warning",
        "category": "bug",
        "rule": "r1",
        "message": "m1",
    }])
    mock_client = MagicMock()
    mock_client.messages.create.return_value = mock_response(text)
    mock_get_client.return_value = mock_client

    ct = CostTracker()
    findings = analyze_chunk(chunk, ct)

    # line 10 in chunk + start_line 100 - 1 = 109
    assert findings[0].line == 109


# ─── Retry logic ──────────────────────────────────────────────────────

@patch("wiz.llm.time.sleep")
def test_api_call_retry_on_429(mock_sleep):
    """Test that 429 errors trigger retry with backoff."""
    mock_client = MagicMock()

    # First call: 429 error; second call: success
    error_429 = Exception("Rate limited")
    error_429.status_code = 429
    success = MagicMock()
    success.content = [MagicMock(text="[]")]
    success.usage.input_tokens = 10
    success.usage.output_tokens = 5

    mock_client.messages.create.side_effect = [error_429, success]

    result = _api_call_with_retry(mock_client, model="test", max_tokens=100,
                                   temperature=0, system="test",
                                   messages=[])
    assert result == success
    mock_sleep.assert_called_once_with(1)  # First retry = 1s


@patch("wiz.llm.time.sleep")
def test_api_call_retry_exhausted(mock_sleep):
    """Test that non-retriable errors raise immediately."""
    mock_client = MagicMock()

    error_401 = Exception("Unauthorized")
    error_401.status_code = 401
    mock_client.messages.create.side_effect = error_401

    with pytest.raises(Exception, match="Unauthorized"):
        _api_call_with_retry(mock_client, model="test", max_tokens=100,
                              temperature=0, system="test", messages=[])

    # No retries for 401
    mock_sleep.assert_not_called()
