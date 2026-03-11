"""Tests for dojigiri/metrics.py — session observability and metrics."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from dojigiri.metrics import (
    SessionMetrics,
    start_session,
    get_session,
    end_session,
    save_session,
    load_history,
    format_summary,
    format_history_summary,
)


class TestSessionMetrics:
    def test_record_file(self):
        m = SessionMetrics()
        m.record_file(100.0)
        m.record_file(200.0)
        assert m.files_scanned == 2
        assert m.scan_duration_ms == 300.0

    def test_record_finding(self):
        m = SessionMetrics()
        m.record_finding("test-rule", "warning")
        m.record_finding("test-rule", "warning")
        m.record_finding("other-rule", "critical")
        assert m.total_findings == 3
        assert m.findings_by_rule["test-rule"] == 2
        assert m.findings_by_severity["warning"] == 2

    def test_record_fix_succeeded(self):
        m = SessionMetrics()
        m.record_fix("test-rule", True, 50.0)
        assert m.fixes_attempted == 1
        assert m.fixes_succeeded == 1
        assert m.fixes_failed == 0
        assert m.fixes_by_rule["test-rule"]["succeeded"] == 1

    def test_record_fix_failed(self):
        m = SessionMetrics()
        m.record_fix("test-rule", False, 50.0)
        assert m.fixes_failed == 1
        assert m.fixes_by_rule["test-rule"]["failed"] == 1

    def test_record_fix_duration(self):
        m = SessionMetrics()
        m.record_fix_duration(100.0)
        m.record_fix_duration(200.0)
        assert m.fix_duration_ms == 300.0

    def test_record_llm_call(self):
        m = SessionMetrics()
        m.record_llm_call(100, 50)
        m.record_llm_call(200, 100)
        assert m.llm_calls == 2
        assert m.llm_tokens_in == 300
        assert m.llm_tokens_out == 150


class TestSessionLifecycle:
    def test_start_and_get(self):
        session = start_session()
        assert session is not None
        assert get_session() is session
        end_session()

    def test_end_returns_session(self):
        start_session()
        session = end_session()
        assert session is not None
        assert get_session() is None

    def test_end_without_start(self):
        # Ensure clean state
        end_session()
        result = end_session()
        assert result is None


class TestSaveSession:
    def test_save_creates_file(self, tmp_path):
        m = SessionMetrics(started_at="2025-01-01T12-00-00")
        m.record_finding("test-rule", "warning")
        with patch("dojigiri.metrics.METRICS_DIR", tmp_path):
            path = save_session(m)
        assert path.exists()
        data = json.loads(path.read_text(encoding="utf-8"))
        assert data["total_findings"] == 1

    def test_save_no_timestamp(self, tmp_path):
        m = SessionMetrics()
        with patch("dojigiri.metrics.METRICS_DIR", tmp_path):
            path = save_session(m)
        assert "unknown" in path.name


class TestLoadHistory:
    def test_empty_dir(self, tmp_path):
        with patch("dojigiri.metrics.METRICS_DIR", tmp_path):
            result = load_history()
        assert result == []

    def test_no_dir(self, tmp_path):
        with patch("dojigiri.metrics.METRICS_DIR", tmp_path / "nonexistent"):
            result = load_history()
        assert result == []

    def test_loads_valid_files(self, tmp_path):
        data = {"started_at": "2025-01-01T00:00:00", "total_findings": 5}
        (tmp_path / "2025-01-01.json").write_text(json.dumps(data), encoding="utf-8")
        with patch("dojigiri.metrics.METRICS_DIR", tmp_path):
            result = load_history(days=0)
        assert len(result) == 1
        assert result[0]["total_findings"] == 5

    def test_skips_corrupt_json(self, tmp_path):
        (tmp_path / "bad.json").write_text("not json", encoding="utf-8")
        (tmp_path / "good.json").write_text('{"started_at": "", "x": 1}', encoding="utf-8")
        with patch("dojigiri.metrics.METRICS_DIR", tmp_path):
            result = load_history(days=0)
        assert len(result) == 1


class TestFormatSummary:
    def test_basic(self):
        m = SessionMetrics(started_at="2025-01-01T00:00:00")
        m.record_file(100.0)
        m.record_finding("test-rule", "warning")
        result = format_summary(m)
        assert "Files scanned: 1" in result
        assert "Total findings: 1" in result
        assert "warning: 1" in result

    def test_with_fixes(self):
        m = SessionMetrics(started_at="2025-01-01T00:00:00")
        m.record_fix("rule-a", True, 50.0)
        m.record_fix("rule-a", False, 30.0)
        m.record_fix_duration(80.0)
        result = format_summary(m)
        assert "Fixes: 1/2 succeeded (50%)" in result
        assert "Failing rules:" in result
        assert "rule-a" in result

    def test_with_llm(self):
        m = SessionMetrics(started_at="2025-01-01T00:00:00")
        m.record_llm_call(1000, 500)
        result = format_summary(m)
        assert "LLM calls: 1" in result


class TestFormatHistorySummary:
    def test_empty(self):
        result = format_history_summary([])
        assert "No session history" in result

    def test_with_sessions(self):
        sessions = [
            {"started_at": "2025-01-01T00:00:00", "total_findings": 10,
             "fixes_attempted": 5, "fixes_succeeded": 4,
             "scan_duration_ms": 1000.0, "fixes_by_rule": {}},
        ]
        result = format_history_summary(sessions)
        assert "1 sessions" in result
        assert "Total findings: 10" in result
        assert "Fix success rate:" in result

    def test_problem_rules(self):
        sessions = [
            {"started_at": "2025-01-01T00:00:00", "total_findings": 0,
             "fixes_attempted": 10, "fixes_succeeded": 5,
             "scan_duration_ms": 500.0,
             "fixes_by_rule": {
                 "bad-rule": {"attempted": 10, "succeeded": 2, "failed": 8},
             }},
        ]
        result = format_history_summary(sessions)
        assert ">20% failure rate" in result
        assert "bad-rule" in result
