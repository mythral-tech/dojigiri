"""Tests for the metrics/observability module."""

import json
import tempfile
from pathlib import Path
from unittest.mock import patch

import pytest

from dojigiri.metrics import (
    SessionMetrics,
    start_session,
    end_session,
    get_session,
    save_session,
    load_history,
    format_summary,
    format_history_summary,
)


class TestSessionMetrics:
    def test_record_finding(self):
        s = SessionMetrics()
        s.record_finding("bare-except", "warning")
        s.record_finding("bare-except", "warning")
        s.record_finding("eval-usage", "critical")

        assert s.total_findings == 3
        assert s.findings_by_rule == {"bare-except": 2, "eval-usage": 1}
        assert s.findings_by_severity == {"warning": 2, "critical": 1}

    def test_record_fix_success(self):
        s = SessionMetrics()
        s.record_fix("bare-except", True, 5.0)

        assert s.fixes_attempted == 1
        assert s.fixes_succeeded == 1
        assert s.fixes_failed == 0
        assert s.fixes_by_rule["bare-except"]["attempted"] == 1
        assert s.fixes_by_rule["bare-except"]["succeeded"] == 1

    def test_record_fix_failure(self):
        s = SessionMetrics()
        s.record_fix("eval-usage", False, 10.0)

        assert s.fixes_attempted == 1
        assert s.fixes_succeeded == 0
        assert s.fixes_failed == 1

    def test_record_llm_call(self):
        s = SessionMetrics()
        s.record_llm_call(100, 200)
        s.record_llm_call(50, 100)

        assert s.llm_calls == 2
        assert s.llm_tokens_in == 150
        assert s.llm_tokens_out == 300


class TestSessionLifecycle:
    def test_start_end_session(self):
        session = start_session()
        assert session is not None
        assert get_session() is session

        ended = end_session()
        assert ended is session
        assert get_session() is None

    def test_end_session_when_none(self):
        # Ensure clean state
        end_session()
        result = end_session()
        assert result is None

    def test_get_session_when_none(self):
        end_session()
        assert get_session() is None


class TestSaveLoad:
    def test_save_session(self, tmp_path):
        s = SessionMetrics(started_at="2026-03-04T10:00:00")
        s.record_finding("bare-except", "warning")
        s.record_fix("bare-except", True, 5.0)

        with patch("dojigiri.metrics.METRICS_DIR", tmp_path):
            path = save_session(s)

        assert path.exists()
        data = json.loads(path.read_text())
        assert data["started_at"] == "2026-03-04T10:00:00"
        assert data["total_findings"] == 1
        assert data["fixes_succeeded"] == 1

    def test_load_history(self, tmp_path):
        # Create some session files
        for i in range(3):
            data = {
                "started_at": f"2026-03-0{i+1}T10:00:00",
                "total_findings": i * 10,
                "fixes_attempted": i,
                "fixes_succeeded": i,
            }
            (tmp_path / f"2026-03-0{i+1}T10-00-00.json").write_text(json.dumps(data))

        with patch("dojigiri.metrics.METRICS_DIR", tmp_path):
            sessions = load_history(days=30)

        assert len(sessions) == 3

    def test_load_history_empty(self, tmp_path):
        with patch("dojigiri.metrics.METRICS_DIR", tmp_path):
            sessions = load_history()
        assert sessions == []

    def test_load_history_nonexistent_dir(self, tmp_path):
        with patch("dojigiri.metrics.METRICS_DIR", tmp_path / "nonexistent"):
            sessions = load_history()
        assert sessions == []


class TestFormatting:
    def test_format_summary_basic(self):
        s = SessionMetrics(started_at="2026-03-04T10:00:00")
        s.files_scanned = 5
        s.total_findings = 10
        s.scan_duration_ms = 150.0
        summary = format_summary(s)
        assert "2026-03-04T10:00:00" in summary
        assert "Files scanned: 5" in summary
        assert "Total findings: 10" in summary

    def test_format_summary_with_fixes(self):
        s = SessionMetrics(started_at="2026-03-04T10:00:00")
        s.fixes_attempted = 10
        s.fixes_succeeded = 8
        s.fix_duration_ms = 50.0
        s.fixes_by_rule = {
            "bare-except": {"attempted": 5, "succeeded": 5, "failed": 0, "total_duration_ms": 20},
            "eval-usage": {"attempted": 5, "succeeded": 3, "failed": 2, "total_duration_ms": 30},
        }
        summary = format_summary(s)
        assert "8/10 succeeded (80%)" in summary
        assert "eval-usage" in summary  # failing rule

    def test_format_history_summary_empty(self):
        result = format_history_summary([])
        assert "No session history" in result

    def test_format_history_summary(self):
        sessions = [
            {"started_at": "2026-03-04T10:00:00", "total_findings": 10,
             "fixes_attempted": 5, "fixes_succeeded": 4, "scan_duration_ms": 100},
            {"started_at": "2026-03-03T10:00:00", "total_findings": 20,
             "fixes_attempted": 10, "fixes_succeeded": 8, "scan_duration_ms": 200},
        ]
        result = format_history_summary(sessions)
        assert "2 sessions" in result
        assert "Total findings: 30" in result
