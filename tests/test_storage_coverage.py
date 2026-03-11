"""Tests for dojigiri/storage.py — report persistence and caching."""

import json
import pytest
from pathlib import Path
from unittest.mock import patch

from dojigiri.storage import (
    file_hash,
    load_cache,
    save_cache,
    _prune_reports,
    load_latest_report,
    load_baseline_report,
    list_reports,
)
from dojigiri import __version__


class TestFileHash:
    def test_deterministic(self, tmp_path):
        f = tmp_path / "test.txt"
        f.write_text("hello world\n", encoding="utf-8")
        h1 = file_hash(str(f))
        h2 = file_hash(str(f))
        assert h1 == h2
        assert len(h1) == 64  # SHA256 hex digest

    def test_different_content(self, tmp_path):
        f1 = tmp_path / "a.txt"
        f2 = tmp_path / "b.txt"
        f1.write_text("hello", encoding="utf-8")
        f2.write_text("world", encoding="utf-8")
        assert file_hash(str(f1)) != file_hash(str(f2))


class TestLoadCache:
    def test_no_file(self, tmp_path):
        with patch("dojigiri.storage.CACHE_FILE", tmp_path / "noexist.json"):
            cache = load_cache()
        assert cache == {"__version__": __version__}

    def test_valid_cache(self, tmp_path):
        cache_file = tmp_path / "cache.json"
        data = {"__version__": __version__, "file.py": "abc123"}
        cache_file.write_text(json.dumps(data), encoding="utf-8")
        with patch("dojigiri.storage.CACHE_FILE", cache_file):
            cache = load_cache()
        assert cache["file.py"] == "abc123"

    def test_version_mismatch(self, tmp_path):
        cache_file = tmp_path / "cache.json"
        data = {"__version__": "0.0.0-old", "file.py": "abc123"}
        cache_file.write_text(json.dumps(data), encoding="utf-8")
        with patch("dojigiri.storage.CACHE_FILE", cache_file):
            cache = load_cache()
        assert "file.py" not in cache

    def test_corrupt_json(self, tmp_path):
        cache_file = tmp_path / "cache.json"
        cache_file.write_text("not json", encoding="utf-8")
        with patch("dojigiri.storage.CACHE_FILE", cache_file):
            cache = load_cache()
        assert cache == {"__version__": __version__}


class TestSaveCache:
    def test_saves(self, tmp_path):
        cache_file = tmp_path / "cache.json"
        with patch("dojigiri.storage.CACHE_FILE", cache_file), \
             patch("dojigiri.storage.STORAGE_DIR", tmp_path), \
             patch("dojigiri.storage.REPORTS_DIR", tmp_path / "reports"):
            save_cache({"file.py": "abc123"})
        data = json.loads(cache_file.read_text(encoding="utf-8"))
        assert data["file.py"] == "abc123"
        assert data["__version__"] == __version__


class TestPruneReports:
    def test_prunes_old(self, tmp_path):
        for i in range(5):
            (tmp_path / f"scan_{i:04d}.json").write_text("{}", encoding="utf-8")
        with patch("dojigiri.storage.REPORTS_DIR", tmp_path):
            _prune_reports(max_keep=2)
        remaining = list(tmp_path.glob("scan_*.json"))
        assert len(remaining) == 2


class TestLoadLatestReport:
    def test_no_file(self, tmp_path):
        with patch("dojigiri.storage.REPORTS_DIR", tmp_path):
            assert load_latest_report() is None

    def test_valid(self, tmp_path):
        latest = tmp_path / "latest.json"
        latest.write_text('{"root": "/test"}', encoding="utf-8")
        with patch("dojigiri.storage.REPORTS_DIR", tmp_path):
            result = load_latest_report()
        assert result["root"] == "/test"

    def test_corrupt(self, tmp_path):
        latest = tmp_path / "latest.json"
        latest.write_text("not json", encoding="utf-8")
        with patch("dojigiri.storage.REPORTS_DIR", tmp_path):
            assert load_latest_report() is None


class TestLoadBaselineReport:
    def test_latest(self, tmp_path):
        latest = tmp_path / "latest.json"
        latest.write_text('{"x": 1}', encoding="utf-8")
        with patch("dojigiri.storage.REPORTS_DIR", tmp_path):
            result = load_baseline_report("latest")
        assert result == {"x": 1}

    def test_specific_path(self, tmp_path):
        report = tmp_path / "report.json"
        report.write_text('{"y": 2}', encoding="utf-8")
        with patch("dojigiri.storage.REPORTS_DIR", tmp_path):
            result = load_baseline_report(str(report))
        assert result == {"y": 2}

    def test_nonexistent_path(self, tmp_path):
        with patch("dojigiri.storage.REPORTS_DIR", tmp_path):
            result = load_baseline_report(str(tmp_path / "missing.json"))
        assert result is None


class TestListReports:
    def test_lists(self, tmp_path):
        for i in range(3):
            (tmp_path / f"scan_{i:04d}.json").write_text("{}", encoding="utf-8")
        with patch("dojigiri.storage.REPORTS_DIR", tmp_path), \
             patch("dojigiri.storage.STORAGE_DIR", tmp_path):
            reports = list_reports()
        assert len(reports) == 3
