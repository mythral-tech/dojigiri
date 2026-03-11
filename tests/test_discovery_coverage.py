"""Tests for dojigiri/discovery.py — file discovery and skip logic."""

import pytest
from pathlib import Path

from dojigiri.discovery import (
    detect_language,
    should_skip_dir,
    should_skip_file,
    collect_files,
    collect_files_with_lang,
)


class TestDetectLanguage:
    def test_python(self):
        assert detect_language(Path("test.py")) == "python"

    def test_javascript(self):
        assert detect_language(Path("app.js")) == "javascript"

    def test_unknown(self):
        assert detect_language(Path("readme.md")) is None

    def test_case_insensitive(self):
        assert detect_language(Path("Test.PY")) == "python"


class TestShouldSkipDir:
    def test_skip_dirs(self):
        assert should_skip_dir("node_modules") is True
        assert should_skip_dir("__pycache__") is True
        assert should_skip_dir(".git") is True

    def test_hidden_dirs(self):
        assert should_skip_dir(".hidden") is True

    def test_normal_dirs(self):
        assert should_skip_dir("src") is False
        assert should_skip_dir("lib") is False


class TestShouldSkipFile:
    def test_lock_files(self, tmp_path):
        lock = tmp_path / "package-lock.json"
        lock.write_text("{}", encoding="utf-8")
        assert should_skip_file(lock) is True

    def test_sensitive_files(self, tmp_path):
        env = tmp_path / ".env"
        env.write_text("SECRET=x", encoding="utf-8")
        assert should_skip_file(env) is True

    def test_non_code_file(self, tmp_path):
        md = tmp_path / "README.md"
        md.write_text("# README", encoding="utf-8")
        assert should_skip_file(md) is True

    def test_empty_file(self, tmp_path):
        py = tmp_path / "empty.py"
        py.write_text("", encoding="utf-8")
        assert should_skip_file(py) is True

    def test_normal_file(self, tmp_path):
        py = tmp_path / "main.py"
        py.write_text("x = 1\n", encoding="utf-8")
        assert should_skip_file(py) is False

    def test_nonexistent(self, tmp_path):
        assert should_skip_file(tmp_path / "missing.py") is True


class TestCollectFiles:
    def test_single_file(self, tmp_path):
        py = tmp_path / "main.py"
        py.write_text("x = 1\n", encoding="utf-8")
        files, skipped = collect_files(py)
        assert len(files) == 1

    def test_skip_single_non_code(self, tmp_path):
        md = tmp_path / "notes.md"
        md.write_text("# Notes", encoding="utf-8")
        files, skipped = collect_files(md)
        assert len(files) == 0
        assert skipped == 1

    def test_directory(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "b.js").write_text("x = 1;\n", encoding="utf-8")
        files, skipped = collect_files(tmp_path)
        assert len(files) == 2

    def test_language_filter(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "b.js").write_text("x = 1;\n", encoding="utf-8")
        files, _ = collect_files(tmp_path, language_filter="python")
        assert len(files) == 1
        assert files[0].suffix == ".py"

    def test_skip_pycache(self, tmp_path):
        cache_dir = tmp_path / "__pycache__"
        cache_dir.mkdir()
        (cache_dir / "mod.py").write_text("x = 1\n", encoding="utf-8")
        (tmp_path / "main.py").write_text("x = 1\n", encoding="utf-8")
        files, _ = collect_files(tmp_path)
        assert len(files) == 1


class TestCollectFilesWithLang:
    def test_single_file(self, tmp_path):
        py = tmp_path / "main.py"
        py.write_text("x = 1\n", encoding="utf-8")
        result = collect_files_with_lang(py)
        assert len(result) == 1
        assert result[0][1] == "python"

    def test_non_code_file(self, tmp_path):
        md = tmp_path / "notes.md"
        md.write_text("# Notes", encoding="utf-8")
        result = collect_files_with_lang(md)
        assert result == []

    def test_directory(self, tmp_path):
        (tmp_path / "a.py").write_text("x = 1\n", encoding="utf-8")
        result = collect_files_with_lang(tmp_path)
        assert len(result) == 1
