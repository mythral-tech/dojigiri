"""Tests for dojigiri/config.py — configuration loading and custom rules."""

import os
import pytest
from pathlib import Path
from unittest.mock import patch

from dojigiri.config import (
    get_api_key,
    get_llm_config,
    load_ignore_patterns,
    load_project_config,
    compile_custom_rules,
    _is_safe_regex,
    PROFILES,
    LANGUAGE_EXTENSIONS,
)


class TestGetApiKey:
    def test_returns_key(self):
        with patch.dict(os.environ, {"ANTHROPIC_API_KEY": "sk-test-123"}):
            assert get_api_key() == "sk-test-123"

    def test_returns_none(self):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("ANTHROPIC_API_KEY", None)
            assert get_api_key() is None


class TestGetLlmConfig:
    def test_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            for key in ("DOJI_LLM_BACKEND", "DOJI_LLM_MODEL", "DOJI_LLM_BASE_URL"):
                os.environ.pop(key, None)
            config = get_llm_config()
            assert config["api_key"] is None
            assert config["backend"] is None

    def test_env_vars(self):
        with patch.dict(os.environ, {
            "DOJI_LLM_BACKEND": "openai",
            "DOJI_LLM_MODEL": "gpt-4",
            "DOJI_LLM_BASE_URL": "http://localhost:8080",
        }):
            config = get_llm_config()
            assert config["backend"] == "openai"
            assert config["model"] == "gpt-4"
            assert config["base_url"] == "http://localhost:8080"

    def test_toml_config(self):
        with patch.dict(os.environ, {}, clear=True):
            for key in ("DOJI_LLM_BACKEND", "DOJI_LLM_MODEL", "DOJI_LLM_BASE_URL"):
                os.environ.pop(key, None)
            config = get_llm_config({"llm": {"backend": "ollama", "model": "llama"}})
            assert config["backend"] == "ollama"
            assert config["model"] == "llama"

    def test_ignores_api_key_from_toml(self, capsys):
        config = get_llm_config({"llm": {"api_key": "stolen-key"}})
        assert config["api_key"] is None

    def test_ignores_base_url_from_toml(self, capsys):
        with patch.dict(os.environ, {}, clear=True):
            os.environ.pop("DOJI_LLM_BASE_URL", None)
            config = get_llm_config({"llm": {"base_url": "http://evil.com"}})
            assert config["base_url"] is None


class TestLoadIgnorePatterns:
    def test_no_file(self, tmp_path):
        result = load_ignore_patterns(tmp_path)
        assert result == []

    def test_with_file(self, tmp_path):
        ignore_file = tmp_path / ".doji-ignore"
        ignore_file.write_text("# comment\nnode_modules/\n*.pyc\n\n", encoding="utf-8")
        result = load_ignore_patterns(tmp_path)
        assert "node_modules/" in result
        assert "*.pyc" in result
        assert len(result) == 2  # comment and empty line excluded


class TestLoadProjectConfig:
    def test_no_file(self, tmp_path):
        result = load_project_config(tmp_path)
        assert result == {}

    def test_valid_toml(self, tmp_path):
        config_file = tmp_path / ".doji.toml"
        config_file.write_text(
            '[dojigiri]\nignore_rules = ["todo-marker"]\nmin_severity = "warning"\n',
            encoding="utf-8",
        )
        result = load_project_config(tmp_path)
        assert result.get("ignore_rules") == ["todo-marker"]

    def test_invalid_toml(self, tmp_path):
        config_file = tmp_path / ".doji.toml"
        config_file.write_text("invalid toml {{{}}", encoding="utf-8")
        result = load_project_config(tmp_path)
        assert result == {}


class TestIsSafeRegex:
    def test_safe_pattern(self):
        assert _is_safe_regex(r"\beval\b") is True

    def test_redos_nested_quantifier(self):
        assert _is_safe_regex(r"(a+)+") is False

    def test_too_long(self):
        assert _is_safe_regex("a" * 501) is False

    def test_invalid_regex_returns_true(self):
        # Invalid regex is "safe" — the caller handles the compile error
        assert _is_safe_regex(r"[invalid") is True


class TestCompileCustomRules:
    def test_empty(self):
        assert compile_custom_rules({}) == []
        assert compile_custom_rules({"rules": []}) == []

    def test_valid_rule(self):
        config = {"rules": [
            {"pattern": r"\bTODO\b", "name": "custom-todo",
             "message": "TODO found", "severity": "info", "category": "style"},
        ]}
        result = compile_custom_rules(config)
        assert len(result) == 1
        assert result[0][3] == "custom-todo"  # name is index 3 in the tuple

    def test_missing_fields(self):
        config = {"rules": [{"pattern": r"\bX\b"}]}  # missing name and message
        result = compile_custom_rules(config)
        assert len(result) == 0

    def test_invalid_severity(self):
        config = {"rules": [
            {"pattern": r"\bX\b", "name": "r1", "message": "m1", "severity": "mega"},
        ]}
        result = compile_custom_rules(config)
        assert len(result) == 0

    def test_invalid_category(self):
        config = {"rules": [
            {"pattern": r"\bX\b", "name": "r1", "message": "m1", "category": "mega"},
        ]}
        result = compile_custom_rules(config)
        assert len(result) == 0

    def test_invalid_regex(self):
        config = {"rules": [
            {"pattern": r"[invalid", "name": "r1", "message": "m1"},
        ]}
        result = compile_custom_rules(config)
        assert len(result) == 0

    def test_with_languages(self):
        config = {"rules": [
            {"pattern": r"\bX\b", "name": "r1", "message": "m1",
             "languages": ["python", "javascript"]},
        ]}
        result = compile_custom_rules(config)
        assert result[0][6] == ["python", "javascript"]  # languages is index 6

    def test_with_suggestion(self):
        config = {"rules": [
            {"pattern": r"\bX\b", "name": "r1", "message": "m1", "suggestion": "fix it"},
        ]}
        result = compile_custom_rules(config)
        assert result[0][5] == "fix it"  # suggestion is index 5

    def test_redos_rejected(self):
        config = {"rules": [
            {"pattern": r"(a+)+", "name": "r1", "message": "m1"},
        ]}
        result = compile_custom_rules(config)
        assert len(result) == 0
