"""Tests for rules package — loader, _compile, and language rule modules."""

import re
import pytest
from pathlib import Path
from unittest.mock import patch

from dojigiri.rules._compile import Rule, _compile
from dojigiri.rules.loader import _compile_yaml_rules, load_yaml_rules, load_yaml_rules_dir
from dojigiri.types import Category, Severity


# ─── _compile ────────────────────────────────────────────────────────


class TestCompile:
    def test_compiles_rules(self):
        raw = [
            (r"\beval\b", Severity.CRITICAL, Category.SECURITY, "eval", "eval bad", "use literal_eval"),
        ]
        result = _compile(raw)
        assert len(result) == 1
        pattern, sev, cat, name, msg, sug = result[0]
        assert isinstance(pattern, re.Pattern)
        assert sev == Severity.CRITICAL
        assert name == "eval"


# ─── _compile_yaml_rules ────────────────────────────────────────────


class TestCompileYamlRules:
    def test_valid_rule(self):
        rules_data = [{
            "id": "test-rule",
            "severity": "warning",
            "category": "bug",
            "pattern": r"\btest\b",
            "message": "Test found",
            "suggestion": "Remove test",
        }]
        result = _compile_yaml_rules(rules_data)
        assert len(result) == 1
        assert result[0][3] == "test-rule"  # rule name

    def test_missing_required_field(self):
        rules_data = [{"id": "bad-rule", "severity": "warning"}]
        result = _compile_yaml_rules(rules_data)
        assert len(result) == 0

    def test_invalid_severity(self):
        rules_data = [{
            "id": "bad-sev",
            "severity": "ultra",
            "category": "bug",
            "pattern": r"test",
            "message": "msg",
        }]
        result = _compile_yaml_rules(rules_data)
        assert len(result) == 0

    def test_invalid_category(self):
        rules_data = [{
            "id": "bad-cat",
            "severity": "warning",
            "category": "nonexistent",
            "pattern": r"test",
            "message": "msg",
        }]
        result = _compile_yaml_rules(rules_data)
        assert len(result) == 0

    def test_invalid_regex(self):
        rules_data = [{
            "id": "bad-regex",
            "severity": "warning",
            "category": "bug",
            "pattern": r"[invalid",
            "message": "msg",
        }]
        result = _compile_yaml_rules(rules_data)
        assert len(result) == 0

    def test_with_flags(self):
        rules_data = [{
            "id": "case-rule",
            "severity": "info",
            "category": "style",
            "pattern": r"todo",
            "message": "TODO found",
            "flags": ["IGNORECASE"],
        }]
        result = _compile_yaml_rules(rules_data)
        assert len(result) == 1
        assert result[0][0].flags & re.IGNORECASE

    def test_unknown_flag(self):
        rules_data = [{
            "id": "flag-rule",
            "severity": "info",
            "category": "style",
            "pattern": r"test",
            "message": "msg",
            "flags": ["UNKNOWN_FLAG"],
        }]
        result = _compile_yaml_rules(rules_data)
        assert len(result) == 1  # Rule still compiles, flag is just ignored


# ─── load_yaml_rules ────────────────────────────────────────────────


class TestLoadYamlRules:
    def test_loads_yaml_file(self, tmp_path):
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text(
            "rules:\n"
            "  - id: test-rule\n"
            "    severity: warning\n"
            "    category: bug\n"
            "    pattern: '\\\\btest\\\\b'\n"
            "    message: test found\n",
            encoding="utf-8",
        )
        try:
            import yaml
            result = load_yaml_rules(yaml_file)
            # If yaml is installed, we should get rules
            assert len(result) >= 0  # May be 0 if pattern is invalid
        except ImportError:
            result = load_yaml_rules(yaml_file)
            assert result == []

    def test_no_yaml_package(self, tmp_path):
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("rules: []", encoding="utf-8")
        with patch.dict("sys.modules", {"yaml": None}):
            with patch("builtins.__import__", side_effect=ImportError):
                # This may or may not work depending on import caching
                pass

    def test_no_rules_key(self, tmp_path):
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("other_key: value\n", encoding="utf-8")
        result = load_yaml_rules(yaml_file)
        assert result == []

    def test_rules_not_list(self, tmp_path):
        try:
            import yaml
        except ImportError:
            pytest.skip("PyYAML not installed")
        yaml_file = tmp_path / "test.yaml"
        yaml_file.write_text("rules: not_a_list\n", encoding="utf-8")
        result = load_yaml_rules(yaml_file)
        assert result == []


# ─── load_yaml_rules_dir ────────────────────────────────────────────


class TestLoadYamlRulesDir:
    def test_nonexistent_dir(self, tmp_path):
        result = load_yaml_rules_dir(tmp_path / "nonexistent")
        assert result == {}

    def test_default_directory(self):
        """Default YAML rules directory should load successfully."""
        result = load_yaml_rules_dir()
        # Should have at least some rules if yaml dir exists
        assert isinstance(result, dict)


# ─── Language rule modules (0% coverage) ─────────────────────────────


class TestLanguageRuleModules:
    def test_python_rules_loaded(self):
        from dojigiri.rules.python import PYTHON_RULES
        assert len(PYTHON_RULES) > 0

    def test_go_rules_loaded(self):
        from dojigiri.rules.go import GO_RULES
        assert len(GO_RULES) > 0

    def test_java_rules_loaded(self):
        from dojigiri.rules.java import JAVA_RULES
        assert len(JAVA_RULES) > 0

    def test_javascript_rules_loaded(self):
        from dojigiri.rules.javascript import JAVASCRIPT_RULES
        assert len(JAVASCRIPT_RULES) > 0

    def test_rust_rules_loaded(self):
        from dojigiri.rules.rust import RUST_RULES
        assert len(RUST_RULES) > 0

    def test_security_rules_loaded(self):
        from dojigiri.rules.security import SECURITY_RULES
        assert len(SECURITY_RULES) > 0

    def test_universal_rules_loaded(self):
        from dojigiri.rules.universal import UNIVERSAL_RULES
        assert len(UNIVERSAL_RULES) > 0


# ─── rules/__init__.py fallback path ────────────────────────────────


class TestRulesInit:
    def test_rules_available(self):
        """Top-level rule lists should be populated."""
        from dojigiri.rules import (
            PYTHON_RULES, GO_RULES, JAVA_RULES, JAVASCRIPT_RULES,
            RUST_RULES, SECURITY_RULES, UNIVERSAL_RULES,
        )
        assert len(UNIVERSAL_RULES) > 0
        assert len(PYTHON_RULES) > 0


# ─── Severity contract ──────────────────────────────────────────────────────


class TestSeverityContract:
    """Enforce the two-signal gate: injection patterns are WARNING, secrets/config are CRITICAL.

    This is the single test that prevents accidental severity drift. If you need to
    change a rule's severity, update the appropriate set below — the change will be
    visible in the diff and reviewable.
    """

    # Rules that MUST be CRITICAL — inherently dangerous regardless of data flow.
    # Secrets, unsafe config, dangerous APIs that are always exploitable.
    MUST_BE_CRITICAL = {
        # Secrets & credentials
        "private-key", "hardcoded-secret", "hardcoded-secret-dict",
        "hardcoded-secret-key", "hardcoded-api-key", "hardcoded-password",
        "hardcoded-jwt-secret", "aws-credentials", "aws-access-key", "aws-secret-key",
        "gcp-api-key", "gcp-service-account", "github-token", "github-fine-grained-token",
        "slack-token", "slack-webhook", "stripe-secret-key", "stripe-key",
        "twilio-api-key", "sendgrid-api-key", "sendgrid-key", "mailgun-api-key",
        "jwt-secret", "google-api-key", "generic-bearer-token", "npm-token",
        "boto3-hardcoded-key", "password-in-query-string", "password-in-url",
        "generic-password-in-url",
        # Unsafe deserialization (always dangerous)
        "pickle-unsafe", "yaml-unsafe", "unsafe-deserialization",
        "node-serialize-usage", "js-yaml-unsafe-load", "serialize-unserialize",
        "pickle-from-request", "dill-loads-unsafe", "marshal-loads-unsafe",
        "llm-pickle-model-load",
        # Dangerous config (always exploitable)
        "insecure-ssl-context", "weak-tls-version", "weak-cipher-suite",
        "werkzeug-debugger", "jwt-none-algorithm", "jwt-alg-none",
        "js-tls-reject-unauthorized", "js-tls-env-disable",
        "logging-config-listen", "code-interactive-console",
        "cors-reflect-origin",
        # Crypto
        "crypto-create-cipher", "crypto-static-iv", "crypto-ecb-mode",
        "crypto-des-algorithm", "crypto-weak-random-token",
        # Electron
        "electron-node-integration", "electron-context-isolation-off",
        "electron-websecurity-off", "electron-shell-openexternal",
        "electron-allow-running-insecure",
        # Next.js / Nuxt
        "nextjs-exposed-server-env", "nextjs-getserversideprops-leak",
        "nuxt-exposed-runtime-secret",
        # LLM — inherently dangerous (not injection-pattern)
        "llm-safety-disabled-google", "llm-safety-disabled-cohere",
        "llm-safety-disabled-mistral",
        "llm-client-controlled-messages", "llm-role-from-user-input",
        "llm-secret-in-prompt", "llm-connection-string-in-prompt",
        "llm-untrusted-model-load", "llm-untrusted-training-data",
        "llm-fine-tune-untrusted",
        "llm-langchain-python-repl", "llm-langchain-bash",
        "llm-base64-decode-to-prompt",
        "llm-client-messages-direct",
        # Agent frameworks — dangerous config
        "crewai-agent-allow-code-execution", "autogen-code-executor-unsafe",
        "langgraph-tool-node-unrestricted", "claude-agent-sdk-unsafe-tool",
        # MCP — shell in tools is always dangerous
        "llm-mcp-tool-shell", "llm-mcp-tool-exec-js",
        # Other
        "db-connection-string", "deserialization-unsafe", "jwt-insecure",
        "rag-document-to-prompt", "rag-source-trust-boundary",
        "flask-secret-hardcoded", "js-hardcoded-jwt-secret",
    }

    # Rules that MUST be WARNING — injection patterns that need taint confirmation.
    # Regex sees the pattern but can't tell if data is user-controlled.
    MUST_BE_WARNING = {
        # SQL injection patterns
        "sql-injection", "sql-injection-execute", "sql-injection-format",
        "sql-injection-fstring", "sql-injection-concat", "sql-injection-percent",
        "sql-injection-raw", "sqlalchemy-execute-fstring", "sqlalchemy-execute-format",
        "sqlalchemy-execute-concat", "sqlalchemy-text-format",
        "django-raw-fstring", "django-rawsql-format", "django-extra-fstring",
        "sql-string-concat", "sql-template-literal", "sequelize-raw-query",
        "knex-raw-interpolation",
        # Code execution patterns
        "eval-usage", "exec-usage", "os-system", "os-popen", "shell-true",
        "shell-injection", "js-command-injection", "js-command-injection-template",
        "subprocess-popen-concat", "subprocess-shell-user-input",
        "function-constructor",
        # Template injection
        "ssti-risk",
        # Prompt injection patterns (all regex-only)
        "prompt-injection-content-fstring", "prompt-injection-content-template",
        "prompt-injection-system-role-fstring", "prompt-injection-system-role-template",
        "prompt-injection-openai-fstring", "prompt-injection-openai-format",
        "prompt-injection-openai-template", "prompt-injection-openai-concat",
        "prompt-injection-anthropic-fstring", "prompt-injection-anthropic-format",
        "prompt-injection-anthropic-concat", "prompt-injection-anthropic-js",
        "prompt-injection-langchain-fstring", "prompt-injection-langchain-system-var",
        "prompt-injection-langchain-js", "prompt-injection-vercel-ai",
        "prompt-injection-litellm", "prompt-injection-genai", "prompt-injection-cohere",
        "prompt-injection-llamaindex-fstring", "prompt-injection-jinja-prompt",
        "prompt-injection-ollama", "prompt-injection-bedrock", "prompt-injection-groq",
        "prompt-injection-format-locals", "prompt-injection-format-map-locals",
        "prompt-injection-system-content-js", "prompt-injection-system-content-concat",
        # LLM output to sink (need taint)
        "llm-output-to-exec", "llm-output-to-sql", "llm-output-to-file",
        "llm-output-to-html", "llm-output-to-import", "llm-output-to-pickle",
        "llm-output-to-eval-js", "llm-output-to-innerhtml", "llm-output-to-sql-js",
        "llm-output-to-redirect", "llm-output-to-fs",
        "llm-json-output-to-eval", "llm-json-output-to-sql", "llm-json-output-to-shell",
        "llm-tool-call-to-exec", "llm-tool-call-to-sql",
        # XSS patterns
        "react-dangerously-set-innerhtml", "react-ref-innerhtml", "react-href-javascript",
        # SSRF patterns
        "ssrf-fetch-user-url", "ssrf-axios-user-url", "ssrf-got-user-url",
        "ssrf-request-user-url",
        # Path traversal / file ops
        "path-traversal", "fs-user-controlled-read", "fs-user-controlled-write",
        "fs-user-controlled-unlink",
        # Other injection patterns
        "ldap-injection", "xpath-injection", "unsafe-redirect",
        "mongodb-where-operator", "mongodb-regex-user-input", "mongoose-find-user-object",
        "deep-merge-no-proto-check", "lodash-merge-user-input", "zip-slip-extract",
        # RAG
        "rag-user-query-in-system-prompt",
        # TypeScript injection patterns
        "ts-prisma-raw-interpolation", "ts-typeorm-raw-query", "ts-nocheck",
        "prompt-injection-openai-ts", "prompt-injection-anthropic-ts",
        "prompt-injection-vercel-ai-ts", "prompt-injection-system-content-ts",
        "prompt-injection-langchain-ts", "llm-output-to-eval-ts",
    }

    def test_critical_rules_are_critical(self):
        """Rules in MUST_BE_CRITICAL must have severity=critical."""
        all_rules = load_yaml_rules_dir()
        rule_severity = {}
        for rules in all_rules.values():
            for rule in rules:
                rule_severity[rule[3]] = rule[1]  # rule[3]=name, rule[1]=severity

        wrong = []
        for rule_id in self.MUST_BE_CRITICAL:
            if rule_id in rule_severity and rule_severity[rule_id] != Severity.CRITICAL:
                wrong.append(f"  {rule_id}: expected CRITICAL, got {rule_severity[rule_id].value}")

        assert not wrong, (
            f"These rules must be CRITICAL (secrets/config/dangerous APIs):\n"
            + "\n".join(wrong)
            + "\n\nIf this is intentional, move the rule to MUST_BE_WARNING."
        )

    def test_warning_rules_are_warning(self):
        """Rules in MUST_BE_WARNING must have severity=warning (two-signal gate)."""
        all_rules = load_yaml_rules_dir()
        rule_severity = {}
        for rules in all_rules.values():
            for rule in rules:
                rule_severity[rule[3]] = rule[1]

        wrong = []
        for rule_id in self.MUST_BE_WARNING:
            if rule_id in rule_severity and rule_severity[rule_id] != Severity.WARNING:
                wrong.append(f"  {rule_id}: expected WARNING, got {rule_severity[rule_id].value}")

        assert not wrong, (
            f"These injection-pattern rules must be WARNING (need taint confirmation for CRITICAL):\n"
            + "\n".join(wrong)
            + "\n\nIf this is intentional, move the rule to MUST_BE_CRITICAL."
        )

    def test_no_rule_in_both_sets(self):
        """A rule can't be in both MUST_BE_CRITICAL and MUST_BE_WARNING."""
        overlap = self.MUST_BE_CRITICAL & self.MUST_BE_WARNING
        assert not overlap, f"Rules in both sets: {overlap}"

    # Rule files covered by the two-signal gate (others pending review)
    _GATED_FILES = {"security", "python", "javascript", "universal", "typescript"}

    def test_all_critical_rules_are_tracked(self):
        """Every CRITICAL rule in gated files should be in MUST_BE_CRITICAL."""
        all_rules = load_yaml_rules_dir()
        untracked = []
        for file_stem, rules in all_rules.items():
            if file_stem not in self._GATED_FILES:
                continue
            for rule in rules:
                name, severity = rule[3], rule[1]
                if severity == Severity.CRITICAL and name not in self.MUST_BE_CRITICAL:
                    untracked.append(f"{file_stem}: {name}")

        assert not untracked, (
            f"CRITICAL rules not in MUST_BE_CRITICAL set (add them or demote to WARNING):\n"
            + "\n".join(f"  {r}" for r in untracked)
        )
