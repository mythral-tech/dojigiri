"""Tests for compliance module — CWE/NIST mappings."""

import re
import pytest

from dojigiri.compliance import get_cwe, get_nist, CWE_MAP, NIST_MAP


# ─── CWE mappings ─────────────────────────────────────────────────────

class TestGetCwe:
    def test_known_rule_returns_cwe(self):
        assert get_cwe("sql-injection-execute") == "CWE-89"

    def test_unknown_rule_returns_none(self):
        assert get_cwe("nonexistent-rule") is None

    def test_empty_string_returns_none(self):
        assert get_cwe("") is None

    def test_all_cwe_ids_are_valid_format(self):
        """Every CWE ID should match CWE-NNN pattern."""
        for rule, cwe in CWE_MAP.items():
            assert re.match(r"^CWE-\d+$", cwe), f"Invalid CWE format for {rule}: {cwe}"

    def test_security_rules_have_cwe(self):
        """Critical security rules must have CWE mappings."""
        security_rules = [
            "sql-injection-execute", "eval-usage", "exec-usage", "hardcoded-secret",
            "path-traversal", "pickle-unsafe", "yaml-unsafe", "innerhtml",
            "os-system", "shell-true", "private-key", "taint-flow",
        ]
        for rule in security_rules:
            assert get_cwe(rule) is not None, f"Security rule {rule} missing CWE"

    def test_injection_rules_map_to_injection_cwes(self):
        """SQL injection should map to CWE-89, command injection to CWE-78."""
        assert get_cwe("sql-injection-execute") == "CWE-89"
        assert get_cwe("os-system") == "CWE-78"
        assert get_cwe("shell-true") == "CWE-78"

    def test_xss_rules_map_to_cwe_79(self):
        assert get_cwe("innerhtml") == "CWE-79"
        assert get_cwe("insert-adjacent-html") == "CWE-79"
        assert get_cwe("document-write") == "CWE-79"

    def test_deserialization_rules_map_to_cwe_502(self):
        assert get_cwe("pickle-unsafe") == "CWE-502"
        assert get_cwe("yaml-unsafe") == "CWE-502"

    def test_null_deref_maps_to_cwe_476(self):
        assert get_cwe("null-dereference") == "CWE-476"


# ─── NIST mappings ────────────────────────────────────────────────────

class TestGetNist:
    def test_known_rule_returns_controls(self):
        nist = get_nist("sql-injection-execute")
        assert isinstance(nist, list)
        assert len(nist) > 0
        assert "SI-10" in nist

    def test_unknown_rule_returns_empty_list(self):
        assert get_nist("nonexistent-rule") == []

    def test_empty_string_returns_empty_list(self):
        assert get_nist("") == []

    def test_all_nist_controls_are_valid_format(self):
        """NIST controls should match XX-NN pattern (family-number)."""
        for rule, controls in NIST_MAP.items():
            assert isinstance(controls, list), f"NIST for {rule} should be a list"
            for ctrl in controls:
                assert re.match(r"^[A-Z]{2}-\d+$", ctrl), \
                    f"Invalid NIST control format for {rule}: {ctrl}"

    def test_credential_rules_map_to_key_management(self):
        """Hardcoded secrets should map to SC-12 (key management)."""
        for rule in ["hardcoded-secret", "aws-credentials", "private-key"]:
            nist = get_nist(rule)
            assert "SC-12" in nist, f"{rule} should map to SC-12"

    def test_injection_rules_map_to_input_validation(self):
        """Injection rules should map to SI-10 (input validation)."""
        for rule in ["sql-injection-execute", "eval-usage", "os-system", "taint-flow"]:
            nist = get_nist(rule)
            assert "SI-10" in nist, f"{rule} should map to SI-10"

    def test_crypto_rules_map_to_crypto_controls(self):
        for rule in ["weak-hash", "insecure-crypto", "insecure-ecb-mode"]:
            nist = get_nist(rule)
            assert "SC-13" in nist, f"{rule} should map to SC-13"


# ─── Coverage ─────────────────────────────────────────────────────────

class TestCoverage:
    def test_all_language_rules_have_cwe(self):
        """Every rule from languages.py should have a CWE mapping."""
        from dojigiri.languages import list_all_rules
        rules = list_all_rules()
        unmapped = [r["name"] for r in rules if r["name"] not in CWE_MAP]
        assert unmapped == [], f"Rules missing CWE mapping: {unmapped}"

    def test_cwe_map_has_no_orphan_keys(self):
        """Every key in CWE_MAP should correspond to an actual rule somewhere."""
        from dojigiri.languages import list_all_rules
        rule_names = {r["name"] for r in list_all_rules()}
        # Also include semantic/graph rules not in languages.py
        semantic_rules = {
            "syntax-error", "unused-import", "exception-swallowed", "exception-swallowed-continue",
            "shadowed-builtin", "shadowed-builtin-param", "type-comparison",
            "global-keyword", "unreachable-code", "high-complexity",
            "too-many-args", "empty-exception-handler", "unused-variable",
            "variable-shadowing", "possibly-uninitialized", "null-dereference",
            "resource-leak", "taint-flow", "taint-flow-cross-file",
            "god-class", "feature-envy",
            "long-method", "near-duplicate", "semantic-clone", "dead-function",
            "arg-count-mismatch", "cross-file-issue", "mutable-default",
            "vulnerable-dependency",
        }
        all_known = rule_names | semantic_rules
        orphans = [k for k in CWE_MAP if k not in all_known]
        assert orphans == [], f"CWE_MAP has orphan keys: {orphans}"

    def test_nist_map_subset_of_cwe_map(self):
        """Every rule in NIST_MAP should also be in CWE_MAP (CWE is the primary)."""
        missing = [k for k in NIST_MAP if k not in CWE_MAP]
        assert missing == [], f"Rules in NIST_MAP but not CWE_MAP: {missing}"
