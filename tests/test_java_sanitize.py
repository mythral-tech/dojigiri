"""Tests for java_sanitize.py — Java FP reduction via sanitization detection.

Covers arithmetic evaluation, explicit sanitizers, static reflection,
collection misdirection, switch determinism, cross-method sanitization,
safe sources, safe bar assignment, safe hash properties, and the
filter_java_fps integration function.
"""

import pytest
from dataclasses import dataclass
from dojigiri.java_sanitize import (
    _eval_arithmetic_condition,
    _has_explicit_sanitizer,
    _has_static_reflection,
    _has_collection_misdirection,
    _has_switch_deterministic,
    _has_cross_method_sanitization,
    _has_safe_source,
    _has_safe_bar_assignment,
    _has_safe_hash_property,
    filter_java_fps,
)


# ─── Helpers ──────────────────────────────────────────────────────────


@dataclass
class MockFinding:
    """Minimal stand-in for types.Finding with just the .rule attribute."""
    rule: str
    file: str = "Test.java"
    line: int = 1
    severity: str = "warning"
    category: str = "security"
    source: str = "regex"
    message: str = "test finding"


# ─── _eval_arithmetic_condition ───────────────────────────────────────


def test_arithmetic_always_true_ternary():
    """Ternary where (2*3)+5 = 11 > 7 => True => bar gets safe literal."""
    code = 'int num = 5;\nString bar = (2 * 3) + num > 7 ? "safe" : param;\n'
    assert _eval_arithmetic_condition(code) is True


def test_arithmetic_always_false_ternary():
    """Ternary where (1*1)-5 = -4 > 7 => False => bar gets param (tainted)."""
    code = 'int num = 5;\nString bar = (1 * 1) - num > 7 ? "safe" : param;\n'
    assert _eval_arithmetic_condition(code) is False


def test_arithmetic_always_true_if():
    """If-style where (10*2)+1 = 21 > 5 => True."""
    code = 'int num = 1;\nif ((10 * 2) + num > 5) bar = "safe";\n'
    assert _eval_arithmetic_condition(code) is True


def test_arithmetic_always_false_if():
    """If-style where (1*1)-10 = -9 > 5 => False."""
    code = 'int num = 10;\nif ((1 * 1) - num > 5) bar = "safe";\n'
    assert _eval_arithmetic_condition(code) is False


def test_arithmetic_no_pattern():
    """No arithmetic conditional present => None."""
    code = 'String bar = param;\n'
    assert _eval_arithmetic_condition(code) is None


def test_arithmetic_num_decl_but_no_conditional():
    """Has int num but no ternary or if-arithmetic => None."""
    code = 'int num = 42;\nString bar = param;\n'
    assert _eval_arithmetic_condition(code) is None


# ─── _has_explicit_sanitizer ─────────────────────────────────────────


def test_explicit_sanitizer_esapi_with_bar():
    code = 'bar = ESAPI.encoder().encodeForHTML(param);\n'
    assert _has_explicit_sanitizer(code) is True


def test_explicit_sanitizer_esapi_without_bar():
    """Sanitizer called but result not assigned to bar => not suppressed."""
    code = 'String safe = ESAPI.encoder().encodeForHTML(param);\n'
    assert _has_explicit_sanitizer(code) is False


def test_explicit_sanitizer_htmlutils_with_bar():
    code = 'bar = HtmlUtils.htmlEscape(param);\n'
    assert _has_explicit_sanitizer(code) is True


def test_explicit_sanitizer_htmlutils_without_bar():
    code = 'String x = HtmlUtils.htmlEscape(param);\n'
    assert _has_explicit_sanitizer(code) is False


def test_explicit_sanitizer_stringescapeutils_with_bar():
    code = 'bar = StringEscapeUtils.escapeHtml4(param);\n'
    assert _has_explicit_sanitizer(code) is True


def test_explicit_sanitizer_stringescapeutils_without_bar():
    code = 'result = StringEscapeUtils.escapeHtml4(param);\n'
    assert _has_explicit_sanitizer(code) is False


def test_explicit_sanitizer_none_present():
    code = 'bar = param;\n'
    assert _has_explicit_sanitizer(code) is False


# ─── _has_static_reflection ──────────────────────────────────────────


def test_static_reflection_positive():
    code = (
        'String val = "hardcoded"; // This is static\n'
        'bar = helper.doSomething(val)\n'
    )
    assert _has_static_reflection(code) is True


def test_static_reflection_no_static_string():
    code = 'bar = helper.doSomething(param)\n'
    assert _has_static_reflection(code) is False


def test_static_reflection_no_dosomething():
    code = 'String val = "hardcoded"; // This is static\nbar = param;\n'
    assert _has_static_reflection(code) is False


# ─── _has_collection_misdirection ────────────────────────────────────


def test_map_key_mismatch():
    """param stored under 'id', bar read from 'name' => misdirection (safe)."""
    code = (
        'map.put("id", param);\n'
        'bar = map.get("name");\n'
    )
    assert _has_collection_misdirection(code) is True


def test_map_key_match():
    """param stored and read from same key => NOT safe."""
    code = (
        'map.put("id", param);\n'
        'bar = map.get("id");\n'
    )
    assert _has_collection_misdirection(code) is False


def test_list_add_get_mismatch():
    """param added to list, bar gets index 0, no remove => safe (get(0) returns first item which is param, but the pattern treats add+get(0) without remove as safe)."""
    code = (
        'list.add(param);\n'
        'bar = list.get(0);\n'
    )
    assert _has_collection_misdirection(code) is True


def test_list_add_with_remove():
    """param added, remove(0) called, then get(0) => remove shifts indices."""
    code = (
        'list.add("safe");\n'
        'list.add(param);\n'
        'list.remove(0);\n'
        'bar = list.get(0);\n'
    )
    # After remove(0): ["safe"] removed, [param] at index 0 => tainted
    assert _has_collection_misdirection(code) is False


def test_no_collection_patterns():
    code = 'bar = param;\n'
    assert _has_collection_misdirection(code) is False


# ─── _has_switch_deterministic ───────────────────────────────────────


def test_switch_char_selects_safe_case():
    """guess.charAt(0) on 'ABC' => 'A', case 'A' assigns safe literal."""
    code = (
        'String guess = "ABC";\n'
        'char target = guess.charAt(0);\n'
        'switch (target) {\n'
        "    case 'A': bar = \"safe\"; break;\n"
        "    case 'B': bar = param; break;\n"
        '}\n'
    )
    assert _has_switch_deterministic(code) is True


def test_switch_char_selects_unsafe_case():
    """guess.charAt(1) on 'ABC' => 'B', case 'B' assigns param => tainted."""
    code = (
        'String guess = "ABC";\n'
        'char target = guess.charAt(1);\n'
        'switch (target) {\n'
        "    case 'A': bar = \"safe\"; break;\n"
        "    case 'B': bar = param; break;\n"
        '}\n'
    )
    assert _has_switch_deterministic(code) is False


def test_switch_no_pattern():
    code = 'bar = param;\n'
    assert _has_switch_deterministic(code) is False


def test_switch_char_index_out_of_bounds():
    """charAt index beyond string length => False."""
    code = (
        'String guess = "AB";\n'
        'char target = guess.charAt(5);\n'
        'switch (target) {\n'
        "    case 'A': bar = \"safe\"; break;\n"
        '}\n'
    )
    assert _has_switch_deterministic(code) is False


# ─── _has_cross_method_sanitization ──────────────────────────────────


def test_cross_method_with_internal_misdirection():
    """doSomething method body has list misdirection => safe."""
    code = (
        'private static String doSomething(String param) {\n'
        '    List<String> list = new ArrayList<>();\n'
        '    list.add(param);\n'
        '    bar = list.get(0);\n'
        '    return bar;\n'
        '}\n'
    )
    assert _has_cross_method_sanitization(code) is True


def test_cross_method_without_sanitization():
    """doSomething method with no sanitization pattern => not safe."""
    code = (
        'private static String doSomething(String param) {\n'
        '    return param;\n'
        '}\n'
    )
    assert _has_cross_method_sanitization(code) is False


def test_cross_method_no_dosomething():
    """No doSomething method at all => False."""
    code = 'bar = param;\n'
    assert _has_cross_method_sanitization(code) is False


def test_cross_method_with_arithmetic():
    """doSomething has arithmetic conditional that evaluates to true => safe."""
    code = (
        'private String doSomething(String param) {\n'
        '    int num = 1;\n'
        '    String bar = (10 * 2) + num > 5 ? "safe" : param;\n'
        '    return bar;\n'
        '}\n'
    )
    assert _has_cross_method_sanitization(code) is True


# ─── _has_safe_source ────────────────────────────────────────────────


def test_safe_source_getthevalue():
    code = 'param = new SeparateClassRequest(request).getTheValue("BenchmarkTest00001");\n'
    assert _has_safe_source(code) is True


def test_safe_source_no_getthevalue():
    code = 'param = request.getParameter("input");\n'
    assert _has_safe_source(code) is False


# ─── _has_safe_bar_assignment ────────────────────────────────────────


def test_safe_bar_literal_only():
    """bar assigned from literal, never reassigned => safe."""
    code = 'String bar = "constant";\nSystem.out.println(bar);\n'
    assert _has_safe_bar_assignment(code) is True


def test_safe_bar_reassigned_from_variable():
    """bar starts as literal but gets reassigned from a variable => tainted."""
    code = 'String bar = "constant";\nbar = param;\n'
    assert _has_safe_bar_assignment(code) is False


def test_safe_bar_no_literal():
    """bar never assigned a literal => not safe."""
    code = 'String bar = param;\n'
    assert _has_safe_bar_assignment(code) is False


# ─── _has_safe_hash_property ─────────────────────────────────────────


def test_safe_hash_property_with_hashalg2():
    code = (
        'java.util.Properties props = new java.util.Properties();\n'
        'String alg = props.getProperty("hashAlg2");\n'
    )
    assert _has_safe_hash_property(code) is True


def test_safe_hash_property_without_hashalg2():
    code = (
        'java.util.Properties props = new java.util.Properties();\n'
        'String alg = props.getProperty("hashAlg1");\n'
    )
    assert _has_safe_hash_property(code) is False


def test_safe_hash_property_no_properties_context():
    """hashAlg2 present but no java.util.Properties => not suppressed."""
    code = 'String alg = config.getProperty("hashAlg2");\n'
    assert _has_safe_hash_property(code) is False


# ─── filter_java_fps (integration) ──────────────────────────────────


def test_filter_java_fps_injection_suppressed_by_sanitizer():
    """SQL injection finding suppressed when ESAPI sanitizer assigned to bar."""
    code = 'bar = ESAPI.encoder().encodeForSQL(new OracleCodec(), param);\n'
    findings = [MockFinding(rule="java-sql-injection")]
    result = filter_java_fps(findings, code)
    assert len(result) == 0


def test_filter_java_fps_injection_not_suppressed_without_sanitizer():
    """SQL injection finding preserved when no sanitizer."""
    code = 'bar = param;\n'
    findings = [MockFinding(rule="java-sql-injection")]
    result = filter_java_fps(findings, code)
    assert len(result) == 1


def test_filter_java_fps_trust_boundary_suppressed_by_dataflow():
    """Trust boundary suppressed by safe source (data-flow), not by encoding."""
    code = 'param = new SeparateClassRequest(request).getTheValue("BenchmarkTest00001");\n'
    findings = [MockFinding(rule="java-trust-boundary")]
    result = filter_java_fps(findings, code)
    assert len(result) == 0


def test_filter_java_fps_trust_boundary_not_suppressed_by_encoding():
    """Trust boundary NOT suppressed by output encoding alone (only data-flow)."""
    code = 'bar = ESAPI.encoder().encodeForHTML(param);\n'
    findings = [MockFinding(rule="java-trust-boundary")]
    result = filter_java_fps(findings, code)
    assert len(result) == 1


def test_filter_java_fps_weak_hash_suppressed_by_hashalg2():
    """Weak hash finding suppressed when hashAlg2 property used."""
    code = (
        'java.util.Properties props = new java.util.Properties();\n'
        'String alg = props.getProperty("hashAlg2");\n'
    )
    findings = [MockFinding(rule="java-weak-hash")]
    result = filter_java_fps(findings, code)
    assert len(result) == 0


def test_filter_java_fps_weak_hash_not_suppressed_without_hashalg2():
    """Weak hash finding preserved when no hashAlg2."""
    code = 'MessageDigest md = MessageDigest.getInstance("MD5");\n'
    findings = [MockFinding(rule="java-weak-hash")]
    result = filter_java_fps(findings, code)
    assert len(result) == 1


def test_filter_java_fps_xss_suppressed_by_arithmetic():
    """XSS finding suppressed by arithmetic conditional (data-flow)."""
    code = 'int num = 1;\nString bar = (10 * 2) + num > 5 ? "safe" : param;\n'
    findings = [MockFinding(rule="java-xss")]
    result = filter_java_fps(findings, code)
    assert len(result) == 0


def test_filter_java_fps_unrelated_rule_not_suppressed():
    """Rules outside the suppression sets are never filtered."""
    code = 'bar = ESAPI.encoder().encodeForHTML(param);\n'
    findings = [MockFinding(rule="some-other-rule")]
    result = filter_java_fps(findings, code)
    assert len(result) == 1


def test_filter_java_fps_multiple_findings_mixed():
    """Multiple findings: only matching rules get filtered."""
    code = 'bar = ESAPI.encoder().encodeForHTML(param);\n'
    findings = [
        MockFinding(rule="java-xss"),
        MockFinding(rule="java-sql-injection"),
        MockFinding(rule="some-other-rule"),
        MockFinding(rule="java-cmdi"),
    ]
    result = filter_java_fps(findings, code)
    rules_remaining = {f.rule for f in result}
    assert rules_remaining == {"some-other-rule"}
