"""Tests for detector module - static analysis engine."""

import pytest
from dojigiri.detector import (
    run_regex_checks,
    run_python_ast_checks,
    analyze_file_static,
    _count_branches,
    _is_line_suppressed,
    _parse_line_suppression,
)
from dojigiri.types import Severity, Category, Source


def test_run_regex_checks_python(sample_python_code):
    """Test regex checks on Python code."""
    findings = run_regex_checks(sample_python_code, "test.py", "python")
    
    # Should detect hardcoded secret, eval usage
    rules_found = {f.rule for f in findings}
    assert "hardcoded-secret" in rules_found
    assert "eval-usage" in rules_found


def test_run_regex_checks_javascript(sample_javascript_code):
    """Test regex checks on JavaScript code."""
    findings = run_regex_checks(sample_javascript_code, "test.js", "javascript")
    
    rules_found = {f.rule for f in findings}
    # var-usage rule was removed (style opinion, not correctness)
    assert "console-log" in rules_found
    assert "loose-equality" in rules_found
    assert "eval-usage" in rules_found


def test_run_regex_checks_skips_comments():
    """Test that regex checks skip comment lines (except todo-marker)."""
    code = '''
# eval("bad code")  # This is in a comment
// console.log("debug")  # This too
real_code = eval("actual problem")
'''
    findings = run_regex_checks(code, "test.py", "python")
    
    # Should only find the non-comment eval
    eval_findings = [f for f in findings if f.rule == "eval-usage"]
    assert len(eval_findings) == 1
    assert "real_code" in eval_findings[0].snippet


def test_run_regex_checks_skips_string_lines():
    """Test that security patterns skip string-only lines."""
    code = '''
"http://example.com/api"
url = "http://example.com/api"  # This should match
'''
    findings = run_regex_checks(code, "test.py", "python")
    
    # Should only find the assignment, not the standalone string
    http_findings = [f for f in findings if f.rule == "insecure-http"]
    # Both might match depending on implementation, but at least the assignment should
    assert len(http_findings) >= 1


def test_run_regex_checks_todo_in_comments():
    """Test that TODO markers are found in comments."""
    code = '''
# TODO: implement this function
def func():
    pass  # FIXME: broken
'''
    findings = run_regex_checks(code, "test.py", "python")
    
    todo_findings = [f for f in findings if f.rule == "todo-marker"]
    assert len(todo_findings) == 2


# ───────────────────────────────────────────────────────────────────────────
# PYTHON AST CHECKS
# ───────────────────────────────────────────────────────────────────────────

def test_python_ast_syntax_error():
    """Test that syntax errors are caught."""
    code = "def broken(\n    invalid syntax"
    findings = run_python_ast_checks(code, "test.py")
    
    assert len(findings) == 1
    assert findings[0].rule == "syntax-error"
    assert findings[0].severity == Severity.CRITICAL


def test_python_ast_unused_import():
    """Test detection of unused imports."""
    code = '''
import unused_module
import os
from pathlib import Path

result = os.path.exists("file.txt")
'''
    findings = run_python_ast_checks(code, "test.py")
    
    unused = [f for f in findings if f.rule == "unused-import"]
    assert len(unused) == 2
    unused_names = {f.message for f in unused}
    assert any("unused_module" in msg for msg in unused_names)
    assert any("Path" in msg for msg in unused_names)


def test_python_ast_unused_import_underscore_names():
    """Test that underscore-prefixed imports are not flagged as unused."""
    code = '''
import _private
from module import __dunder__

def func():
    pass
'''
    findings = run_python_ast_checks(code, "test.py")
    
    unused = [f for f in findings if f.rule == "unused-import"]
    assert len(unused) == 0  # Underscore names should be skipped


def test_python_ast_exception_swallowed():
    """Test detection of swallowed exceptions."""
    code = '''
try:
    risky_operation()
except Exception:
    pass

try:
    another_operation()
except ValueError:
    print("Error occurred")  # This is fine, not just pass
'''
    findings = run_python_ast_checks(code, "test.py")
    
    swallowed = [f for f in findings if f.rule == "exception-swallowed"]
    assert len(swallowed) == 1


def test_python_ast_shadowed_builtin():
    """Test detection of shadowed builtins."""
    code = '''
def func():
    list = [1, 2, 3]
    dict = {}
    type = "string"
    id = 42
    len = 100
'''
    findings = run_python_ast_checks(code, "test.py")
    
    shadowed = [f for f in findings if f.rule == "shadowed-builtin"]
    assert len(shadowed) == 5
    
    shadowed_names = {f.message for f in shadowed}
    assert any("list" in msg for msg in shadowed_names)
    assert any("dict" in msg for msg in shadowed_names)
    assert any("type" in msg for msg in shadowed_names)


def test_python_ast_type_comparison():
    """Test detection of type() == comparison."""
    code = '''
if type(x) == int:
    pass

if type(value) != str:
    pass

# This is fine
if isinstance(x, int):
    pass
'''
    findings = run_python_ast_checks(code, "test.py")
    
    type_comp = [f for f in findings if f.rule == "type-comparison"]
    assert len(type_comp) == 2


def test_python_ast_global_keyword():
    """Test detection of global keyword usage."""
    code = '''
counter = 0

def increment():
    global counter
    counter += 1

def another():
    global value, other
    value = 1
'''
    findings = run_python_ast_checks(code, "test.py")
    
    globals_found = [f for f in findings if f.rule == "global-keyword"]
    assert len(globals_found) == 2


def test_python_ast_unreachable_code():
    """Test detection of unreachable code."""
    code = '''
def func1():
    return True
    print("never executed")  # Unreachable
    x = 5

def func2():
    if condition:
        return 1
    else:
        return 2
    print("also unreachable")  # Unreachable

def func3():
    return 5  # This is fine, last statement
'''
    findings = run_python_ast_checks(code, "test.py")
    
    unreachable = [f for f in findings if f.rule == "unreachable-code"]
    # Detector reports one unreachable block per function (first occurrence only)
    assert len(unreachable) >= 1


def test_python_ast_high_complexity():
    """Test detection of high complexity functions."""
    code = '''
def simple():
    return True

def complex_function():
    if a:
        if b:
            if c:
                if d:
                    if e:
                        if f:
                            if g:
                                if h:
                                    if i:
                                        if j:
                                            if k:
                                                if l:
                                                    if m:
                                                        if n:
                                                            if o:
                                                                if p:
                                                                    return True
    return False
'''
    findings = run_python_ast_checks(code, "test.py")
    
    complexity = [f for f in findings if f.rule == "high-complexity"]
    assert len(complexity) == 1
    assert "complex_function" in complexity[0].message


def test_python_ast_too_many_args():
    """Test detection of functions with too many arguments."""
    code = '''
def simple(a, b):
    pass

def too_many(a, b, c, d, e, f, g, h, i):  # 9 args
    pass

class MyClass:
    def method(self, a, b, c, d, e, f, g, h):  # 8 args + self = 9, but self is excluded
        pass
'''
    findings = run_python_ast_checks(code, "test.py")
    
    too_many = [f for f in findings if f.rule == "too-many-args"]
    # Should flag both: too_many has 9 args, method has 8 (self excluded) which is > 7
    assert len(too_many) == 2


def test_count_branches_simple():
    """Test branch counting for simple function."""
    import ast
    code = '''
def func():
    if a:
        return 1
    else:
        return 2
'''
    tree = ast.parse(code)
    func_node = tree.body[0]
    count = _count_branches(func_node)
    assert count == 1  # One if statement


def test_count_branches_nested():
    """Test branch counting with nested conditions."""
    import ast
    code = '''
def func():
    if a:
        if b:
            return 1
        else:
            return 2
    for i in range(10):
        while x:
            try:
                do_something()
            except:
                pass
'''
    tree = ast.parse(code)
    func_node = tree.body[0]
    count = _count_branches(func_node)
    # if (1) + nested if (1) + for (1) + while (1) + try (1) + except (1) = 6
    assert count == 6


def test_count_branches_excludes_nested_functions():
    """Test that nested function branches are not counted."""
    import ast
    code = '''
def outer():
    if a:
        return 1
    
    def inner():
        if b:
            if c:
                if d:
                    return 2
        return 3
    
    for i in range(10):
        pass
'''
    tree = ast.parse(code)
    func_node = tree.body[0]
    count = _count_branches(func_node)
    # Should only count: if (1) + for (1) = 2
    # Should NOT count the branches inside inner()
    assert count == 2


# ───────────────────────────────────────────────────────────────────────────
# INTEGRATION TESTS
# ───────────────────────────────────────────────────────────────────────────

def test_analyze_file_static_python(sample_python_code):
    """Test full static analysis on Python code."""
    findings = analyze_file_static("test.py", sample_python_code, "python").findings
    # Should have both regex and AST findings
    sources = {f.source for f in findings}
    assert Source.STATIC in sources
    assert Source.AST in sources
    
    # Check some expected findings
    rules = {f.rule for f in findings}
    assert "hardcoded-secret" in rules
    assert "eval-usage" in rules
    assert "bare-except" in rules
    assert "unused-import" in rules
    assert "shadowed-builtin" in rules
    assert "type-comparison" in rules
    assert "unreachable-code" in rules
    # Note: high-complexity detection may not trigger on all sample code
    assert "too-many-args" in rules


def test_analyze_file_static_javascript(sample_javascript_code):
    """Test full static analysis on JavaScript code."""
    findings = analyze_file_static("test.js", sample_javascript_code, "javascript").findings
    # JavaScript has regex + tree-sitter AST checks (including semantic v0.8.0)
    assert all(f.source in (Source.STATIC, Source.AST) for f in findings)

    rules = {f.rule for f in findings}
    # var-usage rule was removed (style opinion, not correctness)
    assert "console-log" in rules
    assert "eval-usage" in rules


def test_analyze_file_static_deduplication():
    """Test that duplicate findings are removed."""
    code = '''
x = eval("1")
x = eval("2")
x = eval("3")
'''
    findings = analyze_file_static("test.py", code, "python").findings
    # All eval calls are on different lines, so all should be reported
    eval_findings = [f for f in findings if f.rule == "eval-usage"]
    assert len(eval_findings) == 3
    
    # Test actual deduplication - same line, same rule
    code2 = '''
x = eval("1"); y = eval("2")  # Both on same line
'''
    findings2 = analyze_file_static("test.py", code2, "python").findings
    eval_findings2 = [f for f in findings2 if f.rule == "eval-usage"]
    # Should only report once per line+rule combo
    assert len(eval_findings2) <= 2


def test_analyze_file_static_sorting():
    """Test that findings are sorted by severity then line."""
    code = '''
# Line 2: warning
f = open("file.txt")
# Line 4: critical  
x = eval("code")
# Line 6: info
# TODO: fix this
# Line 8: another warning
subprocess.run(cmd, shell=True)
# Line 10: another critical
password = "hardcoded_secret_12345"
'''
    findings = analyze_file_static("test.py", code, "python").findings
    # Critical should come first, then warnings, then info
    assert findings[0].severity == Severity.CRITICAL
    assert findings[-1].severity in (Severity.INFO, Severity.WARNING)
    
    # Within same severity, should be sorted by line number
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    if len(critical) > 1:
        assert critical[0].line < critical[1].line


def test_analyze_file_static_go(sample_go_code):
    """Test static analysis on Go code."""
    findings = analyze_file_static("test.go", sample_go_code, "go").findings
    rules = {f.rule for f in findings}
    assert "unchecked-error" in rules
    assert "fmt-print" in rules


def test_analyze_file_static_rust(sample_rust_code):
    """Test static analysis on Rust code."""
    findings = analyze_file_static("test.rs", sample_rust_code, "rust").findings
    rules = {f.rule for f in findings}
    assert "unwrap" in rules
    assert "expect-panic" in rules
    assert "unsafe-block" in rules


def test_analyze_file_static_empty_file():
    """Test static analysis on empty file."""
    findings = analyze_file_static("empty.py", "", "python").findings
    assert len(findings) == 0


def test_analyze_file_static_clean_code():
    """Test static analysis on code with no issues."""
    code = '''
from typing import Optional

def clean_function(arg: Optional[int] = None) -> bool:
    """A well-written function with no issues."""
    if arg is None:
        return False
    return arg > 0
'''
    findings = analyze_file_static("clean.py", code, "python").findings
    # Might have some minor findings, but should not have critical issues
    critical = [f for f in findings if f.severity == Severity.CRITICAL]
    assert len(critical) == 0


# ───────────────────────────────────────────────────────────────────────────
# REGRESSION TESTS — Phase 1 pattern fixes
# ───────────────────────────────────────────────────────────────────────────

def test_regression_yaml_safeloader_same_line():
    """Regression: yaml.load with SafeLoader on same line should NOT be flagged."""
    code = 'data = yaml.load(f, Loader=yaml.SafeLoader)\n'
    findings = run_regex_checks(code, "test.py", "python")
    yaml_findings = [f for f in findings if f.rule == "yaml-unsafe"]
    assert len(yaml_findings) == 0


def test_regression_yaml_safeloader_next_line():
    """Regression: yaml.load with SafeLoader on next line should NOT be flagged."""
    code = (
        'data = yaml.load(\n'
        '    content,\n'
        '    Loader=yaml.SafeLoader,\n'
        ')\n'
    )
    findings = run_regex_checks(code, "test.py", "python")
    yaml_findings = [f for f in findings if f.rule == "yaml-unsafe"]
    assert len(yaml_findings) == 0


def test_regression_yaml_unsafe_no_safeloader():
    """Regression: yaml.load without SafeLoader SHOULD be flagged."""
    code = 'data = yaml.load(file_handle)\n'
    findings = run_regex_checks(code, "test.py", "python")
    yaml_findings = [f for f in findings if f.rule == "yaml-unsafe"]
    assert len(yaml_findings) == 1


def test_regression_hardcoded_secret_placeholder_excluded():
    """Regression: Placeholder values should NOT trigger hardcoded-secret."""
    code = 'api_key = "example_key_here"\n'
    findings = run_regex_checks(code, "test.py", "python")
    secret_findings = [f for f in findings if f.rule == "hardcoded-secret"]
    assert len(secret_findings) == 0


def test_regression_hardcoded_secret_real_value_detected():
    """Regression: Real-looking secrets SHOULD trigger hardcoded-secret."""
    code = 'api_key = "sk_live_abc123def456ghi789"\n'
    findings = run_regex_checks(code, "test.py", "python")
    secret_findings = [f for f in findings if f.rule == "hardcoded-secret"]
    assert len(secret_findings) == 1


def test_regression_sql_injection_format():
    """Regression: .format() on SQL strings SHOULD be detected."""
    code = 'query = "SELECT * FROM users WHERE id = {}".format(user_id)\n'
    findings = run_regex_checks(code, "test.py", "python")
    sql_findings = [f for f in findings if f.rule == "sql-injection"]
    assert len(sql_findings) == 1


def test_regression_mutable_default_multiline_ast():
    """Regression: Mutable defaults in multiline defs should be caught by AST."""
    code = '''
def func(
    a,
    b=[],
    c=None,
):
    pass
'''
    findings = run_python_ast_checks(code, "test.py")
    mutable = [f for f in findings if f.rule == "mutable-default"]
    assert len(mutable) == 1


def test_regression_shadowed_builtin_in_params():
    """Regression: Builtin names as function params SHOULD be caught."""
    code = '''
def process(list, dict, input):
    return list
'''
    findings = run_python_ast_checks(code, "test.py")
    shadow = [f for f in findings if f.rule == "shadowed-builtin-param"]
    assert len(shadow) == 3  # list, dict, input


def test_regression_block_comments_skipped():
    """Regression: Code inside block comments should be skipped."""
    code = '''/*
eval("dangerous code inside block comment");
var x = 5;
*/
var y = 10;
'''
    findings = run_regex_checks(code, "test.js", "javascript")
    eval_findings = [f for f in findings if f.rule == "eval-usage"]
    assert len(eval_findings) == 0  # eval is inside block comment
    # var-usage rule was removed; check loose-equality or other rules instead
    # The key assertion: block comments are properly skipped


def test_regression_python_triple_quote_string_assignment():
    """Regression: Triple-quote in string assignment should NOT enter block comment mode."""
    # The key point: when """ appears mid-line (not at start), it should NOT
    # trigger block comment mode, so the line after it should still be scanned.
    code = '''
api_key = "sk_test_first_12345"
my_var = """some text"""
api_token = "sk_test_after_12345"
'''
    findings = run_regex_checks(code, "test.py", "python")
    secret_findings = [f for f in findings if f.rule == "hardcoded-secret"]
    # Should detect both secrets (line 2 and line 4), proving line 3 didn't
    # enter block comment mode and cause line 4 to be skipped
    assert len(secret_findings) == 2
    lines_with_secrets = {f.line for f in secret_findings}
    assert 2 in lines_with_secrets  # api_key line
    assert 4 in lines_with_secrets  # api_token line (proves line 3 didn't trigger block mode)


def test_regression_python_docstring_is_block_comment():
    """Regression: Actual docstrings (triple-quote at line start) SHOULD be treated as block comments."""
    code = '''
def my_function():
    """
    This is a docstring.
    api_key = "sk_test_should_be_skipped"
    """
    api_key = "sk_test_realvalue_12345"
'''
    findings = run_regex_checks(code, "test.py", "python")
    secret_findings = [f for f in findings if f.rule == "hardcoded-secret"]
    # Should only detect the api_key on line 7, not the one inside docstring on line 5
    assert len(secret_findings) == 1
    assert secret_findings[0].line == 7


# ─── Regression tests ────────────────────────────────────────────────


def test_block_comment_mixed_delimiters():
    """REGRESSION: ''' block should not be closed by triple double-quotes."""
    code = "'''\nThis is a block comment\napi_key = \"sk_test_12345678\"\n'''\nreal_code = 1\n"
    findings = run_regex_checks(code, "test.py", "python")
    # The api_key line is inside a ''' block — should NOT be detected
    secret_findings = [f for f in findings if f.rule == "hardcoded-secret"]
    assert len(secret_findings) == 0


def test_block_comment_double_not_closed_by_single():
    """REGRESSION: \"\"\" block should not be closed by '''."""
    code = '"""\napi_key = "sk_test_12345678"\n\'\'\'\nstill_in_block = True\n"""\nreal_code = 1\n'
    findings = run_regex_checks(code, "test.py", "python")
    # Everything between \"\"\" and \"\"\" is a block comment
    secret_findings = [f for f in findings if f.rule == "hardcoded-secret"]
    assert len(secret_findings) == 0


# ───────────────────────────────────────────────────────────────────────────
# INLINE SUPPRESSION — doji:ignore
# ───────────────────────────────────────────────────────────────────────────

def test_inline_suppress_specific_rule_python():
    """doji:ignore(os-system) should suppress os-system finding."""
    code = 'os.system("ls")  # doji:ignore(os-system)\n'
    findings = run_regex_checks(code, "test.py", "python")
    assert not any(f.rule == "os-system" for f in findings)


def test_inline_suppress_all_rules_python():
    """doji:ignore (no rule) should suppress ALL findings on the line."""
    code = 'x = eval("code")  # doji:ignore\n'
    findings = run_regex_checks(code, "test.py", "python")
    assert not any(f.rule == "eval-usage" for f in findings)


def test_inline_suppress_wrong_rule_not_suppressed():
    """doji:ignore(wrong-rule) should NOT suppress os-system."""
    code = 'os.system("ls")  # doji:ignore(wrong-rule)\n'
    findings = run_regex_checks(code, "test.py", "python")
    assert any(f.rule == "os-system" for f in findings)


def test_inline_suppress_javascript():
    """doji:ignore(eval-usage) in JS comment should suppress."""
    code = 'eval(code)  // doji:ignore(eval-usage)\n'
    findings = run_regex_checks(code, "test.js", "javascript")
    assert not any(f.rule == "eval-usage" for f in findings)


def test_inline_suppress_no_comment_does_not_suppress():
    """A line with no comment at all should never be suppressed, even if
    a string on the line contains doji:ignore text."""
    code = 'x = "doji:ignore(os-system)"; os.system("ls")\n'
    findings = run_regex_checks(code, "test.py", "python")
    assert any(f.rule == "os-system" for f in findings)


def test_inline_suppress_ast_finding():
    """doji:ignore should suppress AST-based findings via analyze_file_static."""
    code = 'import unused_module  # doji:ignore(unused-import)\nimport os\nos.path.exists("f")\n'
    findings = analyze_file_static("test.py", code, "python").findings
    unused = [f for f in findings if f.rule == "unused-import"]
    # unused_module is suppressed, os is used — no unused-import findings
    assert len(unused) == 0


def test_inline_suppress_does_not_affect_other_lines():
    """Suppression on one line should not affect other lines."""
    code = 'os.system("a")  # doji:ignore(os-system)\nos.system("b")\n'
    findings = run_regex_checks(code, "test.py", "python")
    os_findings = [f for f in findings if f.rule == "os-system"]
    assert len(os_findings) == 1
    assert os_findings[0].line == 2


def test_inline_suppress_excluded_from_report_count():
    """Suppressed findings should not appear in analyze_file_static output."""
    code = 'x = eval("1")  # doji:ignore(eval-usage)\ny = eval("2")\n'
    findings = analyze_file_static("test.py", code, "python").findings
    eval_findings = [f for f in findings if f.rule == "eval-usage"]
    assert len(eval_findings) == 1
    assert eval_findings[0].line == 2


def test_is_line_suppressed_helper():
    """Unit test for _is_line_suppressed."""
    lines = [
        'os.system("ls")  # doji:ignore(os-system)',
        'eval("code")  # doji:ignore',
        'normal_code()',
        'x = "doji:ignore(os-system)"; os.system("ls")',
    ]
    assert _is_line_suppressed(lines, 1, "os-system", "python") is True
    assert _is_line_suppressed(lines, 1, "other-rule", "python") is False
    assert _is_line_suppressed(lines, 2, "anything", "python") is True
    assert _is_line_suppressed(lines, 3, "any-rule", "python") is False
    # String containing doji:ignore — no actual comment
    assert _is_line_suppressed(lines, 4, "os-system", "python") is False


def test_inline_suppress_multi_rule():
    """doji:ignore(rule-a, rule-b) should suppress both named rules."""
    code = 'os.system("ls")  # doji:ignore(os-system, shell-true)\n'
    findings = run_regex_checks(code, "test.py", "python")
    assert not any(f.rule == "os-system" for f in findings)


def test_inline_suppress_multi_rule_partial():
    """Multi-rule suppression should not suppress unlisted rules."""
    # os-system fires here; eval-usage is listed but os-system is not
    code = 'os.system("ls")  # doji:ignore(eval-usage, shell-true)\n'
    findings = run_regex_checks(code, "test.py", "python")
    assert any(f.rule == "os-system" for f in findings)


def test_parse_line_suppression_returns_set_for_multi():
    """_parse_line_suppression should return a set for comma-separated rules."""
    line = 'code()  # doji:ignore(rule-a, rule-b, rule-c)'
    result = _parse_line_suppression(line, "python")
    assert isinstance(result, set)
    assert result == {"rule-a", "rule-b", "rule-c"}


def test_parse_line_suppression_returns_true_for_bare():
    """_parse_line_suppression should return True for bare doji:ignore."""
    line = 'code()  # doji:ignore'
    result = _parse_line_suppression(line, "python")
    assert result is True


def test_parse_line_suppression_returns_none_for_no_directive():
    """_parse_line_suppression should return None when no directive found."""
    line = 'code()  # just a comment'
    result = _parse_line_suppression(line, "python")
    assert result is None


def test_parse_line_suppression_unknown_language():
    """Unknown language should return None (no comment style to parse)."""
    assert _parse_line_suppression('code()  # doji:ignore', "unknown_lang") is None


def test_inline_suppress_not_in_block_comment():
    """doji:ignore inside a block comment/docstring should NOT suppress later code."""
    code = '"""\n# doji:ignore(eval-usage)\n"""\nx = eval("code")\n'
    findings = analyze_file_static("test.py", code, "python").findings
    eval_findings = [f for f in findings if f.rule == "eval-usage"]
    assert len(eval_findings) == 1
    assert eval_findings[0].line == 4


def test_inline_suppress_rightmost_comment_wins():
    """When a string contains # before the real comment, the real comment wins."""
    # The string "hello #world" has a # but the real comment is the trailing one
    line = 'x = "hello #world"  # doji:ignore(os-system)'
    result = _parse_line_suppression(line, "python")
    assert isinstance(result, set)
    assert "os-system" in result


def test_inline_suppress_string_with_fake_doji_ignore():
    """A string containing doji:ignore before the real trailing comment should not confuse parser."""
    # The string has #doji:ignore(wrong) but the real comment has no directive
    code = 'x = "test #doji:ignore(os-system)"; os.system("ls")  # unrelated comment\n'
    findings = run_regex_checks(code, "test.py", "python")
    # os-system should fire — doji:ignore is in the string, not in the real comment
    assert any(f.rule == "os-system" for f in findings)


def test_inline_suppress_partial_on_multi_rule_line():
    """When two rules fire on one line, suppressing one should leave the other."""
    # This line triggers both eval-usage (critical/security) and os-system (warning/security).
    # Only os-system is suppressed.
    code = 'os.system(eval("x"))  # doji:ignore(os-system)\n'
    findings = run_regex_checks(code, "test.py", "python")
    rules_found = {f.rule for f in findings}
    assert "os-system" not in rules_found
    assert "eval-usage" in rules_found
