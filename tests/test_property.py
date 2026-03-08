"""Property-based tests using Hypothesis — validates invariants across random inputs."""

import ast
import os
import re
import tempfile

import pytest

try:
    from hypothesis import given, settings, assume, HealthCheck
    from hypothesis import strategies as st
    HAS_HYPOTHESIS = True
except ImportError:
    HAS_HYPOTHESIS = False

from dojigiri.types import Finding, Fix, FixSource, FixStatus, Severity, Category, Source
from dojigiri.fixer import (
    _fix_bare_except,
    _fix_none_comparison,
    _fix_type_comparison,
    _fix_mutable_default,
    _fix_eval_usage,
    _fix_unused_import,
    _fix_unused_variable,
    apply_fixes,
    DETERMINISTIC_FIXERS,
)

pytestmark = pytest.mark.skipif(not HAS_HYPOTHESIS, reason="hypothesis not installed")

# ─── Custom strategies ───────────────────────────────────────────────

PYTHON_IDENT_CHARS = "abcdefghijklmnopqrstuvwxyz_"
PYTHON_TYPES = ["int", "str", "float", "list", "dict", "tuple", "set", "bool", "bytes"]


def valid_python_source():
    """Generate syntactically valid Python source code."""
    return st.one_of(
        # Simple assignment
        st.builds(
            lambda name, val: f"{name} = {val}\n",
            st.from_regex(r"[a-z][a-z0-9_]{0,10}", fullmatch=True),
            st.sampled_from(["42", "'hello'", "[]", "{}", "None", "True", "0.5"]),
        ),
        # Simple function
        st.builds(
            lambda name, body: f"def {name}():\n    {body}\n",
            st.from_regex(r"[a-z][a-z0-9_]{0,10}", fullmatch=True),
            st.sampled_from(["pass", "return None", "return 42", "x = 1"]),
        ),
        # Import statement
        st.builds(
            lambda mod: f"import {mod}\n",
            st.sampled_from(["os", "sys", "re", "json", "math"]),
        ),
    )


def python_with_bare_except():
    """Generate Python with a bare except clause — various nesting and body forms."""
    return st.one_of(
        # Basic try/except
        st.builds(
            lambda indent, body: f"{indent}try:\n{indent}    pass\n{indent}except:\n{indent}    {body}\n",
            st.sampled_from(["", "    ", "        "]),
            st.sampled_from(["pass", "x = 1", "print(e)", "raise", "return None"]),
        ),
        # With try body content
        st.builds(
            lambda var, op: (
                f"try:\n"
                f"    {var} = {op}\n"
                f"except:\n"
                f"    {var} = None\n"
            ),
            st.from_regex(r"[a-z][a-z_]{0,6}", fullmatch=True),
            st.sampled_from(["int(x)", "open(f)", "1/0", "json.loads(s)", "next(it)"]),
        ),
        # Nested in function
        st.builds(
            lambda fname, var: (
                f"def {fname}():\n"
                f"    try:\n"
                f"        {var} = risky()\n"
                f"    except:\n"
                f"        return None\n"
            ),
            st.from_regex(r"[a-z][a-z_]{0,6}", fullmatch=True),
            st.from_regex(r"[a-z][a-z_]{0,6}", fullmatch=True),
        ),
    )


def python_with_none_comparison():
    """Generate Python with == None or != None in various contexts."""
    return st.one_of(
        # Simple if
        st.builds(
            lambda var, op: f"if {var} {op} None:\n    pass\n",
            st.from_regex(r"[a-z][a-z0-9_]{0,8}", fullmatch=True),
            st.sampled_from(["==", "!="]),
        ),
        # Attribute access
        st.builds(
            lambda obj, attr, op: f"if {obj}.{attr} {op} None:\n    pass\n",
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.sampled_from(["==", "!="]),
        ),
        # Subscript
        st.builds(
            lambda var, key, op: f"if {var}[{key!r}] {op} None:\n    pass\n",
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.sampled_from(["==", "!="]),
        ),
        # In assignment
        st.builds(
            lambda var, op: f"result = {var} {op} None\n",
            st.from_regex(r"[a-z][a-z0-9_]{0,8}", fullmatch=True),
            st.sampled_from(["==", "!="]),
        ),
    )


def python_with_type_comparison():
    """Generate Python with type(x) == Y in various forms."""
    return st.one_of(
        # Simple
        st.builds(
            lambda var, typ: f"if type({var}) == {typ}:\n    pass\n",
            st.from_regex(r"[a-z][a-z0-9_]{0,8}", fullmatch=True),
            st.sampled_from(PYTHON_TYPES),
        ),
        # Nested expression
        st.builds(
            lambda obj, attr, typ: f"if type({obj}.{attr}) == {typ}:\n    pass\n",
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.sampled_from(PYTHON_TYPES),
        ),
        # Double parens (edge case)
        st.builds(
            lambda var, typ: f"if type(({var})) == {typ}:\n    pass\n",
            st.from_regex(r"[a-z][a-z0-9_]{0,8}", fullmatch=True),
            st.sampled_from(PYTHON_TYPES),
        ),
        # Call result
        st.builds(
            lambda fn, typ: f"if type({fn}()) == {typ}:\n    pass\n",
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.sampled_from(PYTHON_TYPES),
        ),
    )


def python_with_mutable_default():
    """Generate Python function with mutable default arg — various forms."""
    return st.one_of(
        # Simple
        st.builds(
            lambda name, param, mutable: f"def {name}({param}={mutable}):\n    pass\n",
            st.from_regex(r"[a-z][a-z0-9_]{0,8}", fullmatch=True),
            st.from_regex(r"[a-z][a-z0-9_]{0,8}", fullmatch=True),
            st.sampled_from(["[]", "{}", "set()"]),
        ),
        # With preceding params
        st.builds(
            lambda name, p1, p2, mutable: f"def {name}({p1}, {p2}={mutable}):\n    return {p1}\n",
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.sampled_from(["[]", "{}"]),
        ),
        # Multiple mutable defaults
        st.builds(
            lambda name, p1, p2: f"def {name}({p1}=[], {p2}={{}}):\n    pass\n",
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
        ),
        # Method in class
        st.builds(
            lambda cls, method, param, mutable: (
                f"class {cls.title()}:\n"
                f"    def {method}(self, {param}={mutable}):\n"
                f"        pass\n"
            ),
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.sampled_from(["[]", "{}", "set()"]),
        ),
    )


def python_with_eval():
    """Generate Python using eval()."""
    return st.one_of(
        st.builds(
            lambda expr: f"result = eval({expr!r})\n",
            st.sampled_from(["1+1", "'hello'", "x", "a+b", "len(s)"]),
        ),
        st.builds(
            lambda var, expr: f"{var} = eval({expr!r})\n",
            st.from_regex(r"[a-z][a-z_]{0,5}", fullmatch=True),
            st.sampled_from(["user_input", "data", "config['key']"]),
        ),
    )


def _apply_fix_to_source(source, fix):
    """Apply a single fix to source code, returning the new source."""
    lines = source.splitlines(keepends=True)
    line_idx = fix.line - 1
    if not (0 <= line_idx < len(lines)):
        return source
    if fix.fixed_code:
        lines[line_idx] = fix.fixed_code
        if fix.end_line:
            for i in range(line_idx + 1, min(fix.end_line, len(lines))):
                lines[i] = ""
    return "".join(lines)


# ─── Invariant 1: Fixers never corrupt valid Python ──────────────────


SAFE_DETERMINISTIC_FIXERS = [
    ("bare-except", python_with_bare_except),
    ("none-comparison", python_with_none_comparison),
    ("type-comparison", python_with_type_comparison),
    ("mutable-default", python_with_mutable_default),
]


@pytest.mark.parametrize("rule,strategy_fn", SAFE_DETERMINISTIC_FIXERS)
@given(data=st.data())
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_fixer_preserves_parseable_python(rule, strategy_fn, data):
    """If source parses before fix, it must parse after fix."""
    source = data.draw(strategy_fn())

    # Verify input is valid Python
    try:
        ast.parse(source)
    except SyntaxError:
        assume(False)

    fixer = DETERMINISTIC_FIXERS[rule]
    lines = source.splitlines(keepends=True)

    # Find the correct target line — bare-except targets the except line
    target_line = 1
    if rule == "bare-except":
        for i, line in enumerate(lines, 1):
            if re.match(r"\s*except\s*:", line):
                target_line = i
                break

    finding = Finding(
        file="test.py", line=target_line, severity=Severity.WARNING,
        category=Category.BUG, source=Source.STATIC,
        rule=rule, message=f"Test {rule}",
    )

    result = fixer(lines[target_line - 1], finding, source)
    if result is None:
        return

    fixes = result if isinstance(result, list) else [result]
    for fix in fixes:
        if fix.fixed_code:
            fixed_source = _apply_fix_to_source(source, fix)
            try:
                ast.parse(fixed_source)
            except SyntaxError as e:
                pytest.fail(
                    f"Fixer '{rule}' corrupted valid Python!\n"
                    f"Input:\n{source}\n"
                    f"Output:\n{fixed_source}\n"
                    f"Error: {e}"
                )


# ─── Invariant 2: Fixers are idempotent ──────────────────────────────


@pytest.mark.parametrize("rule,strategy_fn", SAFE_DETERMINISTIC_FIXERS)
@given(data=st.data())
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_fixer_idempotent(rule, strategy_fn, data):
    """Applying a fix twice produces the same result as once."""
    source = data.draw(strategy_fn())

    try:
        ast.parse(source)
    except SyntaxError:
        assume(False)

    fixer = DETERMINISTIC_FIXERS[rule]
    lines = source.splitlines(keepends=True)

    # Find the correct target line
    target_line = 1
    if rule == "bare-except":
        for i, line in enumerate(lines, 1):
            if re.match(r"\s*except\s*:", line):
                target_line = i
                break

    finding = Finding(
        file="test.py", line=target_line, severity=Severity.WARNING,
        category=Category.BUG, source=Source.STATIC,
        rule=rule, message=f"Test {rule}",
    )

    # First application
    result1 = fixer(lines[target_line - 1], finding, source)
    if result1 is None:
        return

    fix1 = result1 if not isinstance(result1, list) else result1[0]
    if not fix1.fixed_code:
        return  # Deletion fix — idempotency trivially holds

    fixed_source = _apply_fix_to_source(source, fix1)

    # Second application on fixed source
    fixed_lines = fixed_source.splitlines(keepends=True)
    if not fixed_lines:
        return

    # Recalculate target line for the fixed source
    target_line_2 = fix1.line
    if not (0 < target_line_2 <= len(fixed_lines)):
        return

    finding2 = Finding(
        file="test.py", line=target_line_2, severity=Severity.WARNING,
        category=Category.BUG, source=Source.STATIC,
        rule=rule, message=f"Test {rule}",
    )

    result2 = fixer(fixed_lines[target_line_2 - 1], finding2, fixed_source)

    # Either no fix needed (idempotent) or same result
    if result2 is None:
        return  # No more fix needed — idempotent

    fix2 = result2 if not isinstance(result2, list) else result2[0]
    assert fix2.fixed_code == fix1.fixed_code, (
        f"Fixer '{rule}' is not idempotent!\n"
        f"Input:\n{source}\n"
        f"First fix: {fix1.fixed_code!r}\n"
        f"Second fix: {fix2.fixed_code!r}"
    )


# ─── Invariant 3: apply_fixes preserves untouched lines ──────────────


@given(
    source_lines=st.lists(
        st.from_regex(r"[a-z][a-z0-9 ]{0,30}\n", fullmatch=True),
        min_size=5, max_size=20,
    ),
    fix_line=st.integers(min_value=1, max_value=5),
)
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_apply_fixes_preserves_untouched_lines(source_lines, fix_line):
    """Lines not covered by any fix must be unchanged after apply_fixes."""
    assume(fix_line <= len(source_lines))

    content = "".join(source_lines)

    fd, tmp_path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)

        fix = Fix(
            file=tmp_path, line=fix_line, rule="test-rule",
            original_code=source_lines[fix_line - 1],
            fixed_code="REPLACED_LINE\n",
            explanation="test", source=FixSource.DETERMINISTIC,
        )

        apply_fixes(tmp_path, [fix], dry_run=False, create_backup=False)

        with open(tmp_path) as f:
            result_lines = f.readlines()

        for i, orig in enumerate(source_lines):
            if i == fix_line - 1:
                assert result_lines[i] == "REPLACED_LINE\n"
            else:
                assert result_lines[i] == orig, (
                    f"Line {i+1} was modified by apply_fixes!\n"
                    f"Original: {orig!r}\nGot: {result_lines[i]!r}"
                )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        try:
            os.unlink(tmp_path + ".doji.bak")
        except OSError:
            pass


# ─── Invariant 4: apply_fixes with multiple non-overlapping fixes ─────


@given(
    source_lines=st.lists(
        st.from_regex(r"[a-z][a-z0-9 ]{0,20}\n", fullmatch=True),
        min_size=10, max_size=30,
    ),
    data=st.data(),
)
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_apply_multiple_fixes_correct(source_lines, data):
    """Multiple non-overlapping fixes applied via apply_fixes are all correct."""
    # Pick 2-4 unique, non-adjacent fix lines
    num_fixes = data.draw(st.integers(min_value=2, max_value=min(4, len(source_lines) // 2)))
    fix_indices = sorted(data.draw(
        st.lists(
            st.integers(min_value=0, max_value=len(source_lines) - 1),
            min_size=num_fixes, max_size=num_fixes, unique=True,
        )
    ))

    content = "".join(source_lines)

    fd, tmp_path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(content)

        fixes = []
        for idx in fix_indices:
            fixes.append(Fix(
                file=tmp_path, line=idx + 1, rule="test-rule",
                original_code=source_lines[idx],
                fixed_code=f"FIXED_{idx}\n",
                explanation="test", source=FixSource.DETERMINISTIC,
            ))

        apply_fixes(tmp_path, fixes, dry_run=False, create_backup=False)

        with open(tmp_path) as f:
            result_lines = f.readlines()

        fix_line_set = set(fix_indices)
        for i, orig in enumerate(source_lines):
            if i in fix_line_set:
                assert result_lines[i] == f"FIXED_{i}\n", (
                    f"Fix at line {i+1} not applied!\n"
                    f"Expected: 'FIXED_{i}\\n'\nGot: {result_lines[i]!r}"
                )
            else:
                assert result_lines[i] == orig, (
                    f"Line {i+1} was modified but shouldn't have been!\n"
                    f"Original: {orig!r}\nGot: {result_lines[i]!r}"
                )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        try:
            os.unlink(tmp_path + ".doji.bak")
        except OSError:
            pass


# ─── Invariant 5: Detection round-trip reduces findings ──────────────


ROUNDTRIP_FIXERS = [
    ("bare-except", python_with_bare_except),
    ("none-comparison", python_with_none_comparison),
    ("type-comparison", python_with_type_comparison),
    ("mutable-default", python_with_mutable_default),
]


@pytest.mark.parametrize("rule,strategy_fn", ROUNDTRIP_FIXERS)
@given(data=st.data())
@settings(max_examples=100, suppress_health_check=[HealthCheck.too_slow])
def test_detect_fix_reduces_findings(rule, strategy_fn, data):
    """detect -> fix -> detect should find fewer (or equal) issues for the target rule."""
    from dojigiri.detector import analyze_file_static

    source = data.draw(strategy_fn())
    try:
        ast.parse(source)
    except SyntaxError:
        assume(False)

    filepath = "test_prop.py"

    # Detect
    findings_before = analyze_file_static(filepath, source, "python").findings
    rule_findings = [f for f in findings_before if f.rule == rule]
    rule_count_before = len(rule_findings)

    if rule_count_before == 0:
        return  # No finding to fix

    # Fix using apply_fixes — proper round-trip
    fixer = DETERMINISTIC_FIXERS[rule]
    fixes_to_apply = []

    for finding in rule_findings:
        lines = source.splitlines(keepends=True)
        line_idx = finding.line - 1
        if 0 <= line_idx < len(lines):
            result = fixer(lines[line_idx], finding, source)
            if result:
                result_fixes = result if isinstance(result, list) else [result]
                fixes_to_apply.extend(result_fixes)

    if not fixes_to_apply:
        return  # No fixes generated

    # Apply via file-based apply_fixes for proper round-trip
    fd, tmp_path = tempfile.mkstemp(suffix=".py")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(source)

        # Set correct file path on fixes
        for fix in fixes_to_apply:
            fix.file = tmp_path

        apply_fixes(tmp_path, fixes_to_apply, dry_run=False, create_backup=False)

        with open(tmp_path) as f:
            fixed_source = f.read()
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        try:
            os.unlink(tmp_path + ".doji.bak")
        except OSError:
            pass

    # Re-detect
    findings_after = analyze_file_static(filepath, fixed_source, "python").findings
    rule_count_after = sum(1 for f in findings_after if f.rule == rule)

    assert rule_count_after <= rule_count_before, (
        f"Fix for '{rule}' increased findings from {rule_count_before} to {rule_count_after}!\n"
        f"Before:\n{source}\n"
        f"After:\n{fixed_source}"
    )


# ─── Invariant 6: Eval fixer always produces valid Python ─────────────


@given(data=st.data())
@settings(max_examples=200, suppress_health_check=[HealthCheck.too_slow])
def test_eval_fixer_preserves_valid_python(data):
    """eval -> ast.literal_eval replacement must keep code parseable."""
    source = data.draw(python_with_eval())

    try:
        ast.parse(source)
    except SyntaxError:
        assume(False)

    fixer = DETERMINISTIC_FIXERS["eval-usage"]
    lines = source.splitlines(keepends=True)

    finding = Finding(
        file="test.py", line=1, severity=Severity.CRITICAL,
        category=Category.SECURITY, source=Source.STATIC,
        rule="eval-usage", message="Use of eval()",
    )

    result = fixer(lines[0], finding, source)
    if result is None:
        return

    fixes = result if isinstance(result, list) else [result]
    fixed_source = source
    for fix in fixes:
        if fix.fixed_code:
            fixed_source = _apply_fix_to_source(fixed_source, fix)

    try:
        ast.parse(fixed_source)
    except SyntaxError as e:
        pytest.fail(
            f"eval fixer corrupted Python!\n"
            f"Input:\n{source}\nOutput:\n{fixed_source}\nError: {e}"
        )
