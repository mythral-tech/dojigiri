"""Tests for intra-procedural taint analysis (dojigiri.semantic.taint).

~30 comprehensive tests covering source detection, sink detection,
taint propagation, sanitization, end-to-end scenarios, and cross-language support.
"""

import pytest

from dojigiri.semantic.core import extract_semantics
from dojigiri.semantic.taint import analyze_taint, TaintSource, TaintSink, TaintPath
from dojigiri.semantic.lang_config import get_config, LanguageConfig
from dojigiri.types import Severity, Category, Source

try:
    from tree_sitter_language_pack import get_parser
    HAS_TREE_SITTER = True
except ImportError:
    HAS_TREE_SITTER = False

needs_tree_sitter = pytest.mark.skipif(
    not HAS_TREE_SITTER, reason="tree-sitter-language-pack not installed"
)


# ─── Helper ──────────────────────────────────────────────────────────────────

def _analyze_python(code: str):
    """Extract semantics and run taint analysis on Python code."""
    config = get_config("python")
    sem = extract_semantics(code, "test.py", "python")
    if sem is None:
        return []
    source_bytes = code.encode("utf-8")
    return analyze_taint(sem, source_bytes, config, "test.py")


def _analyze_js(code: str):
    """Extract semantics and run taint analysis on JavaScript code."""
    config = get_config("javascript")
    sem = extract_semantics(code, "test.js", "javascript")
    if sem is None:
        return []
    source_bytes = code.encode("utf-8")
    return analyze_taint(sem, source_bytes, config, "test.js")


# ─── Source Detection ────────────────────────────────────────────────────────

@needs_tree_sitter
class TestSourceDetection:
    """Verify that taint sources are correctly identified from assignments."""

    def test_input_is_user_input_source(self):
        """input() should be detected as a user_input taint source."""
        code = '''
def foo():
    x = input("Enter: ")
    eval(x)
'''
        findings = _analyze_python(code)
        assert len(findings) >= 1
        f = findings[0]
        assert "user_input" in f.message
        assert "input" in f.message

    def test_os_environ_get_is_env_var_source(self):
        """os.environ.get() should be detected as an env_var taint source."""
        code = '''
def foo():
    secret = os.environ.get("API_KEY")
    eval(secret)
'''
        findings = _analyze_python(code)
        assert len(findings) >= 1
        f = findings[0]
        assert "env_var" in f.message

    def test_regular_assignment_not_a_source(self):
        """A plain assignment with a literal should not be a taint source."""
        code = '''
def foo():
    x = 42
    eval(x)
'''
        findings = _analyze_python(code)
        assert len(findings) == 0

    def test_sys_argv_is_user_input_source(self):
        """sys.argv should be detected as a user_input taint source."""
        code = '''
def foo():
    arg = sys.argv[1]
    eval(arg)
'''
        findings = _analyze_python(code)
        assert len(findings) >= 1
        f = findings[0]
        assert "user_input" in f.message

    def test_file_read_is_file_read_source(self):
        """.read() should be detected as a file_read taint source."""
        code = '''
def foo():
    data = f.read()
    eval(data)
'''
        findings = _analyze_python(code)
        assert len(findings) >= 1
        f = findings[0]
        assert "file_read" in f.message

    def test_request_form_is_user_input_source(self):
        """request.form should be detected as a user_input taint source."""
        code = '''
def handle():
    name = request.form["name"]
    eval(name)
'''
        findings = _analyze_python(code)
        assert len(findings) >= 1
        f = findings[0]
        assert "user_input" in f.message


# ─── Sink Detection ─────────────────────────────────────────────────────────

@needs_tree_sitter
class TestSinkDetection:
    """Verify that taint sinks are correctly identified when tainted data flows in."""

    def test_eval_with_tainted_input(self):
        """eval() called with tainted data should produce a finding."""
        code = '''
def foo():
    x = input()
    eval(x)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1
        f = findings[0]
        assert f.rule == "taint-flow"
        assert f.severity == Severity.WARNING
        assert f.category == Category.SECURITY
        assert "eval" in f.message

    def test_os_system_with_tainted_cmd(self):
        """os.system() called with tainted cmd should produce a finding."""
        code = '''
def foo():
    cmd = input("Command: ")
    os.system(cmd)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1
        f = findings[0]
        assert "system" in f.message.lower() or "os.system" in f.message

    def test_cursor_execute_with_tainted_query(self):
        """cursor.execute() called with tainted query should produce a finding."""
        code = '''
def foo():
    query = input("SQL: ")
    cursor.execute(query)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1
        f = findings[0]
        assert "execute" in f.message

    def test_subprocess_run_with_tainted_cmd(self):
        """subprocess.run() called with tainted cmd should produce a finding."""
        code = '''
def foo():
    cmd = input("Run: ")
    subprocess.run(cmd)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1
        f = findings[0]
        assert "subprocess" in f.message or "system_cmd" in f.message

    def test_safe_call_no_taint(self):
        """Calling a non-sink function with untainted data should not produce findings."""
        code = '''
def foo():
    x = "hello"
    print(x)
'''
        findings = _analyze_python(code)
        assert len(findings) == 0

    def test_exec_with_tainted_code(self):
        """exec() called with tainted code should produce a finding."""
        code = '''
def foo():
    code = input("Code: ")
    exec(code)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1
        f = findings[0]
        assert "exec" in f.message


# ─── Propagation ─────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestTaintPropagation:
    """Verify taint flows through variable assignments."""

    def test_direct_taint_source_to_sink(self):
        """Taint flows directly from source variable to sink."""
        code = '''
def foo():
    x = input()
    eval(x)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1

    def test_one_hop_propagation(self):
        """Taint propagates through one intermediate assignment."""
        code = '''
def foo():
    x = input()
    y = x
    eval(y)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1
        f = findings[0]
        # The finding should mention the chain
        assert "y" in f.message or "x" in f.message

    def test_two_hop_propagation(self):
        """Taint propagates through two intermediate assignments."""
        code = '''
def foo():
    x = input()
    y = x
    z = y
    eval(z)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1
        f = findings[0]
        assert "taint" in f.message.lower() or "Tainted" in f.message

    def test_no_propagation_to_unrelated_var(self):
        """Taint does not propagate to a variable assigned from an unrelated source."""
        code = '''
def foo():
    x = input()
    y = 42
    eval(y)
'''
        findings = _analyze_python(code)
        assert len(findings) == 0

    def test_augmented_assignment_propagates(self):
        """Taint propagates through augmented assignment (+=)."""
        code = '''
def foo():
    x = input()
    x += " extra"
    eval(x)
'''
        findings = _analyze_python(code)
        assert len(findings) >= 1

    def test_string_concatenation_propagates(self):
        """Taint propagates through string concatenation."""
        code = '''
def foo():
    user_input = input()
    query = "SELECT * FROM users WHERE id = " + user_input
    cursor.execute(query)
'''
        findings = _analyze_python(code)
        assert len(findings) >= 1
        f = findings[0]
        assert "execute" in f.message


# ─── Sanitization ────────────────────────────────────────────────────────────

@needs_tree_sitter
class TestSanitization:
    """Verify that sanitizer calls suppress findings."""

    def test_html_escape_sanitizes(self):
        """html.escape() should sanitize tainted data and suppress the finding."""
        code = '''
def foo():
    x = input()
    x = html.escape(x)
    eval(x)
'''
        findings = _analyze_python(code)
        assert len(findings) == 0

    def test_bleach_clean_sanitizes(self):
        """bleach.clean() should sanitize tainted data and suppress the finding."""
        code = '''
def foo():
    x = input()
    x = bleach.clean(x)
    eval(x)
'''
        findings = _analyze_python(code)
        assert len(findings) == 0

    def test_unsanitized_produces_finding(self):
        """Without any sanitizer, tainted data at a sink should produce a finding."""
        code = '''
def foo():
    x = input()
    eval(x)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1

    def test_sanitizer_on_different_var_still_flagged(self):
        """Sanitizing a different variable with a non-configured sanitizer should not suppress the finding.

        Note: _is_sanitized checks for any configured sanitizer call anywhere in
        the function scope (flow-insensitive), so we use a non-sanitizer function
        to demonstrate that a random function call on another var does not suppress.
        """
        code = '''
def foo():
    x = input()
    y = "safe"
    y = str.upper(y)
    eval(x)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1
        f = findings[0]
        assert "x" in f.message

    def test_reassignment_through_sanitizer_clears_taint(self):
        """A tainted variable reassigned via a sanitizer should NOT remain tainted.

        Regression test: previously, _propagate_taint skipped already-tainted vars
        on reassignment, so sanitization via reassignment was ignored.
        """
        code = '''
def process():
    user_input = input("name: ")
    sanitized = html.escape(user_input)
    eval(sanitized)
'''
        findings = _analyze_python(code)
        # sanitized should NOT be tainted — html.escape is a sanitizer
        assert len(findings) == 0

    def test_tainted_var_reassigned_clean_clears_propagation(self):
        """If a tainted var is reassigned to a sanitized value, downstream should be clean."""
        code = '''
def process():
    data = input("data: ")
    data = bleach.clean(data)
    query = data
    cursor.execute(query)
'''
        findings = _analyze_python(code)
        # data was sanitized by bleach.clean, so query (assigned from data) should be clean
        assert len(findings) == 0


# ─── End-to-End Scenarios ────────────────────────────────────────────────────

@needs_tree_sitter
class TestEndToEnd:
    """Full scenario tests combining source, propagation, sink."""

    def test_sql_injection(self):
        """Classic SQL injection: user input concatenated into a query string."""
        code = '''
def get_user():
    user_id = input("Enter user ID: ")
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
'''
        findings = _analyze_python(code)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule == "taint-flow"
        assert f.severity == Severity.WARNING
        assert f.category == Category.SECURITY
        assert f.source == Source.AST
        assert "execute" in f.message
        assert "sql_query" in f.message or "cursor" in f.message

    def test_command_injection(self):
        """Command injection: user input passed directly to os.system()."""
        code = '''
def run():
    cmd = input("Enter command: ")
    os.system(cmd)
'''
        findings = _analyze_python(code)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule == "taint-flow"
        assert "system" in f.message.lower() or "system_cmd" in f.message

    def test_safe_code_no_taint_sources(self):
        """Code with no taint sources should produce no findings."""
        code = '''
def safe():
    x = 10
    y = x + 5
    print(y)
'''
        findings = _analyze_python(code)
        assert len(findings) == 0

    def test_taint_in_one_function_sink_in_another(self):
        """Taint in one function should not affect a sink in another (intra-procedural)."""
        code = '''
def get_data():
    x = input()
    return x

def process():
    y = "safe"
    eval(y)
'''
        findings = _analyze_python(code)
        assert len(findings) == 0

    def test_multiple_taint_paths_in_same_function(self):
        """Multiple taint sources reaching different sinks should produce multiple findings."""
        code = '''
def vulnerable():
    user_cmd = input("cmd: ")
    user_query = input("query: ")
    os.system(user_cmd)
    cursor.execute(user_query)
'''
        findings = _analyze_python(code)
        assert len(findings) >= 2
        rules = {f.rule for f in findings}
        assert rules == {"taint-flow"}
        severities = {f.severity for f in findings}
        assert severities == {Severity.WARNING}


# ─── Cross-Language Tests ────────────────────────────────────────────────────

@needs_tree_sitter
class TestCrossLanguage:
    """Verify taint analysis works across different language configs."""

    def test_javascript_req_body_to_eval(self):
        """JavaScript: req.body flowing to eval() should produce a finding."""
        code = '''
function handle(req, res) {
    const data = req.body.input;
    eval(data);
}
'''
        findings = _analyze_js(code)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule == "taint-flow"
        assert f.severity == Severity.WARNING
        assert f.category == Category.SECURITY
        assert "eval" in f.message

    def test_no_taint_patterns_returns_empty(self):
        """A config with no taint patterns should return an empty list."""
        code = '''
def foo():
    x = input()
    eval(x)
'''
        config = LanguageConfig(
            ts_language_name="python",
            taint_source_patterns=[],
            taint_sink_patterns=[],
            taint_sanitizer_patterns=[],
        )
        sem = extract_semantics(code, "test.py", "python")
        if sem is None:
            pytest.skip("tree-sitter unavailable")
        source_bytes = code.encode("utf-8")
        findings = analyze_taint(sem, source_bytes, config, "test.py")
        assert findings == []

    def test_config_with_empty_source_patterns(self):
        """A config with source patterns empty but sink patterns set should return nothing."""
        code = '''
def foo():
    x = input()
    eval(x)
'''
        config = LanguageConfig(
            ts_language_name="python",
            taint_source_patterns=[],
            taint_sink_patterns=[("eval", "eval")],
            taint_sanitizer_patterns=[],
        )
        sem = extract_semantics(code, "test.py", "python")
        if sem is None:
            pytest.skip("tree-sitter unavailable")
        source_bytes = code.encode("utf-8")
        findings = analyze_taint(sem, source_bytes, config, "test.py")
        assert findings == []


# ─── Finding Attribute Tests ─────────────────────────────────────────────────

@needs_tree_sitter
class TestFindingAttributes:
    """Verify that finding objects have the correct fields and values."""

    def test_finding_file_path(self):
        """Finding should reference the correct file path."""
        code = '''
def foo():
    x = input()
    eval(x)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1
        assert findings[0].file == "test.py"

    def test_finding_has_suggestion(self):
        """Finding should include a remediation suggestion."""
        code = '''
def foo():
    x = input()
    eval(x)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1
        f = findings[0]
        assert f.suggestion is not None
        assert len(f.suggestion) > 0
        assert "sanitize" in f.suggestion.lower() or "parameterized" in f.suggestion.lower()

    def test_finding_message_mentions_source_and_sink(self):
        """Finding message should mention both the source variable and the sink function."""
        code = '''
def foo():
    cmd = input("run: ")
    os.system(cmd)
'''
        findings = _analyze_python(code)
        assert len(findings) == 1
        f = findings[0]
        assert "cmd" in f.message
        assert "os.system" in f.message or "system" in f.message
