"""Tests for enhanced taint tracking (dojigiri.taint_cross).

Covers intra-file variable indirection, multi-hop propagation, f-string taint,
function parameter taint, and cross-file taint analysis.
"""

import pytest

from dojigiri.taint_cross import (
    TaintVar,
    analyze_taint_ast,
    analyze_taint_cross_file,
)
from dojigiri.types import Category, Severity, Source


# ─── Intra-file: Variable indirection ────────────────────────────────────────


class TestVariableIndirection:
    """The core gap: variable indirection where a tainted value is assigned
    to a variable and then passed to a sink."""

    def test_simple_variable_indirection_sql(self):
        """query = f"SELECT {user_input}"; conn.execute(query) — the primary use case."""
        code = '''
def handle(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    conn.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule == "taint-flow"
        assert f.severity == Severity.WARNING  # parameter source = speculative
        assert f.category == Category.SECURITY
        assert "execute" in f.message

    def test_multi_hop_variable_chain(self):
        """a = input(); b = f"SELECT {a}"; c = b; execute(c) — three hops."""
        code = '''
def handle():
    a = input()
    b = f"SELECT * FROM users WHERE id = {a}"
    c = b
    cursor.execute(c)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1
        assert any("execute" in f.message for f in findings)

    def test_string_concat_indirection(self):
        """Taint via string concatenation then variable."""
        code = '''
def handle(user_id):
    query = "SELECT * FROM users WHERE id = " + user_id
    cursor.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1
        assert any("execute" in f.message for f in findings)

    def test_format_method_indirection(self):
        """Taint via .format() then variable."""
        code = '''
def handle(name):
    query = "SELECT * FROM users WHERE name = '{}'".format(name)
    cursor.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1

    def test_percent_format_indirection(self):
        """Taint via % formatting then variable."""
        code = '''
def handle(name):
    query = "SELECT * FROM users WHERE name = '%s'" % name
    cursor.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1

    def test_no_taint_clean_variable(self):
        """Clean variable passed to sink — no finding."""
        code = '''
def handle():
    query = "SELECT * FROM users"
    cursor.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) == 0

    def test_sanitized_variable_no_finding(self):
        """Tainted variable sanitized before reaching sink."""
        code = '''
def handle(user_input):
    safe = int(user_input)
    query = f"SELECT * FROM users WHERE id = {safe}"
    cursor.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) == 0


# ─── Intra-file: F-string taint ──────────────────────────────────────────────


class TestFStringTaint:
    """F-string interpolation propagates taint."""

    def test_fstring_with_tainted_var(self):
        """f"SELECT {tainted}" produces tainted result."""
        code = '''
def handle(user_input):
    query = f"SELECT * FROM users WHERE name = '{user_input}'"
    cursor.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1

    def test_fstring_with_clean_var(self):
        """f"SELECT {clean}" with a literal — no finding."""
        code = '''
def handle():
    table = "users"
    query = f"SELECT * FROM {table}"
    cursor.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) == 0

    def test_fstring_mixed_vars(self):
        """f-string with both tainted and clean variables — should flag."""
        code = '''
def handle(user_input):
    table = "users"
    query = f"SELECT * FROM {table} WHERE name = '{user_input}'"
    cursor.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1


# ─── Intra-file: Function parameter taint ────────────────────────────────────


class TestParameterTaint:
    """Function parameters should be treated as potential taint sources."""

    def test_param_directly_to_sink(self):
        """def f(x): eval(x) — parameter flows directly to sink."""
        code = '''
def process(user_data):
    eval(user_data)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1
        assert any("parameter" in f.message for f in findings)

    def test_param_through_variable_to_sink(self):
        """def f(x): y = x; eval(y) — parameter through variable indirection."""
        code = '''
def process(user_data):
    cmd = user_data
    eval(cmd)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1

    def test_param_to_os_system(self):
        """Parameter flows to os.system()."""
        code = '''
def run_command(cmd):
    os.system(cmd)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1
        assert any("system" in f.message for f in findings)

    def test_self_param_not_tainted(self):
        """'self' parameter should not be treated as tainted."""
        code = '''
class MyClass:
    def process(self, data):
        eval(data)
'''
        findings = analyze_taint_ast("test.py", code)
        taint_findings = [f for f in findings if f.rule == "taint-flow"]
        # Should find data→eval but NOT self→eval
        for f in taint_findings:
            assert "self" not in f.message.split("'")[1]  # First quoted name


# ─── Intra-file: Taint through function return values ────────────────────────


class TestFunctionReturnTaint:
    """Taint propagation through function return values within a file."""

    def test_input_source_to_sink(self):
        """input() → variable → sink."""
        code = '''
def handle():
    name = input("Name: ")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    conn.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1

    def test_request_args_to_sink(self):
        """request.args → variable → sink."""
        code = '''
def handle():
    name = request.args.get("name")
    query = f"SELECT * FROM users WHERE name = '{name}'"
    conn.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1
        assert any("user_input" in f.message for f in findings)


# ─── Cross-file taint analysis ───────────────────────────────────────────────


class TestCrossFileTaint:
    """Cross-file taint tracking via imports."""

    def test_basic_cross_file_sql_injection(self):
        """The primary cross-file case from the spec:
        utils.py has get_query(user_input) that builds SQL.
        views.py imports get_query and calls it with request data.
        """
        files = {
            "utils.py": '''
def get_query(user_input):
    return f"SELECT * FROM users WHERE name = '{user_input}'"
''',
            "views.py": '''
from utils import get_query

def handle(request_name):
    query = get_query(request_name)
    conn.execute(query)
''',
        }
        findings = analyze_taint_cross_file(files)
        assert len(findings) >= 1
        # Should mention the cross-file flow
        f = findings[0]
        assert f.rule == "taint-flow-cross-file"
        assert f.severity == Severity.WARNING
        assert f.category == Category.SECURITY

    def test_no_cross_file_clean_function(self):
        """A clean imported function should not produce findings."""
        files = {
            "utils.py": '''
def add(a, b):
    return a + b
''',
            "views.py": '''
from utils import add

def handle():
    result = add(1, 2)
    print(result)
''',
        }
        findings = analyze_taint_cross_file(files)
        assert len(findings) == 0

    def test_cross_file_param_to_sink(self):
        """Imported function passes parameter directly to a sink."""
        files = {
            "db.py": '''
def run_query(query):
    cursor.execute(query)
''',
            "views.py": '''
from db import run_query

def handle(user_input):
    query = f"SELECT * FROM users WHERE id = {user_input}"
    run_query(query)
''',
        }
        findings = analyze_taint_cross_file(files)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule == "taint-flow-cross-file"
        assert "execute" in f.message or "sql_query" in f.message

    def test_single_file_no_cross_file(self):
        """With a single file, cross-file analysis returns nothing."""
        files = {
            "app.py": '''
def handle():
    name = input()
    eval(name)
''',
        }
        findings = analyze_taint_cross_file(files)
        assert len(findings) == 0

    def test_non_python_files_ignored(self):
        """Non-Python files should be skipped."""
        files = {
            "utils.js": 'function getQuery(input) { return "SELECT " + input; }',
            "views.py": '''
from utils import get_query

def handle():
    pass
''',
        }
        findings = analyze_taint_cross_file(files)
        assert len(findings) == 0


# ─── Finding attributes ──────────────────────────────────────────────────────


class TestFindingAttributes:
    """Verify finding objects have correct fields."""

    def test_finding_has_correct_source(self):
        """AST taint findings should have Source.AST."""
        code = '''
def handle(user_input):
    query = f"SELECT {user_input}"
    conn.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1
        assert findings[0].source == Source.AST

    def test_finding_has_suggestion(self):
        """Findings should include remediation suggestions."""
        code = '''
def handle(user_input):
    eval(user_input)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1
        f = findings[0]
        assert f.suggestion is not None
        assert "sanitize" in f.suggestion.lower() or "parameterized" in f.suggestion.lower()

    def test_finding_references_correct_file(self):
        """Finding should reference the analyzed file."""
        code = '''
def handle(user_input):
    eval(user_input)
'''
        findings = analyze_taint_ast("myfile.py", code)
        assert len(findings) >= 1
        assert findings[0].file == "myfile.py"


# ─── Edge cases ──────────────────────────────────────────────────────────────


class TestEdgeCases:
    """Edge cases and boundary conditions."""

    def test_syntax_error_returns_empty(self):
        """Invalid Python syntax should return empty list, not crash."""
        code = "def handle(:\n    pass"
        findings = analyze_taint_ast("test.py", code)
        assert findings == []

    def test_empty_function(self):
        """Empty function body — no findings."""
        code = '''
def handle():
    pass
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) == 0

    def test_nested_function_taint(self):
        """Taint in nested function should be tracked independently."""
        code = '''
def outer():
    def inner(data):
        eval(data)
    x = input()
    inner(x)
'''
        findings = analyze_taint_ast("test.py", code)
        # Should find taint in inner (parameter → eval)
        assert any("eval" in f.message for f in findings)

    def test_augmented_assignment_preserves_taint(self):
        """Augmented assignment (+=) on a tainted variable keeps it tainted."""
        code = '''
def handle(user_input):
    query = user_input
    query += " extra"
    eval(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1

    def test_multiple_sinks_same_function(self):
        """Multiple sinks in the same function — should produce multiple findings."""
        code = '''
def handle(user_input):
    eval(user_input)
    os.system(user_input)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 2

    def test_taint_in_if_body(self):
        """Taint flow inside an if body should be detected."""
        code = '''
def handle(user_input):
    if True:
        query = f"SELECT {user_input}"
        cursor.execute(query)
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1

    def test_taint_in_try_body(self):
        """Taint flow inside a try block should be detected."""
        code = '''
def handle(user_input):
    try:
        eval(user_input)
    except Exception:
        pass
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1


# ─── Class attribute taint tracking ──────────────────────────────────────────


class TestClassAttributeTaint:
    """Track self.x assignments from __init__ into other methods."""

    def test_param_to_attr_to_sql_sink(self):
        """self.table_name from param → f-string execute → taint-flow finding."""
        code = '''
class VectorDB:
    def __init__(self, table_name):
        self.table_name = table_name

    def delete(self, ids):
        placeholders = ",".join(ids)
        cursor.execute(f"DELETE FROM {self.table_name} WHERE id IN ({placeholders})")
'''
        findings = analyze_taint_ast("test.py", code)
        assert len(findings) >= 1
        f = findings[0]
        assert f.rule == "taint-flow"
        assert "self.table_name" in f.message
        assert f.severity == Severity.WARNING  # parameter source

    def test_literal_attr_no_finding(self):
        """self.table_name from literal → no taint finding."""
        code = '''
class VectorDB:
    def __init__(self):
        self.table_name = "users"

    def query(self):
        cursor.execute(f"SELECT * FROM {self.table_name}")
'''
        findings = analyze_taint_ast("test.py", code)
        sql_taint = [f for f in findings if f.rule == "taint-flow"]
        assert len(sql_taint) == 0

    def test_config_attr_no_finding(self):
        """self.table_name from config constant → no taint finding."""
        code = '''
class VectorDB:
    def __init__(self, config):
        self.table_name = "embeddings"
        self.schema = "public"

    def create_table(self):
        cursor.execute(f"CREATE TABLE {self.schema}.{self.table_name} (id INT)")
'''
        findings = analyze_taint_ast("test.py", code)
        sql_taint = [f for f in findings if f.rule == "taint-flow"]
        assert len(sql_taint) == 0

    def test_mixed_attrs_only_tainted_flagged(self):
        """Only tainted attrs produce findings, clean ones don't."""
        code = '''
class DB:
    def __init__(self, user_table, safe_limit=100):
        self.user_table = user_table  # tainted (param)
        self.default_limit = 100      # clean (literal)

    def query(self):
        cursor.execute(f"SELECT * FROM {self.user_table} LIMIT {self.default_limit}")
'''
        findings = analyze_taint_ast("test.py", code)
        taint_findings = [f for f in findings if f.rule == "taint-flow"]
        assert len(taint_findings) >= 1
        assert any("self.user_table" in f.message for f in taint_findings)

    def test_attr_propagation_through_local(self):
        """self.x assigned from local var that came from param."""
        code = '''
class DB:
    def __init__(self, raw_name):
        name = raw_name.strip()
        self.table_name = name

    def drop(self):
        cursor.execute(f"DROP TABLE {self.table_name}")
'''
        findings = analyze_taint_ast("test.py", code)
        taint_findings = [f for f in findings if f.rule == "taint-flow"]
        assert len(taint_findings) >= 1

    def test_no_init_no_crash(self):
        """Class without __init__ should not crash."""
        code = '''
class Helper:
    def run(self):
        cursor.execute(f"SELECT 1")
'''
        findings = analyze_taint_ast("test.py", code)
        assert isinstance(findings, list)
