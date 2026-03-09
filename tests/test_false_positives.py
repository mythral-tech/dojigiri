"""False-positive tests — safe code that must NOT trigger findings.

For each major rule, write code that looks similar to a pattern but is actually safe.
These verify that Dojigiri doesn't cry wolf on legitimate code.
"""

import pytest
from dojigiri.ast_checks import run_python_ast_checks
from dojigiri.detector import run_regex_checks, analyze_file_static


# ─── hardcoded-secret: dynamic assignment should NOT trigger ─────────


def test_fp_secret_from_env():
    """Dynamic secret via os.environ.get() is not a hardcoded secret."""
    code = 'secret = os.environ.get("SECRET")\n'
    findings = run_regex_checks(code, "app.py", "python")
    assert not any(f.rule == "hardcoded-secret" for f in findings)


def test_fp_secret_placeholder_value():
    """Placeholder values like 'your-key-here' are excluded."""
    code = 'api_key = "your_key_here"\n'
    findings = run_regex_checks(code, "app.py", "python")
    assert not any(f.rule == "hardcoded-secret" for f in findings)


def test_fp_secret_empty_string():
    """Empty or short string assignment is not a secret."""
    code = 'password = ""\n'
    findings = run_regex_checks(code, "app.py", "python")
    assert not any(f.rule == "hardcoded-secret" for f in findings)


def test_fp_secret_test_prefix():
    """Values starting with 'test' are excluded as placeholders."""
    code = 'token = "test_placeholder"\n'
    findings = run_regex_checks(code, "app.py", "python")
    assert not any(f.rule == "hardcoded-secret" for f in findings)


# ─── sql-injection: parameterized queries should NOT trigger ─────────


def test_fp_sql_parameterized_tuple():
    """Parameterized query with ? placeholder is safe."""
    code = 'cursor.execute("SELECT * FROM t WHERE id = ?", (user_id,))\n'
    findings = run_regex_checks(code, "app.py", "python")
    sql = [f for f in findings if f.rule == "sql-injection"]
    assert len(sql) == 0


def test_fp_sql_constant_string():
    """Fully constant SQL string with no interpolation is safe."""
    code = 'cursor.execute("SELECT COUNT(*) FROM users")\n'
    findings = run_regex_checks(code, "app.py", "python")
    sql = [f for f in findings if f.rule == "sql-injection"]
    assert len(sql) == 0


# ─── eval-usage: eval in comments should NOT trigger ─────────────────


def test_fp_eval_in_comment():
    """eval() in a comment line should be skipped."""
    code = '# eval("dangerous code")  # just a note\n'
    findings = run_regex_checks(code, "app.py", "python")
    assert not any(f.rule == "eval-usage" for f in findings)


def test_fp_eval_in_docstring():
    """eval() inside a docstring should not trigger."""
    code = '"""\nExample: eval("1+1")\n"""\ndef safe(): pass\n'
    findings = run_regex_checks(code, "app.py", "python")
    assert not any(f.rule == "eval-usage" for f in findings)


# ─── shell-true / os-system: subprocess with list args ───────────────


def test_fp_subprocess_list_args():
    """subprocess.run with list args (no shell=True) is safe from shell-true."""
    code = 'subprocess.run(["git", "status"], capture_output=True)\n'
    findings = run_regex_checks(code, "app.py", "python")
    assert not any(f.rule == "shell-true" for f in findings)
    assert not any(f.rule == "os-system" for f in findings)


def test_fp_subprocess_list_no_audit():
    """subprocess.run([ should not trigger subprocess-audit (list = safe)."""
    code = 'subprocess.run(["ls", "-la"])\n'
    findings = run_regex_checks(code, "app.py", "python")
    # subprocess-audit only fires when NOT using list args
    assert not any(f.rule == "subprocess-audit" for f in findings)


# ─── bare-except: specific exception types should NOT trigger ────────


def test_fp_except_specific_type():
    """except ValueError: is not a bare except."""
    code = 'try:\n    int(x)\nexcept ValueError:\n    pass\n'
    findings = run_regex_checks(code, "app.py", "python")
    assert not any(f.rule == "bare-except" for f in findings)


def test_fp_except_exception_class():
    """except Exception: is not a bare except (it's specific enough for the regex)."""
    code = 'try:\n    do_thing()\nexcept Exception:\n    handle()\n'
    findings = run_regex_checks(code, "app.py", "python")
    assert not any(f.rule == "bare-except" for f in findings)


def test_fp_except_tuple():
    """except (KeyError, ValueError): is not a bare except."""
    code = 'try:\n    d[k]\nexcept (KeyError, ValueError):\n    default()\n'
    findings = run_regex_checks(code, "app.py", "python")
    assert not any(f.rule == "bare-except" for f in findings)


# ─── yaml-unsafe: safe_load should NOT trigger ───────────────────────


def test_fp_yaml_safe_load():
    """yaml.safe_load() is safe — no yaml-unsafe finding."""
    code = 'data = yaml.safe_load(file_handle)\n'
    findings = run_regex_checks(code, "app.py", "python")
    assert not any(f.rule == "yaml-unsafe" for f in findings)


# ─── unused-import: used imports should NOT be flagged ───────────────


def test_fp_used_import_not_flagged():
    """An import that is actually used should not be flagged as unused."""
    code = 'import os\n\nresult = os.path.exists("file.txt")\n'
    findings = run_python_ast_checks(code, "app.py")
    assert not any(f.rule == "unused-import" for f in findings)


# ─── shadowed-builtin: idiomatic names excluded ─────────────────────


def test_fp_type_and_id_not_shadowed():
    """'type' and 'id' as variable names are excluded (idiomatic usage)."""
    code = 'def func():\n    type = "string"\n    id = 42\n'
    findings = run_python_ast_checks(code, "app.py")
    shadowed = [f for f in findings if f.rule == "shadowed-builtin"]
    names = " ".join(f.message for f in shadowed)
    assert "'type'" not in names
    assert "'id'" not in names
