"""Tests for languages module - regex rule compilation and pattern matching."""

import pytest
import re
from dojigiri.languages import (
    get_rules_for_language,
    UNIVERSAL_RULES,
    PYTHON_RULES,
    JAVASCRIPT_RULES,
    JAVA_RULES,
    GO_RULES,
    RUST_RULES,
    SECURITY_RULES,
)
from dojigiri.types import Severity, Category


def test_get_rules_for_language_python():
    """Test that Python gets universal + security + python rules."""
    rules = get_rules_for_language("python")
    
    # Should have all rule groups combined
    expected_count = len(UNIVERSAL_RULES) + len(SECURITY_RULES) + len(PYTHON_RULES)
    assert len(rules) == expected_count


def test_get_rules_for_language_javascript():
    """Test that JavaScript gets universal + security + javascript rules."""
    rules = get_rules_for_language("javascript")
    
    expected_count = len(UNIVERSAL_RULES) + len(SECURITY_RULES) + len(JAVASCRIPT_RULES)
    assert len(rules) == expected_count


def test_get_rules_for_language_typescript():
    """Test that TypeScript gets JavaScript rules plus TS-specific rules."""
    from dojigiri.rules import TYPESCRIPT_RULES

    rules_ts = get_rules_for_language("typescript")
    rules_js = get_rules_for_language("javascript")

    assert len(rules_ts) == len(rules_js) + len(TYPESCRIPT_RULES)
    assert len(TYPESCRIPT_RULES) > 0


def test_get_rules_for_language_go():
    """Test that Go gets universal + security + go rules."""
    rules = get_rules_for_language("go")
    
    expected_count = len(UNIVERSAL_RULES) + len(SECURITY_RULES) + len(GO_RULES)
    assert len(rules) == expected_count


def test_get_rules_for_language_rust():
    """Test that Rust gets universal + security + rust rules."""
    rules = get_rules_for_language("rust")
    
    expected_count = len(UNIVERSAL_RULES) + len(SECURITY_RULES) + len(RUST_RULES)
    assert len(rules) == expected_count


def test_get_rules_for_language_unknown():
    """Test that unknown languages get only universal + security rules."""
    rules = get_rules_for_language("unknown")
    
    expected_count = len(UNIVERSAL_RULES) + len(SECURITY_RULES)
    assert len(rules) == expected_count


# ───────────────────────────────────────────────────────────────────────────
# UNIVERSAL RULES
# ───────────────────────────────────────────────────────────────────────────

def test_universal_hardcoded_secret():
    """Test detection of hardcoded secrets."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "hardcoded-secret")[0]

    # Should match (real-looking secrets)
    assert pattern.search('api_key = "abc123defgh456"')
    assert pattern.search('secret_key: "token_xyz_1234567890"')
    assert pattern.search('password="Pass123456"')
    assert pattern.search("TOKEN = 'abcdefgh12345678'")

    # Should NOT match (too short)
    assert not pattern.search('api_key = "short"')
    assert not pattern.search('password=""')

    # Should NOT match (common placeholder values)
    assert not pattern.search('api_key = "example_key_here"')
    assert not pattern.search('password = "changeme12345"')
    assert not pattern.search('token = "test_token_value"')
    assert not pattern.search('api_key = "your_api_key_here"')
    assert not pattern.search('password = "placeholder_value"')


def test_universal_aws_credentials():
    """Test detection of AWS credentials."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "aws-credentials")[0]
    
    # Should match (with optional underscore/hyphen between aws and access/secret)
    assert pattern.search('aws_access="AKIAIOSFODNN7EXAMPLE"')
    assert pattern.search('AWS_SECRET="SecretKey123456789"')
    assert pattern.search('aws-access="AKIAIOSFODNN7EXAMPLE"')
    assert pattern.search('awsaccess: "AKIAIOSFODNN7EXAMPLE"')
    
    # Should NOT match (too short)
    assert not pattern.search('aws_key = "short"')


def test_universal_todo_marker():
    """Test TODO/FIXME detection in comments."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "todo-marker")[0]
    
    # Should match (with comment prefix)
    assert pattern.search("# TODO: fix this")
    assert pattern.search("// TODO: implement")
    assert pattern.search("# FIXME urgent")
    assert pattern.search("// HACK workaround")
    assert pattern.search("# XXX check this")
    
    # Should NOT match (no comment prefix)
    assert not pattern.search("TODO: not in comment")
    assert not pattern.search("FIXME without prefix")


def test_universal_long_line():
    """Test long line detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "long-line")[0]
    
    # Should match (>200 chars)
    long_line = "x" * 201
    assert pattern.search(long_line)
    
    # Should NOT match (<=200 chars)
    short_line = "x" * 200
    assert not pattern.search(short_line)


def test_universal_insecure_http():
    """Test insecure HTTP detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "insecure-http")[0]
    
    # Should match (non-localhost HTTP)
    assert pattern.search('"http://example.com"')
    assert pattern.search("'http://api.service.com'")
    
    # Should NOT match (HTTPS or localhost)
    assert not pattern.search('"https://example.com"')
    assert not pattern.search('"http://localhost"')
    assert not pattern.search('"http://127.0.0.1"')
    assert not pattern.search('"http://0.0.0.0"')


def test_universal_sql_injection():
    """Test SQL injection pattern detection (split into specific variants)."""
    rules = get_rules_for_language("python")
    # sql-injection was split into sql-injection-execute, sql-injection-format, etc.
    pattern_execute = next(r for r in rules if r[3] == "sql-injection-execute")[0]
    pattern_concat = next(r for r in rules if r[3] == "sql-injection-concat")[0]
    pattern_percent = next(r for r in rules if r[3] == "sql-injection-percent")[0]

    # Should match (string interpolation in queries)
    assert pattern_execute.search('execute(f"SELECT * FROM {table}")')
    assert pattern_concat.search("'SELECT * FROM ' + table")
    assert pattern_percent.search('"SELECT %s" % data')


# ───────────────────────────────────────────────────────────────────────────
# PYTHON RULES
# ───────────────────────────────────────────────────────────────────────────

def test_python_bare_except():
    """Test bare except detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "bare-except")[0]
    
    # Should match
    assert pattern.search("except:")
    assert pattern.search("    except:")
    
    # Should NOT match
    assert not pattern.search("except Exception:")
    assert not pattern.search("except ValueError:")


def test_python_mutable_default():
    """Test mutable default argument detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "mutable-default")[0]
    
    # Should match
    assert pattern.search("def func(arg=[])")
    assert pattern.search("def func(arg={})")
    assert pattern.search("def func(arg=set())")
    assert pattern.search("def func(a, b=[], c=5)")
    
    # Should NOT match
    assert not pattern.search("def func(arg=None)")
    assert not pattern.search("def func(arg=5)")
    assert not pattern.search("def func(arg='string')")


def test_python_none_comparison():
    """Test None comparison detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "none-comparison")[0]
    
    # Should match
    assert pattern.search("if x == None:")
    assert pattern.search("if value != None:")
    
    # Should NOT match
    assert not pattern.search("if x is None:")
    assert not pattern.search("if x is not None:")


def test_python_eval_usage():
    """Test eval() detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "eval-usage")[0]
    
    # Should match
    assert pattern.search("result = eval(user_input)")
    assert pattern.search("x = eval('1 + 1')")
    
    # Should NOT match (need word boundary)
    assert not pattern.search("evaluate_expression()")  # 'eval' part of larger word


def test_python_exec_usage():
    """Test exec() detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "exec-usage")[0]
    
    # Should match
    assert pattern.search("exec(code)")
    assert pattern.search("exec('print(1)')")


def test_python_open_without_with():
    """Test file open without with statement."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "open-without-with")[0]
    
    # Should match
    assert pattern.search("f = open('file.txt')")
    assert pattern.search("    file = open('data.json')")
    
    # Should NOT match
    assert not pattern.search("with open('file.txt') as f:")
    assert not pattern.search("    with open('file.txt') as f:")


def test_python_os_system():
    """Test os.system() detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "os-system")[0]
    
    # Should match
    assert pattern.search("os.system('ls')")
    assert pattern.search("result = os.system(cmd)")


def test_python_shell_true():
    """Test subprocess with shell=True detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "shell-true")[0]
    
    # Should match
    assert pattern.search("subprocess.run(cmd, shell=True)")
    assert pattern.search("subprocess.Popen(cmd, shell=True)")
    assert pattern.search("subprocess.call(cmd, shell = True)")


def test_python_star_import():
    """Test star import detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "star-import")[0]
    
    # Should match
    assert pattern.search("from module import *")
    assert pattern.search("from package.module import *")
    
    # Should NOT match
    assert not pattern.search("from module import Class")
    assert not pattern.search("import module")


def test_python_assert_statement():
    """Test assert statement detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "assert-statement")[0]
    
    # Should match
    assert pattern.search("assert x > 0")
    assert pattern.search("    assert value is not None")
    
    # Should NOT match (not at start of statement)
    assert not pattern.search("# assert is dangerous")


def test_python_fstring_no_expr():
    """Test f-string without expression."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "fstring-no-expr")[0]
    
    # Should match (no expressions)
    assert pattern.search('f"hello world"')
    assert pattern.search("f'static string'")
    
    # Should NOT match (has expressions)
    assert not pattern.search('f"hello {name}"')
    assert not pattern.search("f'value: {x}'")


def test_python_pickle_unsafe():
    """Test unsafe pickle detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "pickle-unsafe")[0]
    
    # Should match
    assert pattern.search("data = pickle.load(file)")
    assert pattern.search("obj = pickle.loads(bytes)")


def test_python_yaml_unsafe():
    """Test unsafe yaml.load detection.

    The regex now matches ALL yaml.load( calls — SafeLoader suppression
    is done at the detector level (context-aware, handles multiline).
    """
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "yaml-unsafe")[0]

    # Regex should match any yaml.load( call
    assert pattern.search("data = yaml.load(file)")
    assert pattern.search("config = yaml.load(content)")
    assert pattern.search("yaml.load(f, Loader=yaml.SafeLoader)")  # regex matches; detector suppresses


def test_python_weak_hash():
    """Test weak hash algorithm detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "weak-hash")[0]
    
    # Should match
    assert pattern.search("h = hashlib.md5()")
    assert pattern.search("hash = hashlib.sha1()")
    
    # Should NOT match
    assert not pattern.search("h = hashlib.sha256()")
    assert not pattern.search("hash = hashlib.sha512()")


def test_python_weak_random():
    """Test weak random detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "weak-random")[0]
    
    # Should match
    assert pattern.search("x = random.choice(items)")
    assert pattern.search("num = random.randint(1, 100)")
    assert pattern.search("val = random.random()")
    assert pattern.search("random.shuffle(list)")


# ───────────────────────────────────────────────────────────────────────────
# JAVASCRIPT RULES
# ───────────────────────────────────────────────────────────────────────────

def test_javascript_var_usage_removed():
    """Test that var-usage rule has been removed (it's a style opinion, not a bug).

    Users who want it can add it as a custom rule via .doji.toml.
    """
    rules = get_rules_for_language("javascript")
    rule_names = {r[3] for r in rules}
    assert "var-usage" not in rule_names


def test_javascript_loose_equality():
    """Test loose equality (==) detection."""
    rules = get_rules_for_language("javascript")
    pattern = next(r for r in rules if r[3] == "loose-equality")[0]
    
    # Should match
    assert pattern.search("if (x == 5)")
    assert pattern.search("x == y")
    
    # Should NOT match
    assert not pattern.search("if (x === 5)")
    assert not pattern.search("x !== y")
    assert not pattern.search("x = 5")  # assignment


def test_javascript_console_log():
    """Test console.log detection."""
    rules = get_rules_for_language("javascript")
    pattern = next(r for r in rules if r[3] == "console-log")[0]
    
    # Should match
    assert pattern.search("console.log('debug');")
    assert pattern.search("console.log(value)")


def test_javascript_eval():
    """Test eval() detection."""
    rules = get_rules_for_language("javascript")
    pattern = next(r for r in rules if r[3] == "eval-usage")[0]
    
    # Should match
    assert pattern.search("eval(userInput)")
    assert pattern.search("result = eval('1 + 1')")


def test_javascript_innerhtml():
    """Test innerHTML assignment detection."""
    rules = get_rules_for_language("javascript")
    pattern = next(r for r in rules if r[3] == "innerhtml")[0]
    
    # Should match
    assert pattern.search("element.innerHTML = html")
    assert pattern.search("div.innerHTML = '<div>test</div>'")


def test_javascript_insert_adjacent_html():
    """Test insertAdjacentHTML detection."""
    rules = get_rules_for_language("javascript")
    pattern = next(r for r in rules if r[3] == "insert-adjacent-html")[0]
    
    # Should match
    assert pattern.search("element.insertAdjacentHTML('beforeend', html)")


def test_javascript_document_write():
    """Test document.write detection."""
    rules = get_rules_for_language("javascript")
    pattern = next(r for r in rules if r[3] == "document-write")[0]
    
    # Should match
    assert pattern.search("document.write('<div>test</div>')")
    assert pattern.search("document.write(content)")


# ───────────────────────────────────────────────────────────────────────────
# GO RULES
# ───────────────────────────────────────────────────────────────────────────

def test_go_unchecked_error():
    """Test unchecked error detection."""
    rules = get_rules_for_language("go")
    pattern = next(r for r in rules if r[3] == "unchecked-error")[0]
    
    # Should match (pattern requires := for declaration assignment)
    # Pattern: ^\s*\w+(?:,\s*_)\s*[:=]= matches := but not single =
    assert pattern.match("result, _ := operation()")
    assert pattern.match("    value, _ := getValue()")  # With leading whitespace


def test_go_fmt_print():
    """Test fmt.Print detection."""
    rules = get_rules_for_language("go")
    pattern = next(r for r in rules if r[3] == "fmt-print")[0]
    
    # Should match
    assert pattern.search("fmt.Println(value)")
    assert pattern.search("fmt.Print(x)")
    assert pattern.search("fmt.Printf('value: %d', x)")


# ───────────────────────────────────────────────────────────────────────────
# RUST RULES
# ───────────────────────────────────────────────────────────────────────────

def test_rust_unwrap():
    """Test .unwrap() detection."""
    rules = get_rules_for_language("rust")
    pattern = next(r for r in rules if r[3] == "unwrap")[0]
    
    # Should match
    assert pattern.search("let value = option.unwrap();")
    assert pattern.search("result.unwrap()")


def test_rust_expect():
    """Test .expect() detection."""
    rules = get_rules_for_language("rust")
    pattern = next(r for r in rules if r[3] == "expect-panic")[0]
    
    # Should match
    assert pattern.search("result.expect('failed')")
    assert pattern.search("value.expect(\"error message\")")


def test_rust_unsafe_block():
    """Test unsafe block detection."""
    rules = get_rules_for_language("rust")
    pattern = next(r for r in rules if r[3] == "unsafe-block")[0]
    
    # Should match
    assert pattern.search("unsafe { operation() }")
    assert pattern.search("unsafe {")


# ───────────────────────────────────────────────────────────────────────────
# SECURITY RULES
# ───────────────────────────────────────────────────────────────────────────

def test_security_path_traversal():
    """Test path traversal detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "path-traversal")[0]
    
    # Should match
    assert pattern.search("open('../../../etc/passwd')")
    assert pattern.search("read('../../config.ini')")


def test_security_private_key():
    """Test private key detection."""
    rules = get_rules_for_language("python")
    pattern = next(r for r in rules if r[3] == "private-key")[0]
    
    # Should match
    assert pattern.search("-----BEGIN PRIVATE KEY-----")
    assert pattern.search("-----BEGIN RSA PRIVATE KEY-----")
    assert pattern.search("-----BEGIN EC PRIVATE KEY-----")


# ───────────────────────────────────────────────────────────────────────────
# NOSQL INJECTION (MongoDB operator injection) — CWE-943
# ───────────────────────────────────────────────────────────────────────────

def test_nosql_injection_mongodb_findone_with_field():
    """Detect MongoDB collection.findOne() with common field names in query object."""
    rules = get_rules_for_language("javascript")
    pattern = next(r for r in rules if r[3] == "nosql-injection-mongodb")[0]

    # Should match — destructured req.body fields passed to findOne
    assert pattern.search('db.collection("users").findOne({ email: email, password: password })')
    assert pattern.search("db.collection('users').findOne({email: email})")

    # Should match — multi-line object (opening brace at end of line)
    assert pattern.search('db.collection("users").findOne({')

    # Should match — variable argument to find()
    assert pattern.search('db.collection("users").find(filter)')
    assert pattern.search("db.collection('logs').deleteOne(query)")


def test_nosql_injection_mongodb_other_operations():
    """Detect various MongoDB collection operations with variable arguments."""
    rules = get_rules_for_language("javascript")
    pattern = next(r for r in rules if r[3] == "nosql-injection-mongodb")[0]

    assert pattern.search('db.collection("items").updateOne(filter, update)')
    assert pattern.search('db.collection("items").deleteMany(criteria)')
    assert pattern.search('db.collection("items").aggregate(pipeline)')


# ───────────────────────────────────────────────────────────────────────────
# PROTOTYPE POLLUTION VIA MERGE — CWE-1321
# ───────────────────────────────────────────────────────────────────────────

def test_prototype_pollution_merge_lodash():
    """Detect _.merge with variable source argument — prototype pollution."""
    rules = get_rules_for_language("javascript")
    pattern = next(r for r in rules if r[3] == "prototype-pollution-merge")[0]

    # Should match — lodash merge with variable
    assert pattern.search("_.merge(config, userPrefs)")
    assert pattern.search("_.defaultsDeep(defaults, overrides)")
    assert pattern.search("_.mergeWith(target, source, customizer)")

    # Should match — Object.assign with variable
    assert pattern.search("Object.assign(config, userInput)")

    # Should match — custom deep merge
    assert pattern.search("deepMerge(target, source)")
    assert pattern.search("deepExtend(obj, data)")


def test_prototype_pollution_merge_safe():
    """Should NOT match safe merge patterns with literals."""
    rules = get_rules_for_language("javascript")
    pattern = next(r for r in rules if r[3] == "prototype-pollution-merge")[0]

    # Should NOT match — literal object as source
    assert not pattern.search("_.merge(config, { theme: 'dark' })")
    assert not pattern.search('Object.assign(config, { key: "val" })')


# ───────────────────────────────────────────────────────────────────────────
# JNDI INJECTION (variable-based lookup) — CWE-74
# ───────────────────────────────────────────────────────────────────────────

def test_jndi_injection_variable_lookup():
    """Detect ctx.lookup(variable) pattern for JNDI injection."""
    rules = get_rules_for_language("java")
    pattern = next(r for r in rules if r[3] == "java-jndi-lookup-variable")[0]

    # Should match — variable-based context lookup
    assert pattern.search("ctx.lookup(path)")
    assert pattern.search("context.lookup(resourceName)")
    assert pattern.search("initialContext.lookup(jndiName)")
    assert pattern.search("jndiContext.lookup(name)")

    # Should NOT match — literal string lookup
    assert not pattern.search('ctx.lookup("java:comp/env/jdbc/mydb")')
    assert not pattern.search("context.lookup(\"ldap://safe.internal\")")


# ───────────────────────────────────────────────────────────────────────────
# SpEL INJECTION (variable-based parseExpression) — CWE-917
# ───────────────────────────────────────────────────────────────────────────

def test_spel_injection_variable_parse():
    """Detect parser.parseExpression(variable) pattern for SpEL injection."""
    rules = get_rules_for_language("java")
    pattern = next(r for r in rules if r[3] == "java-spel-parse-variable")[0]

    # Should match — variable-based expression parsing
    assert pattern.search("parser.parseExpression(expression)")
    assert pattern.search("expressionParser.parseExpression(input)")
    assert pattern.search("spelParser.parseExpression(userExpr)")
    assert pattern.search("exprParser.parseExpression(filterExpr)")

    # Should NOT match — literal string expression
    assert not pattern.search('parser.parseExpression("T(java.lang.Math).random()")')
    assert not pattern.search("parser.parseExpression(\"1 + 1\")")
