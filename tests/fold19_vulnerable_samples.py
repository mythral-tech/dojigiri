"""Fold 19: Red-team evasion — adversarial patterns designed to slip past
Doji's current regex and AST checks while remaining genuinely dangerous.

Targets: variable aliasing of builtins, star-unpacking to hide shell=True,
walrus + ternary obfuscation, lambda wrappers, dict-based dispatch tables
calling dangerous functions, setattr/delattr abuse, comprehension-embedded
danger, try/finally hidden exec, conditional imports with dangerous defaults,
and creative whitespace/comment placement to break regex anchors.
"""

import os
import sys
import json
import sqlite3
import hashlib
import logging
import subprocess
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Section 1: Builtin aliasing to evade name-based detection ────────

# Local aliases — regex looks for "eval(" and "exec(" literally
_e = eval  # reference to eval
_x = exec  # reference to exec
_s = os.system  # reference to os.system
_p = getattr(__builtins__, "eval") if isinstance(__builtins__, dict) else eval


def use_aliased_eval(expr: str):
    """eval via local alias — evades 'eval(' regex."""
    return _e(expr)


def use_aliased_exec(code: str):
    """exec via local alias."""
    _x(code)


def use_aliased_system(cmd: str):
    """os.system via local alias."""
    _s(cmd)


# ── Section 2: Star-unpacking to hide keyword args ──────────────────

def subprocess_star_kwargs(cmd: str):
    """shell=True hidden in dict unpacking."""
    opts = {"shell": True, "capture_output": True, "text": True}
    return subprocess.run(cmd, **opts)  # shell=True via **kwargs


def subprocess_merged_kwargs(cmd: str, extra_opts: dict):
    """shell=True merged from two dicts."""
    base = {"capture_output": True}
    base.update(extra_opts)  # extra_opts could contain shell=True
    return subprocess.run(cmd, **base)


def subprocess_conditional_shell(cmd, use_shell: bool = True):
    """shell= from variable — can't statically determine."""
    return subprocess.run(cmd, shell=use_shell)  # subprocess-audit


# ── Section 3: Dict dispatch tables with dangerous functions ────────

COMMANDS = {
    "eval": eval,
    "exec": exec,
    "system": os.system,
    "popen": os.popen,
}


def dispatch_command(action: str, payload: str):
    """Dispatch table calling dangerous functions."""
    handler = COMMANDS.get(action)
    if handler:
        return handler(payload)  # arbitrary dangerous call via dispatch


DESERIALIZERS = {
    "pickle": __import__("pickle").loads,
    "json": json.loads,
    "yaml": lambda d: __import__("yaml").safe_load(d),
}


def deserialize(format: str, data):
    """Deserializer dispatch — pickle path is dangerous."""
    return DESERIALIZERS.get(format, json.loads)(data)


# ── Section 4: Lambda wrappers ──────────────────────────────────────

run_eval = lambda expr: eval(expr)  # eval-usage in lambda
run_exec = lambda code: exec(code)  # exec-usage in lambda
run_system = lambda cmd: os.system(cmd)  # os-system in lambda
run_sql = lambda conn, q: conn.execute(f"SELECT * FROM t WHERE x = '{q}'")  # sql-injection in lambda


def apply_lambda(func, data: str):
    """Apply a lambda — could be any of the above."""
    return func(data)


# ── Section 5: Comprehension-embedded danger ─────────────────────────

def eval_list(expressions: list) -> list:
    """List comprehension with eval."""
    return [eval(e) for e in expressions]  # eval-usage in comprehension


def system_list(commands: list) -> list:
    """List comprehension with os.system."""
    return [os.system(c) for c in commands]  # os-system in comprehension


def sql_comprehension(conn, keys: list):
    """List comprehension with SQL injection."""
    return [
        conn.execute(f"SELECT * FROM data WHERE key = '{k}'").fetchone()  # sql-injection
        for k in keys
    ]


def dict_comprehension_sql(conn, tables: list):
    """Dict comprehension with SQL injection."""
    return {
        t: conn.execute(f"SELECT COUNT(*) FROM {t}").fetchone()[0]  # sql-injection
        for t in tables
    }


# ── Section 6: Ternary/walrus obfuscation ───────────────────────────

def ternary_eval(expr: str, safe_mode: bool = False):
    """eval hidden in ternary."""
    return eval(expr) if not safe_mode else None  # eval-usage in ternary


def ternary_system(cmd: str, dry_run: bool = False):
    """os.system hidden in ternary."""
    return os.system(cmd) if not dry_run else print(f"Would run: {cmd}")  # os-system in ternary


def walrus_eval_chain(data: dict):
    """Walrus operator with eval."""
    if (expr := data.get("expr")) and (result := eval(expr)):  # eval-usage
        return result
    return None


# ── Section 7: setattr / delattr abuse ───────────────────────────────

def inject_via_setattr(obj: Any, attr: str, value: Any):
    """setattr with user-controlled attribute name."""
    setattr(obj, attr, value)  # arbitrary attribute injection


def inject_method(obj: Any, method_name: str, code: str):
    """Inject a method via setattr + compile."""
    compiled = compile(code, "<injected>", "exec")  # compile-usage
    namespace = {}
    exec(compiled, namespace)  # exec-usage
    setattr(obj, method_name, namespace.get(method_name))


# ── Section 8: try/finally hidden execution ─────────────────────────

def finally_exec(code: str):
    """exec hidden in finally block — always runs."""
    try:
        pass
    finally:
        exec(code)  # exec-usage — always runs regardless of exception


def finally_system(cmd: str):
    """os.system hidden in finally."""
    try:
        raise RuntimeError("trigger finally")
    except RuntimeError:
        pass
    finally:
        os.system(cmd)  # os-system in finally


def except_eval(expr: str):
    """eval hidden in except handler."""
    try:
        int("not a number")
    except ValueError:
        return eval(expr)  # eval-usage in except


# ── Section 9: Conditional imports with dangerous defaults ───────────

def flexible_deserialize(data: bytes, use_safe: bool = False):
    """Import pickle conditionally — dangerous by default."""
    if use_safe:
        return json.loads(data)
    else:
        import pickle
        return pickle.loads(data)  # pickle-unsafe — default path


def flexible_hash(data: str, algorithm: str = "md5"):
    """Dynamic hash selection — defaults to weak."""
    h = hashlib.new(algorithm)  # weak if algorithm="md5" or "sha1"
    h.update(data.encode())
    return h.hexdigest()


def flexible_xml_parse(xml_str: str, safe: bool = False):
    """XML parsing — unsafe by default."""
    if safe:
        import defusedxml.ElementTree as ET
        return ET.fromstring(xml_str)
    else:
        import xml.etree.ElementTree as ET
        return ET.fromstring(xml_str)  # xxe-risk — default path


# ── Section 10: Creative whitespace and comment placement ────────────

def spaced_eval(
    expression   :   str   # the expression to evaluate
) -> Any:
    """Extra whitespace around eval call."""
    return   eval(   expression   )  # eval-usage with whitespace


def commented_system(cmd: str):
    """os.system with misleading comments."""
    # This is NOT os.system, it's totally safe (narrator: it was not safe)
    result = os.system(  # nosec — false suppression
        cmd
    )
    return result


def multiline_pickle_loads(
    data: bytes,
    # pickle.loads is fine here because we trust the source (we don't)
):
    """pickle.loads with misleading docstring."""
    return pickle.loads(  # type: ignore
        data
    )  # pickle-unsafe — multiline


# ── Section 11: hashlib.new() with variable algorithm ────────────────

def hash_dynamic(data: str, algo: str = "md5") -> str:
    """hashlib.new with variable — could be weak."""
    return hashlib.new(algo, data.encode()).hexdigest()


def hash_from_config(data: str, config: dict) -> str:
    """Hash algorithm from config — could be weak."""
    algo = config.get("hash_algorithm", "md5")
    return hashlib.new(algo, data.encode()).hexdigest()


def pbkdf2_weak_default(password: str, salt: bytes, iterations: int = 100) -> bytes:
    """PBKDF2 with weak default iterations."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, iterations)


# ── Section 12: SQL via cursor methods — less common ────────────────

def executescript_multiline(conn, table: str, data: str):
    """executescript with f-string — multiline."""
    conn.executescript(f"""
        INSERT INTO {table} (data) VALUES ('{data}');
        UPDATE {table} SET processed = 1 WHERE data = '{data}';
    """)  # sql-injection via executescript


def execute_with_semicolons(conn, user_input: str):
    """execute with potential multi-statement via semicolons."""
    conn.execute(f"SELECT * FROM users WHERE name = '{user_input}'")  # sql-injection


# ── Section 13: Hardcoded secrets — adversarial patterns ────────────

import pickle  # at bottom — unusual placement

# Secret with unusual variable name (tests \w+[_-](?:secret|...) pattern)
PAYMENT_GATEWAY_SECRET = "pgw_doji_fake_1234567890abcdef"  # hardcoded-secret
OAUTH_CLIENT_SECRET = "ocs_prod_abcdefghijklmnop"  # hardcoded-secret
SESSION_ENCRYPTION_KEY = "sek_aes256_9f8e7d6c5b4a3210"  # hardcoded-secret

# Secret in assignment with spaces around =
API_TOKEN    =    "at_prod_1a2b3c4d5e6f7g8h9i0j"  # hardcoded-secret — extra spaces

# Secret as keyword argument — should match hardcoded-password-default
def connect_service(
    host: str = "prod.internal",
    secret: str = "svc_secret_key_production_2024",  # hardcoded-password-default
    token: str = "tok_live_abcdefghijklmnop1234",  # hardcoded-password-default
):
    """Connect with hardcoded secret defaults."""
    pass


# ── Section 14: Mixed chains — realistic attack flows ───────────────

def admin_panel(request: dict, conn):
    """Admin panel with multiple vulnerabilities chained."""
    # Auth bypass — hardcoded check
    if request.get("admin_pass") != "SuperAdmin2024!":  # hardcoded comparison
        return {"error": "unauthorized"}

    action = request.get("action", "")

    if action == "query":
        # SQL injection
        sql = request.get("sql", "")
        return conn.execute(f"SELECT * FROM data WHERE {sql}").fetchall()  # sql-injection

    elif action == "eval":
        # Arbitrary eval
        return eval(request.get("expression", "None"))  # eval-usage

    elif action == "exec":
        # Arbitrary exec
        exec(request.get("code", "pass"))  # exec-usage

    elif action == "shell":
        # Command injection
        return os.system(request.get("command", "echo ok"))  # os-system

    elif action == "fetch":
        # SSRF
        import requests as req  # type: ignore
        url = request.get("url", "")
        return req.get(url, timeout=10).text  # ssrf-risk

    elif action == "deserialize":
        # Pickle RCE
        import base64
        data = base64.b64decode(request.get("data", ""))
        return pickle.loads(data)  # pickle-unsafe
