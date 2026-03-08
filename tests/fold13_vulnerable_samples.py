"""Fold 13: Hidden execution paths and stdlib dark corners.

Targets: __import__ dynamic loading, globals()/locals() injection,
types.FunctionType code object creation, configparser interpolation,
runpy/compileall execution, operator.attrgetter chains, inspect-based
introspection attacks, atexit handlers, weakref callbacks with side effects,
and creative string building to evade pattern matching.
"""

import os
import sys
import json
import types
import pickle
import sqlite3
import hashlib
import logging
import inspect
import operator
import textwrap
import tempfile
import subprocess
import configparser
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ── Section 1: __import__ dynamic module loading ─────────────────────

def import_and_call(module_name: str, func_name: str, *args):
    """Dynamic import via __import__ — arbitrary code execution."""
    mod = __import__(module_name)  # dynamic-import via __import__
    func = getattr(mod, func_name)
    return func(*args)


def import_nested(dotted_name: str, attr: str):
    """__import__ with dotted module path."""
    parts = dotted_name.split(".")
    mod = __import__(dotted_name)
    for part in parts[1:]:
        mod = getattr(mod, part)
    return getattr(mod, attr)


def conditional_import_exec(user_choice: str, payload: str):
    """Conditional import leading to exec."""
    if user_choice == "pickle":
        mod = __import__("pickle")  # dynamic-import
        return mod.loads(payload.encode())  # pickle after import
    elif user_choice == "yaml":
        mod = __import__("yaml")  # dynamic-import
        return mod.load(payload)  # yaml.load unsafe
    elif user_choice == "marshal":
        mod = __import__("marshal")  # dynamic-import
        return mod.loads(payload.encode())  # marshal unsafe


# ── Section 2: globals() / locals() injection ────────────────────────

def inject_via_globals(key: str, value: Any):
    """Write to globals() — arbitrary variable/function injection."""
    globals()[key] = value  # can override any global, including builtins


def exec_from_globals(func_name: str, *args):
    """Call function from globals by name — arbitrary execution."""
    func = globals().get(func_name)
    if func and callable(func):
        return func(*args)  # arbitrary function call


def locals_to_sql(conn, **kwargs):
    """Build SQL from locals() — injection via kwarg names/values."""
    local_vars = locals()
    pairs = ", ".join(f"{k} = '{v}'" for k, v in local_vars.items() if k != "conn")
    conn.execute(f"UPDATE config SET {pairs}")  # sql-injection via locals


def eval_with_globals(expr: str, extra_globals: dict):
    """eval with augmented globals — sandbox escape."""
    g = dict(globals())
    g.update(extra_globals)
    return eval(expr, g)  # eval-usage with expanded namespace


# ── Section 3: types.FunctionType — code object injection ────────────

def create_function_from_code(code_obj, name: str = "dynamic"):
    """Create function from code object — arbitrary execution."""
    return types.FunctionType(code_obj, globals(), name)


def compile_to_function(source: str, func_name: str = "f"):
    """Compile source string to callable function."""
    code_obj = compile(source, "<dynamic>", "exec")  # compile-usage
    namespace = {}
    exec(code_obj, namespace)  # exec-usage
    return namespace.get(func_name)


def modify_function_globals(func, key: str, value: Any):
    """Modify a function's __globals__ — inject into any function's scope."""
    func.__globals__[key] = value  # modify function's global scope


# ── Section 4: configparser interpolation attacks ────────────────────

def load_config_interpolation(config_path: str) -> dict:
    """ConfigParser with BasicInterpolation — %(key)s can reference other keys."""
    config = configparser.ConfigParser()
    config.read(config_path)
    # If config contains %(home)s or similar, interpolation can leak data
    result = {}
    for section in config.sections():
        result[section] = dict(config[section])
    return result


def config_to_command(config_path: str):
    """Read command from config and execute."""
    config = configparser.ConfigParser()
    config.read(config_path)
    if config.has_option("hooks", "post_deploy"):
        cmd = config.get("hooks", "post_deploy")
        os.system(cmd)  # os-system from config file


def config_to_eval(config_path: str):
    """Read expression from config and eval."""
    config = configparser.ConfigParser()
    config.read(config_path)
    if config.has_option("formulas", "compute"):
        expr = config.get("formulas", "compute")
        return eval(expr)  # eval-usage from config


# ── Section 5: runpy — execute modules by name ───────────────────────

def run_module(module_name: str):
    """Run arbitrary module via runpy."""
    import runpy
    return runpy.run_module(module_name, run_name="__main__")  # arbitrary module execution


def run_path(script_path: str):
    """Run arbitrary script via runpy."""
    import runpy
    return runpy.run_path(script_path)  # arbitrary script execution


# ── Section 6: operator.attrgetter / methodcaller chains ─────────────

def attrgetter_chain(obj: Any, attr_path: str):
    """operator.attrgetter with user-controlled path — attribute access."""
    getter = operator.attrgetter(attr_path)  # arbitrary attribute access
    return getter(obj)


def methodcaller_exec(obj: Any, method_name: str, *args):
    """operator.methodcaller with user-controlled method — arbitrary method call."""
    caller = operator.methodcaller(method_name, *args)
    return caller(obj)  # arbitrary method invocation


def attrgetter_on_module(module_name: str, attr_chain: str):
    """attrgetter on dynamically imported module."""
    mod = __import__(module_name)  # dynamic-import
    getter = operator.attrgetter(attr_chain)
    return getter(mod)  # arbitrary nested attribute access


# ── Section 7: inspect-based introspection ───────────────────────────

def get_source_code(obj: Any) -> str:
    """Get source code of object — info disclosure."""
    return inspect.getsource(obj)  # reveals implementation details


def get_caller_locals():
    """Access caller's local variables via inspect — info disclosure."""
    frame = inspect.currentframe().f_back
    caller_locals = frame.f_locals  # access caller's scope
    # Could contain passwords, tokens, etc.
    return dict(caller_locals)


def modify_caller_variable(var_name: str, new_value: Any):
    """Modify variable in caller's frame — scope injection."""
    frame = inspect.currentframe().f_back
    frame.f_locals[var_name] = new_value  # inject into caller's scope
    # Note: this doesn't always work in CPython due to fast locals
    # but the intent is dangerous


# ── Section 8: atexit handlers ───────────────────────────────────────

import atexit


def register_cleanup_command(cmd: str):
    """Register shell command as atexit handler."""
    atexit.register(os.system, cmd)  # os-system deferred to exit


def register_cleanup_eval(expr: str):
    """Register eval as atexit handler."""
    atexit.register(eval, expr)  # eval-usage deferred to exit


def register_data_exfil(url: str, data: dict):
    """Register data exfiltration at exit."""
    import requests  # type: ignore
    atexit.register(requests.post, url, json=data)  # ssrf-risk at exit


# ── Section 9: weakref callbacks ─────────────────────────────────────

import weakref


def weakref_callback_exec(obj: Any, code: str):
    """weakref finalizer that executes code."""
    def on_delete(ref):
        exec(code)  # exec-usage in weakref callback
    ref = weakref.ref(obj, on_delete)
    return ref


def weakref_finalize_system(obj: Any, cmd: str):
    """weakref finalizer that runs system command."""
    weakref.finalize(obj, os.system, cmd)  # os-system in weakref finalizer


# ── Section 10: String building to hide dangerous calls ──────────────

def build_and_eval(parts: list):
    """Build eval expression from parts."""
    expr = "".join(parts)
    return eval(expr)  # eval-usage — built from parts


def reverse_string_exec(reversed_code: str):
    """Execute reversed string — obfuscation."""
    code = reversed_code[::-1]
    exec(code)  # exec-usage — reversed string


def base64_exec(encoded: str):
    """Execute base64-decoded string."""
    import base64
    code = base64.b64decode(encoded).decode()
    exec(code)  # exec-usage — base64 decoded


def hex_eval(hex_expr: str):
    """Eval hex-decoded expression."""
    expr = bytes.fromhex(hex_expr).decode()
    return eval(expr)  # eval-usage — hex decoded


def chr_build_exec(char_codes: list):
    """Build code from chr() calls and exec."""
    code = "".join(chr(c) for c in char_codes)
    exec(code)  # exec-usage — built from char codes


# ── Section 11: Subprocess via less common entry points ──────────────

def os_popen_read(cmd: str) -> str:
    """os.popen for command execution."""
    return os.popen(cmd).read()  # os-popen


def os_popen_write(cmd: str, data: str):
    """os.popen in write mode."""
    p = os.popen(cmd, "w")  # os-popen
    p.write(data)
    p.close()


# ── Section 12: SQL injection via ORM-like patterns ──────────────────

class SimpleORM:
    """Minimal ORM with SQL injection everywhere."""

    def __init__(self, db_path: str):
        self.conn = sqlite3.connect(db_path)

    def find_by(self, table: str, **conditions):
        """Find records by conditions — SQL injection in keys AND values."""
        where = " AND ".join(f"{k} = '{v}'" for k, v in conditions.items())
        query = f"SELECT * FROM {table} WHERE {where}"  # sql-injection
        return self.conn.execute(query).fetchall()

    def insert(self, table: str, **data):
        """Insert record — SQL injection in table and column names."""
        cols = ", ".join(data.keys())
        vals = ", ".join(f"'{v}'" for v in data.values())
        self.conn.execute(f"INSERT INTO {table} ({cols}) VALUES ({vals})")  # sql-injection
        self.conn.commit()

    def delete_where(self, table: str, condition: str):
        """Delete with raw condition — SQL injection."""
        self.conn.execute(f"DELETE FROM {table} WHERE {condition}")  # sql-injection
        self.conn.commit()

    def raw_query(self, sql: str, *params):
        """Execute raw SQL — no parameterization."""
        return self.conn.execute(sql).fetchall()  # raw SQL, params ignored

    def update_field(self, table: str, field: str, value: str, where_id: int):
        """Update single field — SQL injection in field name."""
        self.conn.execute(
            f"UPDATE {table} SET {field} = '{value}' WHERE id = {where_id}"  # sql-injection
        )


# ── Section 13: Hardcoded credentials in various formats ────────────

# Connection strings
REDIS_URL = "redis://:SuperSecret123@redis.internal:6379/0"  # db-connection-string
MONGO_URI = "mongodb://admin:M0ngoP@ss!@mongo.cluster:27017/prod"  # db-connection-string
AMQP_URL = "amqp://guest:guest123@rabbitmq:5672/"  # db-connection-string

# API keys in various formats
STRIPE_KEY = "doji_fake_4eC39HqLyjWDarjtT1zdp7dc"  # hardcoded-secret
GITHUB_TOKEN = "ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef12"  # hardcoded-secret
SENDGRID_KEY = "SG.abcdefghij.klmnopqrstuvwxyz123456"  # hardcoded-secret — has dots

# Secrets as class constants
class PaymentConfig:
    MERCHANT_SECRET = "msk_prod_9f8e7d6c5b4a3210"  # hardcoded-secret
    WEBHOOK_SECRET = "whsec_abcdef123456789012345678"  # hardcoded-secret
    ENCRYPTION_KEY = "enc-key-aes256-prod-x7y8z9"  # hardcoded-secret


# ── Section 14: Pickle via less obvious paths ────────────────────────

def unpickle_from_file(filepath: str):
    """pickle.load from file — classic but with open()."""
    with open(filepath, "rb") as f:
        return pickle.load(f)  # pickle-unsafe


def unpickle_from_shelve(db_path: str, key: str):
    """shelve.open is pickle-backed."""
    import shelve
    with shelve.open(db_path) as db:  # unsafe-deserialization
        return db.get(key)


def unpickle_from_redis(redis_client, key: str):
    """Get pickled data from Redis."""
    data = redis_client.get(key)
    if data:
        return pickle.loads(data)  # pickle-unsafe from cache


def copyreg_exploit():
    """copyreg can be used to register custom pickle reducers."""
    import copyreg
    # Registering a custom reducer for a type — can be exploited
    # to execute arbitrary code during unpickling
    copyreg.pickle(type(lambda: None), lambda f: (eval, ("os.system('id')",)))


# ── Section 15: Weak hashing in non-obvious contexts ────────────────

def etag_generator(content: bytes) -> str:
    """Generate ETag using MD5 — collision possible."""
    return hashlib.md5(content).hexdigest()  # weak-hash for ETag


def cache_key(data: str) -> str:
    """Generate cache key using SHA1."""
    return hashlib.sha1(data.encode()).hexdigest()  # weak-hash for cache key


def password_hash_single_sha256(password: str, salt: str) -> str:
    """Single SHA-256 for password — no stretching."""
    return hashlib.sha256((salt + password).encode()).hexdigest()  # no iterations


def file_checksum_md5(filepath: str) -> str:
    """MD5 for file integrity."""
    h = hashlib.md5()  # weak-hash
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Section 16: Environment variable as execution vector ─────────────

def env_eval():
    """Eval from environment variable."""
    expr = os.environ.get("INIT_EXPR", "1+1")
    return eval(expr)  # eval-usage from env


def env_system():
    """os.system from environment variable."""
    cmd = os.environ.get("STARTUP_CMD", "true")
    os.system(cmd)  # os-system from env


def env_exec():
    """exec from environment variable."""
    code = os.environ.get("INIT_CODE", "pass")
    exec(code)  # exec-usage from env


def env_import():
    """Dynamic import from environment variable."""
    module = os.environ.get("PLUGIN_MODULE", "json")
    __import__(module)  # dynamic-import from env


# ── Section 17: Multiline f-string SQL ───────────────────────────────

def complex_multiline_sql(conn, user_id: str, status: str, limit: int):
    """Multiline f-string SQL — harder for regex to catch."""
    cursor = conn.execute(
        f"""
        SELECT u.name, u.email, o.total
        FROM users u
        JOIN orders o ON u.id = o.user_id
        WHERE u.id = '{user_id}'
        AND o.status = '{status}'
        ORDER BY o.created_at DESC
        LIMIT {limit}
        """  # sql-injection — multiline f-string
    )
    return cursor.fetchall()


def multiline_fstring_insert(conn, table: str, name: str, value: str):
    """Multiline f-string INSERT."""
    conn.execute(
        f"""INSERT INTO {table}
            (name, value, created_at)
            VALUES ('{name}', '{value}', datetime('now'))
        """  # sql-injection — multiline f-string
    )
    conn.commit()


# ── Section 18: subprocess with variable construction ────────────────

def subprocess_list_with_user_input(filename: str):
    """Subprocess with list args but user input not sanitized."""
    subprocess.run(["cat", filename])  # path traversal via filename


def subprocess_format_string(host: str, port: int):
    """Subprocess with f-string command."""
    subprocess.run(
        f"nmap -sV {host} -p {port}",
        shell=True,  # shell-true with user input
    )


def subprocess_join(args: list):
    """Subprocess with joined args."""
    cmd = " ".join(args)
    subprocess.run(cmd, shell=True)  # shell-true with joined user args
