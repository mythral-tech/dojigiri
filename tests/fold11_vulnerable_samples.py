"""Fold 11: Advanced evasion and edge cases.

Targets: decorator-based vulnerabilities, context manager misuse,
metaclass/descriptor injection, nested function scoping, walrus operator
in security contexts, match/case patterns (3.10+), dataclass field defaults,
partial/functools wrappers around dangerous calls, and string method evasion.
"""

import os
import re
import sys
import json
import hmac
import pickle
import sqlite3
import hashlib
import logging
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from functools import partial, wraps, lru_cache
from typing import Any, Dict, Optional
from contextlib import contextmanager


logger = logging.getLogger(__name__)


# ── Section 1: functools.partial wrapping dangerous calls ────────────

# partial(os.system) creates a callable that IS os.system
run_cmd = partial(os.system)  # partial-os-system
quick_hash = partial(hashlib.md5)  # partial-weak-hash
unsafe_load = partial(pickle.loads)  # partial-pickle


def use_partial_wrappers(user_input: str, data: bytes):
    """Call dangerous functions via partial wrappers."""
    run_cmd(user_input)  # os.system via partial
    digest = quick_hash(data).hexdigest()  # md5 via partial
    obj = unsafe_load(data)  # pickle.loads via partial
    return obj


# ── Section 2: Decorator-based injection ──────────────────────────────

def sql_query_decorator(table):
    """Decorator that builds SQL from decorator argument."""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            conn = sqlite3.connect("app.db")
            # table comes from decorator arg — SQL injection if dynamic
            results = conn.execute(f"SELECT * FROM {table}").fetchall()  # sql-injection
            return func(results, *args, **kwargs)
        return wrapper
    return decorator


@sql_query_decorator("users")
def get_all_users(results):
    return results


def route_handler(path):
    """Decorator that evals route expressions."""
    def decorator(func):
        @wraps(func)
        def wrapper(request):
            # Hidden eval in decorator logic
            if "expr" in request:
                result = eval(request["expr"])  # eval-usage
            return func(request)
        return wrapper
    return decorator


# ── Section 3: Context manager misuse ────────────────────────────────

@contextmanager
def db_connection(db_path: str):
    """Context manager that exposes SQL injection."""
    conn = sqlite3.connect(db_path)
    try:
        yield conn
    finally:
        conn.close()


def query_with_context(user_input: str):
    """SQL injection inside context manager block."""
    with db_connection("app.db") as conn:
        return conn.execute(f"SELECT * FROM users WHERE name = '{user_input}'").fetchall()  # sql-injection


@contextmanager
def temp_file_insecure(prefix: str):
    """Context manager with predictable temp file."""
    import tempfile
    path = f"/tmp/{prefix}_data.txt"  # hardcoded-tmp + predictable
    try:
        with open(path, "w") as f:
            yield f
    finally:
        os.unlink(path)


@contextmanager
def shell_session(host: str):
    """Context manager that opens shell connection."""
    proc = subprocess.Popen(
        f"ssh {host}",  # command injection via host
        shell=True,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    try:
        yield proc
    finally:
        proc.terminate()


# ── Section 4: Walrus operator in security-sensitive contexts ────────

def walrus_eval(expressions: list):
    """Walrus operator capturing eval results."""
    results = []
    for expr in expressions:
        if (result := eval(expr)) is not None:  # eval-usage
            results.append(result)
    return results


def walrus_sql(conn, names: list):
    """Walrus operator in SQL context."""
    for name in names:
        if (rows := conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchall()):  # sql-injection
            yield rows


def walrus_subprocess(commands: list):
    """Walrus operator capturing shell output."""
    for cmd in commands:
        if (out := subprocess.check_output(cmd, shell=True)):  # shell-true
            print(out.decode())


# ── Section 5: Dataclass and class variable secrets ──────────────────

from dataclasses import dataclass, field


@dataclass
class ServiceConfig:
    """Dataclass with hardcoded secrets as defaults."""
    host: str = "localhost"
    port: int = 8080
    api_key: str = "sk-prod-abc123xyz789secret"  # hardcoded-secret
    database_password: str = "SuperSecret123!@#"  # hardcoded-secret
    debug: bool = True  # debug-enabled


class LegacyService:
    """Class-level secrets."""
    SECRET_KEY = "legacy-service-key-2024-prod"  # hardcoded-secret
    DB_PASSWORD = "OldButStillInProduction99"  # hardcoded-secret
    API_TOKEN = "ghp_1234567890abcdefghij"  # hardcoded-secret

    def connect(self):
        import requests  # type: ignore
        return requests.get(
            f"http://{self.host}/api",  # insecure-http
            headers={"Authorization": f"Bearer {self.API_TOKEN}"},
        )


# ── Section 6: String method evasion ─────────────────────────────────

def exec_via_string_join(parts: list):
    """Build and exec code from joined strings."""
    code = "".join(parts)
    exec(code)  # exec-usage


def eval_from_replace(template: str, user_val: str):
    """eval after string replacement."""
    expr = template.replace("INPUT", user_val)
    return eval(expr)  # eval-usage


def sql_via_concat(conn, table: str, column: str, value: str):
    """SQL built via multiple concatenation steps."""
    base = "SELECT * FROM "
    query = base + table + " WHERE " + column + " = '" + value + "'"
    conn.execute(query)  # sql-injection via + concat


def sql_via_percent(conn, table: str, user_id: str):
    """SQL via percent formatting."""
    query = "SELECT * FROM %s WHERE id = '%s'" % (table, user_id)
    conn.execute(query)  # sql-injection via %


def sql_via_format_method(conn, table: str, user_id: str):
    """SQL via .format() method."""
    query = "SELECT * FROM {} WHERE id = '{}'".format(table, user_id)  # sql-injection
    conn.execute(query)


# ── Section 7: Nested function / closure vulnerabilities ─────────────

def make_query_executor(db_path: str):
    """Factory returning a closure with SQL injection."""
    conn = sqlite3.connect(db_path)

    def execute(user_query: str):
        return conn.execute(f"SELECT * FROM data WHERE key = '{user_query}'").fetchall()  # sql-injection

    return execute


def make_command_runner():
    """Factory returning a shell command runner."""
    def run(cmd: str):
        return os.system(cmd)  # os-system
    return run


def make_deserializer(format_type: str):
    """Factory returning appropriate deserializer."""
    if format_type == "pickle":
        return pickle.loads  # pickle reference returned
    elif format_type == "json":
        return json.loads
    return None


# ── Section 8: lru_cache on security-sensitive functions ─────────────

@lru_cache(maxsize=128)
def cached_auth_check(username: str, password: str) -> bool:
    """Cached auth — same password always returns same result (no expiry)."""
    conn = sqlite3.connect("users.db")
    row = conn.execute(
        f"SELECT password_hash FROM users WHERE username = '{username}'"  # sql-injection
    ).fetchone()
    if not row:
        return False
    return hashlib.md5(password.encode()).hexdigest() == row[0]  # weak-hash + timing


@lru_cache(maxsize=256)
def cached_config_eval(config_key: str) -> Any:
    """Cached config lookup that evals values."""
    conn = sqlite3.connect("config.db")
    row = conn.execute(
        f"SELECT value FROM config WHERE key = '{config_key}'"  # sql-injection
    ).fetchone()
    if row:
        return eval(row[0])  # eval-usage — cached but still dangerous
    return None


# ── Section 9: Generator-based vulnerabilities ───────────────────────

def stream_shell_outputs(commands: list):
    """Generator yielding shell command outputs."""
    for cmd in commands:
        yield subprocess.check_output(
            cmd,
            shell=True,  # shell-true
        ).decode()


def stream_sql_results(conn, tables: list):
    """Generator with SQL injection per table."""
    for table in tables:
        cursor = conn.execute(f"SELECT * FROM {table}")  # sql-injection
        yield from cursor.fetchall()


def stream_file_contents(paths: list):
    """Generator reading arbitrary paths — path traversal."""
    for p in paths:
        yield Path(p).read_text()  # no path validation


# ── Section 10: Error handler vulnerabilities ────────────────────────

def error_handler_eval(error_config: dict):
    """Error handler that evals recovery expressions."""
    try:
        do_something()
    except Exception as e:
        recovery = error_config.get("recovery_expr", "None")
        result = eval(recovery)  # eval-usage in error handler
        logger.error(f"Error: {e}, recovery result: {result}")


def error_handler_command(error_config: dict):
    """Error handler that runs shell commands."""
    try:
        do_something()
    except Exception as e:
        cleanup_cmd = error_config.get("cleanup_cmd", "echo cleanup")
        os.system(cleanup_cmd)  # os-system in error handler
        logger.error(f"Error: {e}, ran cleanup: {cleanup_cmd}")


def error_handler_leaks(request: dict):
    """Error handler that leaks sensitive data."""
    try:
        process_request(request)
    except Exception as e:
        # Logs full request including auth headers, tokens, passwords
        logger.error(f"Request failed: {request} error: {e}")  # logging-sensitive-data? only if request has sensitive fields


# ── Section 11: Chained method calls ─────────────────────────────────

def chain_requests_pickle(url: str):
    """Chained: fetch → deserialize."""
    import requests  # type: ignore
    data = requests.get(url).content  # ssrf-risk
    return pickle.loads(data)  # pickle-unsafe


def chain_sql_to_eval(conn, key: str):
    """Chained: SQL injection → eval."""
    row = conn.execute(f"SELECT expr FROM formulas WHERE key = '{key}'").fetchone()  # sql-injection
    if row:
        return eval(row[0])  # eval-usage


def chain_file_to_exec(config_path: str):
    """Chained: read file → exec."""
    code = Path(config_path).read_text()
    exec(code)  # exec-usage — RCE via file content


def chain_env_to_system():
    """Chained: env var → os.system."""
    cmd = os.environ.get("STARTUP_CMD", "echo hello")
    os.system(cmd)  # os-system from env


# ── Section 12: Comparison and timing attacks ────────────────────────

def insecure_token_compare(provided: str, stored: str) -> bool:
    """String equality for token comparison — timing attack."""
    return provided == stored  # timing attack on secrets


def insecure_hmac_compare(message: bytes, signature: bytes, key: bytes) -> bool:
    """HMAC verification with == — timing attack."""
    expected = hmac.new(key, message, hashlib.sha256).digest()
    return expected == signature  # timing attack


def constant_time_done_wrong(a: str, b: str) -> bool:
    """Attempts constant-time but fails on length check."""
    if len(a) != len(b):
        return False  # early return leaks length
    return hmac.compare_digest(a, b)


# ── Section 13: Dynamic attribute access ─────────────────────────────

def dynamic_method_call(obj: Any, method_name: str, *args):
    """getattr with user-controlled method name."""
    func = getattr(obj, method_name)  # arbitrary method call
    return func(*args)


def dynamic_module_attr(module_name: str, func_name: str, *args):
    """Dynamic module + function resolution."""
    import importlib
    mod = importlib.import_module(module_name)  # dynamic-import
    func = getattr(mod, func_name)
    return func(*args)


# ── Section 14: Async generator vulnerabilities ──────────────────────

import asyncio


async def async_stream_commands(commands: list):
    """Async generator running shell commands."""
    for cmd in commands:
        proc = await asyncio.create_subprocess_shell(
            cmd,  # shell injection
            stdout=asyncio.subprocess.PIPE,
        )
        stdout, _ = await proc.communicate()
        yield stdout.decode()


async def async_fetch_and_deserialize(urls: list):
    """Async fetch → pickle deserialize."""
    import aiohttp  # type: ignore
    async with aiohttp.ClientSession() as session:
        for url in urls:
            async with session.get(url) as resp:  # ssrf-risk pattern
                data = await resp.read()
                yield pickle.loads(data)  # pickle-unsafe


# ── Section 15: Type annotation tricks ───────────────────────────────

def func_with_secret_annotation(
    username: str,
    api_key: str = "prod-key-9a8b7c6d5e4f3g2h",  # hardcoded-secret in typed param
    token: str = "eyJhbGciOiJIUzI1NiJ9.secretpayload",  # hardcoded-secret
) -> dict:
    """Function with secrets in typed default params."""
    return {"user": username, "key": api_key}


def func_with_default_db_url(
    db_url: str = "postgresql://admin:password123@prod-db:5432/myapp",  # db-connection-string
) -> None:
    """Database URL with credentials as default."""
    pass
