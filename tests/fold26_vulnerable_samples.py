"""Fold 26: Decorators, context managers, generators, and magic methods.

Focus on decorators that inject dangerous behavior, context managers that
execute code on entry/exit, generators that yield dangerous results,
__getattr__/__getattribute__ abuse, __del__ destructors with side effects,
__format__ injection, cached_property with secrets, and functools patterns.
"""

import os
import re
import sys
import json
import hmac
import hashlib
import logging
import sqlite3
import pickle
import subprocess
import functools
from pathlib import Path
from typing import Any, Dict, List, Optional, Callable

logger = logging.getLogger(__name__)


# ── Section 1: Decorators that inject dangerous behavior ─────────────

def auto_eval(func):
    """Decorator that evals the return value."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        result = func(*args, **kwargs)
        return eval(result)  # eval-usage — evals function return
    return wrapper


def auto_exec(func):
    """Decorator that execs the return value."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        code = func(*args, **kwargs)
        exec(code)  # exec-usage — execs function return
    return wrapper


def shell_command(func):
    """Decorator that runs return value as shell command."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        cmd = func(*args, **kwargs)
        return os.system(cmd)  # os-system — runs function return as command
    return wrapper


def sql_query(conn):
    """Decorator factory that executes return value as SQL."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            query = func(*args, **kwargs)
            return conn.execute(query).fetchall()  # potential sql-injection via return
        return wrapper
    return decorator


def log_with_secrets(func):
    """Decorator that logs all arguments including secrets."""
    @functools.wraps(func)
    def wrapper(*args, **kwargs):
        logger.info(f"Calling {func.__name__} with args={args} kwargs={kwargs}")  # logs secrets
        return func(*args, **kwargs)
    return wrapper


def pickle_cache(cache_dir: str):
    """Decorator that caches results with pickle."""
    def decorator(func):
        @functools.wraps(func)
        def wrapper(*args, **kwargs):
            cache_key = hashlib.md5(  # weak-hash
                f"{func.__name__}:{args}:{kwargs}".encode()
            ).hexdigest()
            cache_path = Path(cache_dir) / f"{cache_key}.pkl"
            if cache_path.exists():
                return pickle.loads(cache_path.read_bytes())  # pickle-unsafe from cache
            result = func(*args, **kwargs)
            cache_path.write_bytes(pickle.dumps(result))
            return result
        return wrapper
    return decorator


# ── Section 2: Context managers with dangerous operations ────────────

class ShellContext:
    """Context manager that runs setup/teardown commands."""

    def __init__(self, setup_cmd: str, teardown_cmd: str):
        self.setup_cmd = setup_cmd
        self.teardown_cmd = teardown_cmd

    def __enter__(self):
        os.system(self.setup_cmd)  # os-system in __enter__
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        os.system(self.teardown_cmd)  # os-system in __exit__
        return False


class SQLTransaction:
    """Context manager for SQL transactions — injection."""

    def __init__(self, db_path: str, setup_query: str = ""):
        self.conn = sqlite3.connect(db_path)
        self.setup_query = setup_query

    def __enter__(self):
        if self.setup_query:
            self.conn.execute(self.setup_query)  # potential injection via setup_query
        return self.conn

    def __exit__(self, exc_type, exc_val, exc_tb):
        if exc_type is None:
            self.conn.commit()
        else:
            self.conn.rollback()
        self.conn.close()
        return False


class EvalContext:
    """Context manager that evals on exit."""

    def __init__(self, cleanup_expr: str):
        self.cleanup_expr = cleanup_expr

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        eval(self.cleanup_expr)  # eval-usage in __exit__
        return False


class PickleContext:
    """Context manager that loads/saves pickle state."""

    def __init__(self, state_path: str):
        self.state_path = state_path
        self.state = {}

    def __enter__(self):
        if Path(self.state_path).exists():
            with open(self.state_path, "rb") as f:
                self.state = pickle.load(f)  # pickle-unsafe in __enter__
        return self.state

    def __exit__(self, exc_type, exc_val, exc_tb):
        with open(self.state_path, "wb") as f:
            pickle.dump(self.state, f)
        return False


# ── Section 3: contextlib-based context managers ─────────────────────

from contextlib import contextmanager


@contextmanager
def temp_shell_env(setup_cmd: str, cleanup_cmd: str):
    """contextmanager that runs shell commands."""
    subprocess.run(setup_cmd, shell=True)  # shell-true in setup
    try:
        yield
    finally:
        subprocess.run(cleanup_cmd, shell=True)  # shell-true in cleanup


@contextmanager
def temp_db_table(conn, table_name: str, schema: str):
    """contextmanager that creates/drops table — injection."""
    conn.execute(f"CREATE TABLE {table_name} ({schema})")  # sql-injection
    try:
        yield conn
    finally:
        conn.execute(f"DROP TABLE IF EXISTS {table_name}")  # sql-injection


@contextmanager
def temp_pickle_state(path: str):
    """contextmanager with pickle load/save."""
    state = {}
    if Path(path).exists():
        with open(path, "rb") as f:
            state = pickle.load(f)  # pickle-unsafe
    yield state
    with open(path, "wb") as f:
        pickle.dump(state, f)


# ── Section 4: Generator patterns with dangerous operations ─────────

def eval_generator(expressions: list):
    """Generator that evals each expression."""
    for expr in expressions:
        yield eval(expr)  # eval-usage in generator


def sql_generator(conn, queries: list):
    """Generator that executes SQL queries."""
    for q in queries:
        yield conn.execute(f"SELECT * FROM data WHERE key = '{q}'").fetchall()  # sql-injection


def shell_generator(commands: list):
    """Generator that runs shell commands."""
    for cmd in commands:
        proc = subprocess.run(cmd, shell=True, capture_output=True, text=True)  # shell-true
        yield proc.stdout


def pickle_generator(file_paths: list):
    """Generator that loads pickle files."""
    for path in file_paths:
        with open(path, "rb") as f:
            yield pickle.load(f)  # pickle-unsafe in generator


def file_reader_generator(paths: list):
    """Generator that opens files without closing properly."""
    for path in paths:
        f = open(path)  # open-without-with — FD leak per iteration
        yield f.read()
        # f never closed


# ── Section 5: __getattr__ / __getattribute__ abuse ──────────────────

class DynamicExecutor:
    """Class that executes any method call as shell command."""

    def __getattr__(self, name: str):
        def method(*args):
            cmd = f"{name} {' '.join(str(a) for a in args)}"
            return os.system(cmd)  # os-system via __getattr__
        return method


class SQLProxy:
    """Proxy that turns attribute access into SQL queries."""

    def __init__(self, conn):
        self.conn = conn

    def __getattr__(self, table_name: str):
        def query(**kwargs):
            conditions = " AND ".join(f"{k} = '{v}'" for k, v in kwargs.items())
            return self.conn.execute(
                f"SELECT * FROM {table_name} WHERE {conditions}"  # sql-injection
            ).fetchall()
        return query


class EvalProxy:
    """Proxy that evals attribute names."""

    def __getattr__(self, name: str):
        return eval(name)  # eval-usage via __getattr__


# ── Section 6: __del__ destructors ───────────────────────────────────

class TempFileManager:
    """Manager with shell cleanup in __del__."""

    def __init__(self, temp_dir: str):
        self.temp_dir = temp_dir

    def __del__(self):
        # Runs on garbage collection — injection via temp_dir
        os.system(f"rm -rf {self.temp_dir}")  # os-system in __del__


class DBCleaner:
    """Cleaner with SQL in __del__."""

    def __init__(self, conn, table: str):
        self.conn = conn
        self.table = table

    def __del__(self):
        self.conn.execute(f"DELETE FROM {self.table} WHERE expired = 1")  # sql-injection in __del__


# ── Section 7: __format__ injection ──────────────────────────────────

class UserInput:
    """Class with dangerous __format__."""

    def __init__(self, value: str):
        self.value = value

    def __format__(self, format_spec: str):
        if format_spec == "eval":
            return str(eval(self.value))  # eval-usage in __format__
        if format_spec == "exec":
            exec(self.value)  # exec-usage in __format__
            return ""
        return self.value


class SQLFormatter:
    """Formatter that builds SQL."""

    def __init__(self, table: str):
        self.table = table

    def __format__(self, format_spec: str):
        return f"SELECT * FROM {self.table} WHERE {format_spec}"  # sql building in __format__


# ── Section 8: cached_property / lru_cache with secrets ──────────────

class ServiceConfig:
    """Config with secrets in cached properties."""

    @functools.cached_property
    def db_password(self) -> str:
        """Cached password — stays in memory."""
        return os.environ.get("DB_PASSWORD", "CachedFallbackPassword2024!")  # hardcoded fallback

    @functools.cached_property
    def api_key(self) -> str:
        """Cached API key."""
        return os.environ.get("API_KEY", "cached_api_key_prod_fallback_2024")  # hardcoded fallback

    @functools.cached_property
    def signing_key(self) -> bytes:
        """Cached signing key — weak derivation."""
        secret = os.environ.get("SIGNING_SECRET", "default-signing-secret")
        return hashlib.md5(secret.encode()).digest()  # weak-hash for key


@functools.lru_cache(maxsize=128)
def get_user_token(user_id: int) -> str:
    """Cached user token — stays in memory after logout."""
    return hashlib.sha1(  # weak-hash
        f"token:{user_id}:{os.urandom(8).hex()}".encode()
    ).hexdigest()


# ── Section 9: functools.partial with dangerous functions ────────────

# Partial application of dangerous functions
run_system = functools.partial(os.system)  # os.system partial
run_eval = functools.partial(eval)  # eval partial
run_exec = functools.partial(exec)  # exec partial

run_subprocess = functools.partial(
    subprocess.run, shell=True, capture_output=True  # shell-true in partial
)


def apply_partial(func: Callable, *args) -> Any:
    """Apply any partial function."""
    return func(*args)


# ── Section 10: Hardcoded secrets in class hierarchy ─────────────────

class BaseService:
    """Base service with hardcoded secret."""
    SECRET_KEY = "base-service-secret-key-production"  # hardcoded-secret


class AuthService(BaseService):
    """Auth service inheriting secret."""
    AUTH_TOKEN = "auth-service-token-production-2024"  # hardcoded-secret

    def authenticate(self, token: str) -> bool:
        return hmac.new(
            self.SECRET_KEY.encode(), token.encode(), hashlib.sha256
        ).hexdigest() == token  # timing attack


class PaymentService(BaseService):
    """Payment service with hardcoded keys."""
    STRIPE_KEY = "doji_fake_payment_service_key_2024"  # hardcoded-secret
    PAYMENT_SECRET = "payment-webhook-secret-production"  # hardcoded-secret


# ── Section 11: Mixed chain — realistic service ─────────────────────

class PluginSystem:
    """Plugin system combining multiple vulnerability patterns."""

    PLUGIN_SECRET = "plugin-system-master-key-2024"  # hardcoded-secret

    def __init__(self, db_path: str = "plugins.db"):
        self.conn = sqlite3.connect(db_path)

    @contextmanager
    def plugin_context(self, plugin_name: str):
        """Context manager for plugin execution — SQL injection."""
        self.conn.execute(
            f"UPDATE plugins SET status = 'running' WHERE name = '{plugin_name}'"  # sql-injection
        )
        try:
            yield self.conn
        finally:
            self.conn.execute(
                f"UPDATE plugins SET status = 'idle' WHERE name = '{plugin_name}'"  # sql-injection
            )

    def run_plugin_code(self, code: str):
        """Execute plugin code — RCE."""
        exec(code, {"os": os, "subprocess": subprocess})  # exec-usage

    def search_plugins(self, query: str) -> list:
        """Search plugins — SQL injection."""
        return self.conn.execute(
            f"SELECT * FROM plugins WHERE name LIKE '%{query}%'"  # sql-injection
        ).fetchall()

    def install_from_url(self, url: str) -> bytes:
        """Install plugin from URL — SSRF + pickle."""
        import urllib.request
        data = urllib.request.urlopen(url).read()  # ssrf-risk
        return pickle.loads(data)  # pickle-unsafe from URL

    def export_plugins(self, format_type: str) -> str:
        """Export — command injection."""
        path = f"/tmp/plugins_export.{format_type}"  # hardcoded-tmp
        subprocess.run(
            f"sqlite3 plugins.db '.dump' > {path}",
            shell=True,  # shell-true
        )
        return path

    def hash_plugin(self, plugin_path: str) -> str:
        """Hash plugin — weak hash."""
        data = open(plugin_path, "rb").read()  # open-without-with
        return hashlib.md5(data).hexdigest()  # weak-hash
