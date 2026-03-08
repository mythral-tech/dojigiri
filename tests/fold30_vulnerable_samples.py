"""Fold 30: Final fold — comprehension patterns, nested scopes, closures,
string methods for code building, multiline dict/list literals with secrets,
conditional imports, try/except with dangerous fallbacks, and __all__ exports.

Focus on patterns that hide vulnerabilities in Python's syntactic sugar:
list/dict/set comprehensions with side effects, nested function closures
capturing dangerous references, and string manipulation to build code/SQL.
"""

import os
import sys
import json
import hmac
import hashlib
import logging
import sqlite3
import pickle
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Section 1: Comprehension side effects ─────────────────────────────

def eval_comprehension(expressions: list) -> list:
    """List comprehension with eval."""
    return [eval(expr) for expr in expressions]  # eval-usage in comprehension

def exec_comprehension(code_blocks: list) -> list:
    """List comprehension with exec side effects."""
    return [exec(code) for code in code_blocks]  # exec-usage in comprehension

def sql_comprehension(conn, names: list) -> list:
    """List comprehension with SQL injection."""
    return [
        conn.execute(f"SELECT * FROM users WHERE name = '{name}'").fetchone()  # sql-injection
        for name in names
    ]

def system_comprehension(commands: list) -> list:
    """List comprehension with os.system."""
    return [os.system(cmd) for cmd in commands]  # os-system in comprehension

def pickle_comprehension(paths: list) -> list:
    """List comprehension loading pickles."""
    return [pickle.loads(Path(p).read_bytes()) for p in paths]  # pickle-unsafe in comprehension

def hash_comprehension(items: list) -> dict:
    """Dict comprehension with weak hash."""
    return {item: hashlib.md5(item.encode()).hexdigest() for item in items}  # weak-hash

def subprocess_comprehension(commands: list) -> list:
    """List comprehension with subprocess."""
    return [
        subprocess.check_output(cmd, shell=True, text=True)  # shell-true
        for cmd in commands
    ]


# ── Section 2: Generator expressions with dangers ────────────────────

def eval_genexpr(expressions: list) -> Any:
    """Generator expression with eval, consumed by next()."""
    return next(eval(e) for e in expressions)  # eval-usage in genexpr

def sql_genexpr(conn, ids: list) -> list:
    """Generator expression with SQL injection."""
    return list(
        conn.execute(f"SELECT * FROM t WHERE id = {i}").fetchone()  # sql-injection
        for i in ids
    )


# ── Section 3: Nested closures capturing dangerous refs ──────────────

def make_sql_executor(conn):
    """Closure that captures connection for unsafe SQL."""
    def execute(table: str, field: str, value: str):
        return conn.execute(
            f"SELECT * FROM {table} WHERE {field} = '{value}'"  # sql-injection in closure
        ).fetchall()
    return execute

def make_shell_runner():
    """Closure that runs shell commands."""
    def run(cmd: str) -> str:
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)  # shell-true
        return result.stdout
    return run

def make_eval_chain():
    """Nested closures creating eval chain."""
    def outer(transform: str):
        def inner(data: Any):
            return eval(transform, {"data": data})  # eval-usage in nested closure
        return inner
    return outer

def make_pickle_loader(base_dir: str):
    """Closure for pickle loading."""
    def load(name: str) -> Any:
        path = Path(base_dir) / f"{name}.pkl"
        with open(path, "rb") as f:
            return pickle.load(f)  # pickle-unsafe in closure
    return load


# ── Section 4: String methods building code/SQL ──────────────────────

def sql_via_replace(template: str, user: str) -> str:
    """SQL built via str.replace."""
    query = "SELECT * FROM users WHERE name = '{USER}'".replace("{USER}", user)
    return query  # sql via replace — no parameterization

def sql_via_join_parts(conn, table: str, conditions: list):
    """SQL built by joining condition parts."""
    where = " AND ".join(conditions)
    conn.execute(f"SELECT * FROM {table} WHERE {where}")  # sql-injection — joined conditions

def command_via_join(parts: list) -> int:
    """Shell command built by joining parts."""
    cmd = " ".join(parts)
    return os.system(cmd)  # os-system — joined command

def code_via_format(template: str, **kwargs) -> Any:
    """Code execution via string formatting."""
    code = template.format(**kwargs)
    return eval(code)  # eval-usage — formatted string


# ── Section 5: Conditional imports with dangerous fallbacks ──────────

def conditional_pickle():
    """Try cPickle, fall back to pickle — both unsafe."""
    try:
        import _pickle as pkl
    except ImportError:
        import pickle as pkl
    return pkl  # returns pickle module for unsafe use

def conditional_yaml_unsafe():
    """Try yaml with unsafe fallback."""
    try:
        from yaml import CSafeLoader as Loader
    except ImportError:
        from yaml import SafeLoader as Loader
    return Loader

def conditional_crypto():
    """Try modern crypto, fall back to weak."""
    try:
        from cryptography.hazmat.primitives import hashes
    except ImportError:
        # Fallback to weak hashlib
        pass
    return hashlib.md5  # weak-hash — returned as fallback


# ── Section 6: try/except with dangerous error handling ──────────────

def query_with_fallback(conn, user: str):
    """Try parameterized, fall back to unsafe on error."""
    try:
        return conn.execute("SELECT * FROM users WHERE name = ?", (user,))
    except Exception:
        # Fallback to string interpolation — UNSAFE
        return conn.execute(
            f"SELECT * FROM users WHERE name = '{user}'"  # sql-injection in except
        )

def shell_with_retry(cmd: str, retries: int = 3) -> str:
    """Retry shell commands on failure."""
    for attempt in range(retries):
        try:
            return subprocess.check_output(
                cmd, shell=True, text=True  # shell-true
            )
        except subprocess.CalledProcessError:
            continue
    return ""

def eval_with_fallback(expr: str) -> Any:
    """Eval with bare except fallback."""
    try:
        return eval(expr)  # eval-usage
    except:  # bare-except
        return None

def file_read_no_with(path: str) -> str:
    """File operations without context manager in try/except."""
    try:
        f = open(path)  # open-without-with
        data = f.read()
        f.close()
        return data
    except:  # bare-except
        return ""


# ── Section 7: Multiline data structures with secrets ────────────────

# Config dict spread across many lines
PRODUCTION_CONFIG = {
    "database": {
        "host": "prod-db.internal",
        "port": 5432,
        "password": "MultilineConfigPassword2024!",  # hardcoded-secret in nested dict
        "ssl": True,
    },
    "redis": {
        "url": "redis://:RedisMultilinePass2024@redis.prod:6379",  # db-connection-string
    },
    "api": {
        "secret_key": "multiline_api_secret_prod_2024_xyz",  # hardcoded-secret in nested dict
        "encryption_key": "multiline_enc_key_prod_2024_abc",  # hardcoded-secret in nested dict
    },
    "auth": {
        "jwt_secret": "multiline_jwt_secret_production_2024",  # hardcoded-secret in nested dict
        "oauth_client_secret": "multiline_oauth_secret_prod_24",  # hardcoded-secret in nested dict
    },
}

# List of connection strings
DB_URLS = [
    "postgresql://admin:ListPass2024@db1.prod:5432/app",  # db-connection-string
    "postgresql://admin:ListPass2024@db2.prod:5432/app",  # db-connection-string
    "mysql://root:MysqlListPass2024@mysql.prod:3306/db",  # db-connection-string
]

# Tuple of secrets
SECRET_TUPLE = (
    "tuple_secret_key_production_2024_first",  # hardcoded-secret
    "tuple_secret_key_production_2024_second",  # hardcoded-secret
)


# ── Section 8: __all__ with dangerous exports ────────────────────────

__all__ = [
    "eval_comprehension",
    "sql_comprehension",
    "make_shell_runner",
    "PRODUCTION_CONFIG",
    "AdminPanel",
]


# ── Section 9: Class with every pattern combined ─────────────────────

class AdminPanel:
    """Admin panel combining comprehension, closure, and string-building patterns."""

    ADMIN_SECRET = "admin-panel-master-secret-2024-final"  # hardcoded-secret
    ADMIN_TOKEN = "admin-bearer-token-production-2024-xyz"  # hardcoded-secret

    def __init__(self, db_path: str = "admin.db"):
        self.conn = sqlite3.connect(db_path)

    def bulk_query(self, names: list) -> list:
        """Comprehension SQL injection."""
        return [
            self.conn.execute(
                f"SELECT * FROM users WHERE name = '{n}'"  # sql-injection
            ).fetchone()
            for n in names
        ]

    def bulk_eval(self, expressions: list) -> list:
        """Comprehension eval."""
        return [eval(e) for e in expressions]  # eval-usage

    def bulk_command(self, commands: list) -> list:
        """Comprehension shell execution."""
        return [
            subprocess.run(cmd, shell=True, capture_output=True, text=True)  # shell-true
            for cmd in commands
        ]

    def transform_data(self, data: list, expr: str) -> list:
        """Transform using eval in comprehension."""
        return [eval(expr, {"row": row}) for row in data]  # eval-usage

    def cache_all(self, items: dict):
        """Bulk pickle cache."""
        for key, value in items.items():
            path = f"/tmp/admin_cache_{key}.pkl"  # hardcoded-tmp
            with open(path, "wb") as f:
                pickle.dump(value, f)

    def load_all_cache(self, keys: list) -> dict:
        """Bulk pickle load via comprehension."""
        result = {}
        for key in keys:
            path = f"/tmp/admin_cache_{key}.pkl"  # hardcoded-tmp
            with open(path, "rb") as f:
                result[key] = pickle.load(f)  # pickle-unsafe
        return result

    def hash_records(self, records: list) -> list:
        """Weak hash in comprehension."""
        return [hashlib.md5(str(r).encode()).hexdigest() for r in records]  # weak-hash

    def execute_hooks(self, hooks: list):
        """Execute hook code."""
        for hook in hooks:
            exec(hook, {"self": self, "os": os, "subprocess": subprocess})  # exec-usage

    def render_sql(self, template: str, **kwargs) -> list:
        """SQL via string format."""
        query = template.format(**kwargs)
        return self.conn.execute(query).fetchall()  # sql via format — injection

    def export_data(self, filename: str):
        """Export via shell."""
        subprocess.run(
            f"sqlite3 admin.db -csv 'SELECT * FROM users' > {filename}",
            shell=True  # shell-true
        )

    def verify_admin(self, token: str) -> bool:
        """Assert-based auth check."""
        assert token == self.ADMIN_TOKEN  # assert-statement
        return True

    def sign_payload(self, payload: bytes) -> str:
        """HMAC with weak hash."""
        return hmac.new(
            self.ADMIN_SECRET.encode(), payload, hashlib.md5  # weak-hash
        ).hexdigest()

    def open_report(self, path: str) -> str:
        """Open file without context manager."""
        f = open(path)  # open-without-with
        data = f.read()
        return data
