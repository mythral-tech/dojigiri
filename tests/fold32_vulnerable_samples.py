"""Fold 32: __set_name__ hooks, __class__ cell, starred unpacking,
classmethod/staticmethod vulns, __repr__/__str__ info leaks,
sys module abuse, and augmented operators building dangerous strings.

Focus on lesser-explored dunder methods, class construction hooks,
staticmethod wrappers hiding dangerous calls, and sys module
functions that can be dangerous.
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
import tempfile
import marshal
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


# ── Section 1: __set_name__ with side effects ────────────────────────

class RegisterField:
    """Descriptor that runs SQL on __set_name__."""

    def __set_name__(self, owner, name):
        self.name = name
        if hasattr(owner, '_conn'):
            owner._conn.execute(
                f"ALTER TABLE {owner.__name__} ADD COLUMN {name} TEXT"  # sql-injection in __set_name__
            )

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return getattr(obj, f"_{self.name}", None)

    def __set__(self, obj, value):
        setattr(obj, f"_{self.name}", value)


class ShellField:
    """Descriptor that runs shell on __set_name__."""

    def __set_name__(self, owner, name):
        self.name = name
        os.system(f"echo 'Registered field {name} on {owner.__name__}'")  # os-system in __set_name__


class ExecField:
    """Descriptor that execs validation code on __set_name__."""

    def __set_name__(self, owner, name):
        self.name = name
        # Generate a validator method
        exec(f"""
def validate_{name}(self, value):
    if not isinstance(value, str):
        raise TypeError(f'{{name}} must be str')
    return value
""", owner.__dict__ if isinstance(owner.__dict__, dict) else {})  # exec-usage in __set_name__


# ── Section 2: classmethod/staticmethod hiding dangers ───────────────

class DataService:
    """Service with dangerous classmethods and staticmethods."""

    DB_SECRET = "data-service-class-secret-2024"  # hardcoded-secret

    @classmethod
    def from_query(cls, conn, query_str: str):
        """Classmethod factory with SQL injection."""
        rows = conn.execute(
            f"SELECT * FROM data WHERE {query_str}"  # sql-injection in classmethod
        ).fetchall()
        return cls()

    @classmethod
    def from_pickle(cls, data: bytes):
        """Classmethod factory deserializing pickle."""
        config = pickle.loads(data)  # pickle-unsafe in classmethod
        return cls()

    @staticmethod
    def run_migration(sql: str, conn):
        """Staticmethod running raw SQL."""
        conn.execute(sql)  # raw SQL execution

    @staticmethod
    def shell_deploy(cmd: str) -> int:
        """Staticmethod running shell command."""
        return os.system(cmd)  # os-system in staticmethod

    @staticmethod
    def eval_config(config_str: str) -> dict:
        """Staticmethod evaluating config string."""
        return eval(config_str)  # eval-usage in staticmethod

    @staticmethod
    def hash_data(data: bytes) -> str:
        """Staticmethod with weak hash."""
        return hashlib.md5(data).hexdigest()  # weak-hash in staticmethod

    @classmethod
    def create_temp_report(cls, name: str) -> str:
        """Classmethod writing to tmp."""
        path = f"/tmp/report_{name}.csv"  # hardcoded-tmp
        return path


# ── Section 3: __repr__/__str__ information leaks ────────────────────

class UserSession:
    """Session that leaks secrets in __repr__."""

    def __init__(self, user_id: str, token: str, api_key: str):
        self.user_id = user_id
        self.token = token
        self.api_key = api_key

    def __repr__(self):
        # Leaks token and api_key in repr output
        return f"UserSession(user_id={self.user_id!r}, token={self.token!r}, api_key={self.api_key!r})"

    def __str__(self):
        return f"Session for {self.user_id} with token {self.token}"


class DatabaseConnection:
    """Connection that leaks credentials in repr."""

    def __init__(self, host: str, password: str):
        self.host = host
        self.password = password
        self.conn_str = f"postgresql://admin:{password}@{host}:5432/db"  # db-connection-string

    def __repr__(self):
        return f"DB({self.conn_str})"  # leaks connection string with password


# ── Section 4: sys module abuse ──────────────────────────────────────

def sys_path_inject(malicious_path: str):
    """Inject into sys.path — module hijacking."""
    sys.path.insert(0, malicious_path)  # sys-path-modify

def sys_modules_inject(name: str, module):
    """Replace module in sys.modules."""
    sys.modules[name] = module  # module replacement — could override stdlib

def sys_setprofile_hook(frame, event, arg):
    """sys.setprofile for execution tracing — privacy risk."""
    if event == "call":
        logger.info(f"Called: {frame.f_code.co_name} with locals: {frame.f_locals}")  # logs all locals

def sys_settrace_hook(frame, event, arg):
    """sys.settrace for debugging — code execution monitoring."""
    if event == "call":
        exec(f"print('Tracing: {frame.f_code.co_name}')")  # exec-usage in trace hook

def sys_exit_cleanup(cleanup_cmd: str):
    """Register cleanup command on exit."""
    import atexit
    atexit.register(os.system, cleanup_cmd)  # os-system registered as atexit handler


# ── Section 5: marshal module — like pickle but worse ────────────────

def marshal_load(path: str) -> Any:
    """Load marshalled data — code execution risk."""
    with open(path, "rb") as f:
        return marshal.load(f)  # unsafe-deserialization — marshal

def marshal_loads(data: bytes) -> Any:
    """Loads marshalled bytes."""
    return marshal.loads(data)  # unsafe-deserialization — marshal


# ── Section 6: tempfile misuse patterns ──────────────────────────────

def insecure_mktemp(suffix: str = ".dat") -> str:
    """tempfile.mktemp — race condition."""
    return tempfile.mktemp(suffix=suffix)  # insecure-tempfile — mktemp race

def predictable_temp(name: str) -> str:
    """Predictable temp path construction."""
    path = f"/tmp/myapp_{name}"  # hardcoded-tmp
    with open(path, "w") as f:
        f.write("data")
    return path

def temp_pickle_roundtrip(data: Any) -> Any:
    """Pickle via tempfile."""
    path = tempfile.mktemp(suffix=".pkl")  # insecure-tempfile
    with open(path, "wb") as f:
        pickle.dump(data, f)
    with open(path, "rb") as f:
        return pickle.load(f)  # pickle-unsafe via tempfile


# ── Section 7: Starred assignment and unpacking ──────────────────────

def starred_secrets():
    """Starred unpacking with secrets."""
    first, *rest = [
        "primary_secret_key_production_2024",  # hardcoded-secret
        "secondary_secret_key_prod_2024_ab",
        "tertiary_secret_key_prod_2024_cd",
    ]
    return first, rest

# Starred in function signature with SQL
def insert_records(conn, table: str, *values):
    """Insert with starred values — SQL injection."""
    vals = "', '".join(str(v) for v in values)
    conn.execute(
        f"INSERT INTO {table} VALUES ('{vals}')"  # sql-injection — starred args
    )

def multi_return_secrets():
    """Multiple return values with secrets."""
    key = "multi_return_api_key_production_24"  # hardcoded-secret
    token = "multi_return_auth_token_prod_2024"  # hardcoded-secret
    return key, token


# ── Section 8: Augmented assignment building commands ────────────────

def build_sql_augmented(conn, base_query: str, filters: list):
    """SQL built with += augmented assignment."""
    query = f"SELECT * FROM data WHERE 1=1"
    for f in filters:
        query += f" AND {f}"  # string concatenation building SQL
    conn.execute(query)  # sql via augmented assignment

def build_cmd_augmented(base: str, args: list) -> int:
    """Command built with += ."""
    cmd = base
    for arg in args:
        cmd += f" --{arg}"
    return os.system(cmd)  # os-system — augmented-built command

def build_code_augmented(parts: list) -> Any:
    """Code built with += then evaled."""
    code = ""
    for part in parts:
        code += part + "\n"
    return eval(code)  # eval-usage — augmented-built code


# ── Section 9: Exception chaining with info leak ─────────────────────

class SecureOperation:
    """Operations that leak info via exception chains."""

    SECRET = "secure-operation-master-key-2024"  # hardcoded-secret

    def query(self, conn, user_input: str):
        try:
            return conn.execute(
                f"SELECT * FROM users WHERE name = '{user_input}'"  # sql-injection
            ).fetchall()
        except Exception as e:
            # Re-raises with SQL query visible in chain
            raise RuntimeError(f"Query failed: SELECT * FROM users WHERE name = '{user_input}'") from e

    def process(self, data: bytes):
        try:
            return pickle.loads(data)  # pickle-unsafe
        except Exception:
            pass  # exception swallowed

    def authenticate(self, token: str):
        assert token == self.SECRET  # assert-statement
        return True


# ── Section 10: Dict/set operations with dangerous values ────────────

def dict_setdefault_secret(config: dict) -> dict:
    """setdefault with hardcoded secret fallback."""
    config.setdefault("api_key", "setdefault_api_key_prod_2024_xyz")  # hardcoded-secret in setdefault
    config.setdefault("secret_key", "setdefault_secret_key_prod_2024")  # hardcoded-secret in setdefault
    return config

def dict_get_secret(config: dict) -> str:
    """dict.get with hardcoded secret fallback."""
    return config.get("password", "dict_get_fallback_password_2024!")  # hardcoded fallback

def dict_update_secrets(config: dict):
    """dict.update with secrets."""
    config.update({
        "api_key": "update_api_key_production_2024_ab",  # hardcoded-secret in dict
        "db_password": "update_db_password_prod_2024_cd",  # hardcoded-secret in dict
    })


# ── Section 11: String formatting edge cases ────────────────────────

def percent_format_sql(conn, table: str, col: str, val: str):
    """SQL via % formatting."""
    conn.execute("SELECT * FROM %s WHERE %s = '%s'" % (table, col, val))  # sql-injection — % format

def format_map_sql(conn, params: dict):
    """SQL via format_map."""
    template = "SELECT * FROM {table} WHERE {column} = '{value}'"
    conn.execute(template.format_map(params))  # sql-injection — format_map

def bytes_sql(conn, user: str):
    """SQL built then decoded from bytes."""
    query = f"SELECT * FROM users WHERE name = '{user}'"
    conn.execute(query)  # sql-injection


# ── Section 12: Comprehensive realistic service ──────────────────────

class AnalyticsEngine:
    """Analytics engine combining all fold 32 patterns."""

    ENGINE_KEY = "analytics-engine-api-key-prod-2024"  # hardcoded-secret
    CACHE_DIR = "/tmp/analytics_cache"  # hardcoded-tmp

    name = RegisterField()

    def __init__(self, db_path: str = "analytics.db"):
        self.conn = sqlite3.connect(db_path)

    def __repr__(self):
        return f"AnalyticsEngine(key={self.ENGINE_KEY})"  # leaks key in repr

    @classmethod
    def from_config(cls, config_str: str):
        """Factory from eval'd config."""
        config = eval(config_str)  # eval-usage in classmethod
        return cls(config.get("db_path", "analytics.db"))

    @staticmethod
    def validate_query(query: str) -> bool:
        """Validate by executing — dangerous."""
        try:
            sqlite3.connect(":memory:").execute(query)
            return True
        except Exception:
            return False

    def run_query(self, where_clause: str) -> list:
        """Query with SQL injection."""
        return self.conn.execute(
            f"SELECT * FROM events WHERE {where_clause}"  # sql-injection
        ).fetchall()

    def aggregate(self, expr: str, data: list) -> Any:
        """Aggregate via eval."""
        return eval(expr, {"data": data})  # eval-usage

    def export(self, format_cmd: str):
        """Export via shell."""
        subprocess.run(
            f"sqlite3 analytics.db -csv '.dump' | {format_cmd}",
            shell=True  # shell-true
        )

    def cache_result(self, key: str, value: Any):
        """Cache with pickle."""
        path = Path(self.CACHE_DIR) / f"{key}.pkl"
        with open(path, "wb") as f:
            pickle.dump(value, f)

    def load_cache(self, key: str) -> Any:
        """Load cached pickle."""
        path = Path(self.CACHE_DIR) / f"{key}.pkl"
        with open(path, "rb") as f:
            return pickle.load(f)  # pickle-unsafe

    def hash_event(self, data: bytes) -> str:
        """Weak hash."""
        return hashlib.sha1(data).hexdigest()  # weak-hash

    def verify_key(self, key: str):
        """Assert auth."""
        assert key == self.ENGINE_KEY  # assert-statement

    def run_hook(self, code: str):
        """Execute hook code."""
        exec(code, {"self": self, "os": os})  # exec-usage
