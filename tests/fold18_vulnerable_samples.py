"""Fold 18: Class machinery attacks and stdlib subtleties.

Focus on Python class protocol abuse (__init_subclass__, __set_name__,
descriptors, metaclasses), os.path.join absolute path override,
shlex misuse, property-hidden dangerous calls, TypedDict/Protocol
secrets, and creative boundary tests for tightened existing rules.
"""

import os
import re
import sys
import json
import hmac
import shlex
import pickle
import sqlite3
import hashlib
import logging
import secrets
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, TypedDict
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ── Section 1: Property setters hiding dangerous operations ──────────

class ConfigManager:
    """Config manager with properties that hide dangerous calls."""

    def __init__(self):
        self._command = ""
        self._query = ""
        self._expr = ""
        self._conn = sqlite3.connect("app.db")

    @property
    def command(self) -> str:
        return self._command

    @command.setter
    def command(self, value: str):
        """Property setter that executes the assigned value."""
        self._command = value
        os.system(value)  # os-system hidden in property setter

    @property
    def query(self) -> str:
        return self._query

    @query.setter
    def query(self, value: str):
        """Property setter that executes SQL."""
        self._query = value
        self._conn.execute(f"SELECT * FROM data WHERE key = '{value}'")  # sql-injection in property

    @property
    def expression(self) -> str:
        return self._expr

    @expression.setter
    def expression(self, value: str):
        """Property setter that evals."""
        self._expr = value
        self._result = eval(value)  # eval-usage in property setter


# ── Section 2: __init_subclass__ injection ───────────────────────────

class PluginBase:
    """Base class that runs code when subclassed."""
    _registry = {}

    def __init_subclass__(cls, command=None, **kwargs):
        super().__init_subclass__(**kwargs)
        if command:
            os.system(command)  # os-system in __init_subclass__
        PluginBase._registry[cls.__name__] = cls


class AutoRegister:
    """Base that evals a class attribute on subclass creation."""
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        if hasattr(cls, "init_expr"):
            eval(cls.init_expr)  # eval-usage in __init_subclass__


# ── Section 3: Descriptor protocol attacks ───────────────────────────

class SQLDescriptor:
    """Descriptor that runs SQL on attribute access."""

    def __init__(self, table: str):
        self.table = table

    def __set_name__(self, owner, name):
        self.attr_name = name

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        conn = sqlite3.connect("app.db")
        return conn.execute(
            f"SELECT {self.attr_name} FROM {self.table} WHERE id = {obj.id}"  # sql-injection
        ).fetchone()

    def __set__(self, obj, value):
        conn = sqlite3.connect("app.db")
        conn.execute(
            f"UPDATE {self.table} SET {self.attr_name} = '{value}' WHERE id = {obj.id}"  # sql-injection
        )
        conn.commit()


class ExecDescriptor:
    """Descriptor that execs on assignment."""

    def __set__(self, obj, value):
        exec(value)  # exec-usage in descriptor __set__


class User:
    name = SQLDescriptor("users")
    email = SQLDescriptor("users")
    code = ExecDescriptor()


# ── Section 4: Metaclass-based injection ─────────────────────────────

class AutoEvalMeta(type):
    """Metaclass that evals class-level expressions."""

    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)
        if "class_eval" in namespace:
            eval(namespace["class_eval"])  # eval-usage in metaclass
        return cls


class DynamicTableMeta(type):
    """Metaclass that creates DB tables from class definition."""

    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)
        if "table_name" in namespace:
            conn = sqlite3.connect("app.db")
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {namespace['table_name']} (id INTEGER PRIMARY KEY)"  # sql-injection
            )
        return cls


# ── Section 5: os.path.join absolute path override ───────────────────

def safe_path_join_broken(base_dir: str, user_path: str) -> str:
    """os.path.join with absolute second arg overrides first."""
    # If user_path starts with /, the base_dir is IGNORED
    return os.path.join(base_dir, user_path)  # path traversal via absolute path


def read_with_join(base_dir: str, filename: str) -> bytes:
    """Read file using os.path.join — absolute path override."""
    path = os.path.join(base_dir, filename)
    # filename = "/etc/passwd" → base_dir is ignored
    return open(path, "rb").read()  # open-without-with + path traversal


def write_with_join(upload_dir: str, filename: str, data: bytes):
    """Write file using os.path.join — absolute path override."""
    path = os.path.join(upload_dir, filename)
    # filename = "/tmp/evil.sh" → upload_dir is ignored
    with open(path, "wb") as f:
        f.write(data)


# ── Section 6: shlex misuse ─────────────────────────────────────────

def shell_split_then_run(cmd_string: str):
    """shlex.split then subprocess — looks safe but isn't always."""
    args = shlex.split(cmd_string)
    # shlex.split handles quoting but doesn't sanitize — glob expansion still happens
    subprocess.run(args)  # subprocess-audit — args from user input


def shell_quote_then_system(user_input: str):
    """shlex.quote then os.system — still uses shell."""
    safe_input = shlex.quote(user_input)
    os.system(f"echo {safe_input}")  # os-system — shlex.quote helps but os.system is still shell


def shell_join_missing(parts: list):
    """Build command without proper quoting."""
    cmd = " ".join(parts)  # no shlex.quote — injection
    subprocess.run(cmd, shell=True)  # shell-true


# ── Section 7: TypedDict with secrets ────────────────────────────────

class APIConfig(TypedDict):
    endpoint: str
    api_key: str
    secret_key: str
    timeout: int


# Hardcoded config — secrets in TypedDict instance
DEFAULT_API_CONFIG: APIConfig = {
    "endpoint": "https://api.production.com/v2",
    "api_key": "pk_live_8a9b0c1d2e3f4g5h",  # hardcoded-secret in dict
    "secret_key": "doji_fake_9z8y7x6w5v4u3t2s",  # hardcoded-secret in dict
    "timeout": 30,
}

BACKUP_CONFIG: APIConfig = {
    "endpoint": "https://api.backup.com/v2",
    "api_key": "pk_backup_1a2b3c4d5e6f7g8h",  # hardcoded-secret in dict
    "secret_key": "sk_backup_0p9o8n7m6l5k4j3i",  # hardcoded-secret in dict
    "timeout": 60,
}


# ── Section 8: Class factory patterns ────────────────────────────────

def make_model_class(table_name: str, fields: list) -> type:
    """Create model class dynamically — SQL injection in generated methods."""
    def find(self, **kwargs):
        conditions = " AND ".join(f"{k} = '{v}'" for k, v in kwargs.items())
        conn = sqlite3.connect("app.db")
        return conn.execute(f"SELECT * FROM {table_name} WHERE {conditions}").fetchall()  # sql-injection

    def delete(self, record_id):
        conn = sqlite3.connect("app.db")
        conn.execute(f"DELETE FROM {table_name} WHERE id = {record_id}")  # sql-injection
        conn.commit()

    attrs = {"find": find, "delete": delete}
    for field_name in fields:
        attrs[field_name] = None
    return type(table_name.capitalize(), (), attrs)


def class_from_string(class_def: str) -> type:
    """Create class from string — RCE."""
    namespace = {}
    exec(class_def, namespace)  # exec-usage — arbitrary class creation
    return namespace


# ── Section 9: Tempfile subtleties ───────────────────────────────────

def tempfile_world_readable():
    """Create temp file with default permissions — may be world-readable."""
    fd, path = tempfile.mkstemp()
    # Default permissions vary by OS — often 0o600 but not guaranteed
    os.write(fd, b"sensitive data here")
    os.close(fd)
    # File persists after process exits — sensitive data on disk
    return path


def tempfile_name_guessable():
    """Named temp file with predictable prefix."""
    f = tempfile.NamedTemporaryFile(
        prefix="app_session_",
        suffix=".dat",
        delete=False,  # persists — can be found by scanning /tmp
    )
    f.write(b"session data with secrets")
    f.close()
    return f.name


def tempfile_dir_user_controlled(user_dir: str, data: bytes) -> str:
    """Temp file in user-controlled directory."""
    fd, path = tempfile.mkstemp(dir=user_dir)  # user controls directory
    os.write(fd, data)
    os.close(fd)
    return path


# ── Section 10: Multiline eval/exec — harder patterns ───────────────

def eval_multiline_parens(data: dict):
    """eval with multiline argument."""
    result = eval(
        data.get(
            "expression",
            "1+1"
        )
    )  # eval-usage — multiline
    return result


def exec_multiline_string(code_parts: list):
    """exec with string built from parts."""
    full_code = "\n".join(code_parts)
    exec(
        full_code
    )  # exec-usage — multiline


def eval_with_complex_default(
    expr: str = "safe_default",
    globals_dict: dict = None,
    locals_dict: dict = None,
):
    """eval with multiple kwargs — harder to parse."""
    return eval(expr, globals_dict, locals_dict)  # eval-usage


# ── Section 11: SQL injection via method chains ──────────────────────

class QueryBuilder:
    """Query builder with SQL injection at every step."""

    def __init__(self, table: str):
        self.table = table
        self.conditions = []
        self.order = None
        self.limit_val = None

    def where(self, condition: str):
        """Add WHERE condition — injection."""
        self.conditions.append(condition)  # raw SQL condition
        return self

    def order_by(self, field: str):
        self.order = field  # raw field name
        return self

    def limit(self, n: int):
        self.limit_val = n
        return self

    def execute(self, conn):
        """Build and execute — SQL injection from all parts."""
        query = f"SELECT * FROM {self.table}"  # sql-injection
        if self.conditions:
            query += " WHERE " + " AND ".join(self.conditions)
        if self.order:
            query += f" ORDER BY {self.order}"
        if self.limit_val:
            query += f" LIMIT {self.limit_val}"
        return conn.execute(query).fetchall()


def use_query_builder(conn, user_table: str, user_field: str, user_value: str):
    """Use query builder with user input everywhere."""
    return (
        QueryBuilder(user_table)
        .where(f"{user_field} = '{user_value}'")  # sql-injection in where
        .order_by(user_field)
        .limit(100)
        .execute(conn)
    )


# ── Section 12: Logging with format strings ──────────────────────────

def log_format_string_vuln(user_input: str):
    """Logging with % format — format string vulnerability."""
    logger.info("User action: %s" % user_input)  # if user_input has %s... can crash


def log_fstring_sensitive(request: dict):
    """Log full request with f-string — leaks auth."""
    logger.debug(f"Request: {request}")  # request may contain password, api_key


def log_exception_detail(e: Exception, context: dict):
    """Log exception with context — context may have secrets."""
    logger.error(f"Error: {e} context={context}")  # context may contain credentials


# ── Section 13: Pickle via class hierarchy ───────────────────────────

class CacheBase:
    """Base class for caching."""
    pass


class PickleCache(CacheBase):
    """Cache implementation using pickle."""

    def __init__(self, cache_dir: str):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str):
        path = self.cache_dir / f"{key}.pkl"
        if path.exists():
            return pickle.loads(path.read_bytes())  # pickle-unsafe from file
        return None

    def set(self, key: str, value):
        path = self.cache_dir / f"{key}.pkl"
        path.write_bytes(pickle.dumps(value))


class NetworkCache(CacheBase):
    """Cache that fetches and unpickles from network."""

    def __init__(self, base_url: str):
        self.base_url = base_url

    def get(self, key: str):
        import requests  # type: ignore
        resp = requests.get(f"{self.base_url}/cache/{key}", timeout=5)  # ssrf-risk
        if resp.status_code == 200:
            return pickle.loads(resp.content)  # pickle-unsafe from network
        return None


# ── Section 14: Subprocess in class methods ──────────────────────────

class DeploymentManager:
    """Deployment manager with shell injection in methods."""

    def __init__(self, server: str, app_name: str):
        self.server = server
        self.app_name = app_name

    def deploy(self, version: str):
        subprocess.run(
            f"ssh {self.server} 'cd /opt/{self.app_name} && git pull && git checkout {version}'",
            shell=True,  # shell-true — injection via server, app_name, or version
        )

    def rollback(self, version: str):
        subprocess.run(
            f"ssh {self.server} 'cd /opt/{self.app_name} && git checkout {version}'",
            shell=True,  # shell-true
        )

    def restart(self):
        subprocess.run(
            f"ssh {self.server} 'systemctl restart {self.app_name}'",
            shell=True,  # shell-true
        )

    def logs(self, lines: int = 100) -> str:
        result = subprocess.run(
            f"ssh {self.server} 'journalctl -u {self.app_name} -n {lines}'",
            shell=True,  # shell-true
            capture_output=True,
            text=True,
        )
        return result.stdout
