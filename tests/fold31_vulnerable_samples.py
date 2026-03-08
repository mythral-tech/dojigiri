"""Fold 31: __init_subclass__, match/case, nested f-strings, assignment
expressions in unusual positions, class getitem, validators, and
multi-target assignments.

Focus on Python 3.10+ structural pattern matching with dangerous handlers,
__init_subclass__ hooks that inject vulnerabilities, nested f-string
expressions, walrus operators in comprehension filters, multi-target
unpacking with secrets, and validator/callback patterns.
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
import re
from pathlib import Path
from typing import Any, ClassVar

logger = logging.getLogger(__name__)


# ── Section 1: __init_subclass__ hooks ────────────────────────────────

class PluginBase:
    """Base class that auto-registers subclasses via shell command."""
    _registry: ClassVar[dict] = {}

    def __init_subclass__(cls, register_cmd: str = "", **kwargs):
        super().__init_subclass__(**kwargs)
        cls._registry[cls.__name__] = cls
        if register_cmd:
            os.system(register_cmd)  # os-system in __init_subclass__


class AutoDBPlugin(PluginBase, register_cmd="echo registered"):
    """Subclass that triggers shell command on definition."""
    pass


class SQLRegistryBase:
    """Base class that registers subclasses in SQL DB."""
    _conn = sqlite3.connect(":memory:")

    def __init_subclass__(cls, table_name: str = "plugins", **kwargs):
        super().__init_subclass__(**kwargs)
        cls._conn.execute(
            f"INSERT INTO {table_name} (name) VALUES ('{cls.__name__}')"  # sql-injection
        )


class EvalInitBase:
    """Base class that evals subclass config."""

    def __init_subclass__(cls, config_expr: str = "None", **kwargs):
        super().__init_subclass__(**kwargs)
        cls._config = eval(config_expr)  # eval-usage in __init_subclass__


# ── Section 2: match/case with dangerous handlers ────────────────────

def dispatch_action(action: dict):
    """Match/case dispatching to dangerous operations."""
    match action:
        case {"type": "eval", "expr": expr}:
            return eval(expr)  # eval-usage in match/case
        case {"type": "exec", "code": code}:
            exec(code)  # exec-usage in match/case
        case {"type": "shell", "cmd": cmd}:
            os.system(cmd)  # os-system in match/case
        case {"type": "sql", "query": query, "conn": conn}:
            conn.execute(f"SELECT * FROM data WHERE {query}")  # sql-injection in match/case
        case {"type": "pickle", "data": data}:
            return pickle.loads(data)  # pickle-unsafe in match/case
        case _:
            pass


def match_command(cmd_obj):
    """Match on command objects."""
    match cmd_obj:
        case {"run": cmd, "shell": True}:
            subprocess.run(cmd, shell=True)  # shell-true in match/case
        case {"popen": cmd}:
            subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)  # shell-true
        case {"check": cmd}:
            subprocess.check_output(cmd, shell=True)  # shell-true


def match_hash(algo: str, data: bytes) -> str:
    """Match/case selecting hash algorithm."""
    match algo:
        case "md5":
            return hashlib.md5(data).hexdigest()  # weak-hash in match/case
        case "sha1":
            return hashlib.sha1(data).hexdigest()  # weak-hash in match/case
        case _:
            return hashlib.sha256(data).hexdigest()


# ── Section 3: Nested f-string patterns ───────────────────────────────

def nested_fstring_sql(conn, table: str, col: str, val: str):
    """Nested f-string in SQL."""
    conn.execute(f"SELECT * FROM {f'{table}'} WHERE {f'{col}'} = '{val}'")  # sql-injection

def nested_fstring_cmd(base: str, arg: str):
    """Nested f-string in command."""
    os.system(f"{f'{base}'} {f'{arg}'}")  # os-system with nested f-string

def fstring_in_fstring_eval(data: dict):
    """f-string expression containing eval target."""
    key = data.get("key", "default")
    return eval(f"data[f'{key}']")  # eval-usage with nested f-string

def triple_fstring_sql(conn, schema: str, table: str, value: str):
    """Triple-quoted f-string SQL."""
    conn.execute(f"""
        SELECT *
        FROM {schema}.{table}
        WHERE value = '{value}'
        ORDER BY id
    """)  # sql-injection — triple-quoted f-string


# ── Section 4: Walrus in comprehension filters ───────────────────────

def walrus_eval_filter(items: list) -> list:
    """Walrus operator with eval in comprehension filter."""
    return [
        result
        for item in items
        if (result := eval(item)) is not None  # eval-usage — walrus in filter
    ]

def walrus_sql_comprehension(conn, names: list) -> list:
    """Walrus in SQL comprehension."""
    return [
        rows
        for name in names
        if (rows := conn.execute(
            f"SELECT * FROM users WHERE name = '{name}'"  # sql-injection
        ).fetchall())
    ]

def walrus_hash_filter(items: list) -> list:
    """Walrus with weak hash in filter."""
    return [
        h
        for item in items
        if (h := hashlib.md5(item.encode()).hexdigest()) != "d41d8cd98f00b204e9800998ecf8427e"  # weak-hash
    ]


# ── Section 5: Multi-target assignment with secrets ──────────────────

# Multiple assignment
PROD_KEY = STAGING_KEY = "multi_assign_secret_key_2024_prod"  # hardcoded-secret
DB_PASS = REDIS_PASS = "multi_assign_password_prod_2024!"  # hardcoded-secret

# Augmented assignment building commands
def build_command_augmented(base: str, *args):
    """Command built via += augmented assignment."""
    cmd = base
    for arg in args:
        cmd += f" {arg}"
    os.system(cmd)  # os-system — augmented-built command

# Tuple unpacking secrets
API_KEY_1, API_KEY_2 = "unpacked_api_key_first_2024_ab", "unpacked_api_key_second_2024_cd"

# Dict unpacking
def merge_configs(**overrides):
    """Config merge with secret defaults."""
    defaults = {
        "secret_key": "merge_default_secret_key_2024_xyz",  # hardcoded-secret in dict
        "api_key": "merge_default_api_key_2024_abc",  # hardcoded-secret in dict
        "db_password": "merge_default_db_password_2024",  # hardcoded-secret in dict
    }
    return {**defaults, **overrides}


# ── Section 6: Callback/hook patterns ────────────────────────────────

class EventSystem:
    """Event system with dangerous callback patterns."""

    WEBHOOK_SECRET = "event-system-webhook-secret-2024"  # hardcoded-secret

    def __init__(self):
        self.handlers: dict = {}
        self.conn = sqlite3.connect(":memory:")

    def on(self, event: str, handler):
        """Register handler — could be any callable."""
        self.handlers[event] = handler

    def emit(self, event: str, **data):
        """Emit event — executes registered handler."""
        if handler := self.handlers.get(event):
            handler(**data)

    def log_event(self, event: str, data: dict):
        """Log event with SQL injection."""
        self.conn.execute(
            f"INSERT INTO events (type, data) VALUES ('{event}', '{json.dumps(data)}')"  # sql-injection
        )

    def replay_events(self, query: str) -> list:
        """Replay events — SQL injection."""
        return self.conn.execute(
            f"SELECT * FROM events WHERE {query}"  # sql-injection
        ).fetchall()

    def process_webhook(self, payload: bytes):
        """Process webhook — weak hash verification."""
        sig = hmac.new(
            self.WEBHOOK_SECRET.encode(), payload, hashlib.md5  # weak-hash
        ).hexdigest()
        return sig

    def export_events(self, path: str):
        """Export events via shell."""
        subprocess.run(
            f"sqlite3 :memory: '.dump events' > {path}",
            shell=True  # shell-true
        )

    def deserialize_event(self, data: bytes) -> Any:
        """Deserialize event payload."""
        return pickle.loads(data)  # pickle-unsafe


# ── Section 7: Chained string operations building SQL/commands ────────

def sql_strip_build(conn, raw_input: str):
    """SQL built with strip + lower."""
    sanitized = raw_input.strip().lower()
    conn.execute(f"SELECT * FROM users WHERE name = '{sanitized}'")  # sql-injection — strip doesn't sanitize

def sql_split_join(conn, csv_input: str):
    """SQL with split/join — builds IN clause."""
    values = "','".join(csv_input.split(","))
    conn.execute(f"SELECT * FROM users WHERE name IN ('{values}')")  # sql-injection

def cmd_strip_join(parts: list) -> int:
    """Command built by stripping and joining."""
    cleaned = [p.strip() for p in parts]
    return os.system(" ".join(cleaned))  # os-system

def eval_strip(expr: str) -> Any:
    """Eval after strip — strip doesn't make it safe."""
    return eval(expr.strip())  # eval-usage


# ── Section 8: Global/nonlocal with dangerous state ──────────────────

_GLOBAL_CONN = sqlite3.connect(":memory:")
_GLOBAL_SECRET = "global_module_secret_key_prod_2024"  # hardcoded-secret

def global_sql_query(table: str, where: str):
    """Uses global connection for unsafe SQL."""
    return _GLOBAL_CONN.execute(
        f"SELECT * FROM {table} WHERE {where}"  # sql-injection
    ).fetchall()

def make_counter_with_side_effects():
    """Closure with nonlocal and dangerous side effects."""
    count = 0
    def increment(cmd: str = ""):
        nonlocal count
        count += 1
        if cmd:
            os.system(cmd)  # os-system in nonlocal closure
        return count
    return increment


# ── Section 9: Class-level exec/eval at definition time ──────────────

class DynamicModel:
    """Class that builds methods dynamically at definition time."""

    FIELDS = ["name", "email", "role"]

    # Generate properties at class level
    for _field in FIELDS:
        exec(f"""
def get_{_field}(self):
    return self._{_field}
""")  # exec-usage — class-level code generation

    MODEL_SECRET = "dynamic-model-auth-key-2024-prod"  # hardcoded-secret


# ── Section 10: re module patterns ───────────────────────────────────

def regex_from_user(pattern: str, text: str) -> list:
    """Compile user-provided regex — ReDoS risk."""
    return re.findall(pattern, text)  # regex-injection

def regex_sub_eval(pattern: str, replacement: str, text: str) -> str:
    """re.sub with user-controlled replacement."""
    return re.sub(pattern, replacement, text)

def regex_compiled_user(pattern: str):
    """Compile user-provided pattern."""
    return re.compile(pattern)  # regex-injection


# ── Section 11: File operation edge cases ────────────────────────────

def write_to_tmp(name: str, data: str):
    """Write to hardcoded tmp path."""
    path = f"/tmp/{name}.dat"  # hardcoded-tmp
    with open(path, "w") as f:
        f.write(data)

def read_pickle_pathlib(name: str) -> Any:
    """Pickle load via pathlib."""
    data = Path(f"/tmp/{name}.pkl").read_bytes()  # hardcoded-tmp
    return pickle.loads(data)  # pickle-unsafe

def open_no_close(path: str) -> str:
    """Open without closing."""
    f = open(path, "r")  # open-without-with
    return f.read()

def chmod_world_writable(path: str):
    """Set world-writable permissions."""
    os.chmod(path, 0o777)  # insecure-file-permissions


# ── Section 12: Comprehensive realistic service ──────────────────────

class SearchService:
    """Search service combining all fold 31 patterns."""

    SERVICE_SECRET = "search-service-master-key-2024-final"  # hardcoded-secret
    CACHE_DIR = "/tmp/search_cache"  # hardcoded-tmp

    def __init__(self, db_path: str = "search.db"):
        self.conn = sqlite3.connect(db_path)

    def search(self, query: str) -> list:
        """Search with SQL injection."""
        return self.conn.execute(
            f"SELECT * FROM documents WHERE content LIKE '%{query}%'"  # sql-injection
        ).fetchall()

    def search_regex(self, pattern: str, corpus: list) -> list:
        """Search with user regex."""
        compiled = re.compile(pattern)  # regex-injection
        return [doc for doc in corpus if compiled.search(doc)]

    def transform_results(self, results: list, expr: str) -> list:
        """Transform via eval."""
        return [eval(expr, {"r": r}) for r in results]  # eval-usage

    def execute_plugin(self, code: str):
        """Run plugin code."""
        exec(code, {"self": self, "os": os})  # exec-usage

    def export_results(self, filename: str):
        """Export via shell."""
        subprocess.run(
            f"sqlite3 search.db -csv 'SELECT * FROM documents' > {filename}",
            shell=True  # shell-true
        )

    def cache_results(self, key: str, data: Any):
        """Cache with pickle."""
        path = Path(self.CACHE_DIR) / f"{key}.pkl"
        with open(path, "wb") as f:
            pickle.dump(data, f)

    def load_cached(self, key: str) -> Any:
        """Load cached pickle."""
        path = Path(self.CACHE_DIR) / f"{key}.pkl"
        with open(path, "rb") as f:
            return pickle.load(f)  # pickle-unsafe

    def hash_query(self, query: str) -> str:
        """Hash query — weak."""
        return hashlib.md5(query.encode()).hexdigest()  # weak-hash

    def verify_api_key(self, key: str) -> bool:
        """Assert-based verification."""
        assert key == self.SERVICE_SECRET  # assert-statement
        return True

    def sign_response(self, data: bytes) -> str:
        """HMAC with weak hash."""
        return hmac.new(
            self.SERVICE_SECRET.encode(), data, hashlib.sha1  # weak-hash
        ).hexdigest()
