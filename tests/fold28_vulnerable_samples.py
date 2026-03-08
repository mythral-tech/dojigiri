"""Fold 28: Edge-case syntax and boundary conditions.

Stress-test regex boundaries: minimum-length secrets (exactly 8 chars),
secrets with unusual characters, SQL with different quote styles,
subprocess with keyword-only shell=True, chained method calls,
one-liner lambdas with dangerous calls, semicolon-separated statements,
walrus operator in conditions, and unusual whitespace patterns.
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
from typing import Any

logger = logging.getLogger(__name__)


# ── Section 1: Secret length boundaries ──────────────────────────────

# Exactly 8 chars — minimum threshold
PASS_8 = "password: 'Aa1Bb2Cc'"  # 8 chars — should match
KEY_8 = "api_key = 'X9y8Z7w6'"  # 8 chars — boundary

# 7 chars — below threshold (should NOT match)
SHORT_KEY = "api_key = 'Ab3Cd5e'"  # 7 chars — too short

# Secrets with all-special characters
SPECIAL_SECRET = "secret_key = '!@#$%^&*'"  # 8 special chars
MIXED_SECRET = "api_key = 'a1!b2@c3#d'"  # mixed alphanum + special

# Very long secret
LONG_SECRET_KEY = "doji_fake_key_abcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"  # hardcoded-secret

# Secrets with = and spaces variations
TOKEN_NO_SPACE = "auth_token='prod_token_value_12345678'"  # no spaces around =
TOKEN_EXTRA_SPACE = "auth_token   =   'prod_token_value_12345678'"  # extra spaces

# Secret in single vs double quotes
SECRET_SINGLE = "jwt_secret = 'single_quote_secret_2024'"  # single quotes
SECRET_DOUBLE = 'jwt_secret = "double_quote_secret_2024"'  # double quotes


# ── Section 2: SQL with different quote/string patterns ──────────────

def sql_double_quotes(conn, val: str):
    """SQL with double-quoted f-string."""
    conn.execute(f'SELECT * FROM t WHERE x = "{val}"')  # sql-injection — double quotes

def sql_triple_quotes(conn, val: str):
    """SQL with triple-quoted f-string."""
    conn.execute(f"""SELECT * FROM users
        WHERE name = '{val}'
        AND active = 1""")  # sql-injection — triple quote multiline

def sql_raw_string(conn, val: str):
    """SQL with raw f-string."""
    conn.execute(rf"SELECT * FROM t WHERE path = '{val}'")  # sql-injection — raw f-string

def sql_bytes_decode(conn, val: str):
    """SQL via bytes decode."""
    query = f"SELECT * FROM t WHERE x = '{val}'"
    conn.execute(query)  # sql-injection — variable intermediary

def sql_multiline_concat(conn, table: str, field: str, value: str):
    """SQL multiline concatenation."""
    query = (
        f"SELECT * FROM {table} "
        f"WHERE {field} = '{value}' "
        f"ORDER BY id"
    )
    conn.execute(query)  # sql-injection — multiline f-string concat


# ── Section 3: Subprocess with keyword-only and unusual patterns ─────

def subprocess_kwonly_shell(cmd: str):
    """shell=True as keyword-only arg."""
    return subprocess.run(cmd.split(), shell=True)  # shell-true

def subprocess_run_kwargs(cmd: str, **kwargs):
    """Subprocess with **kwargs that could include shell=True."""
    kwargs.setdefault("shell", True)
    return subprocess.run(cmd, **kwargs)  # shell-true hidden in kwargs

def subprocess_popen_communicate(cmd: str) -> str:
    """Popen + communicate pattern."""
    p = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)  # shell-true
    stdout, _ = p.communicate()
    return stdout.decode()

def subprocess_with_timeout(cmd: str) -> str:
    """subprocess.run with shell=True and timeout."""
    return subprocess.run(
        cmd, shell=True, timeout=30, capture_output=True, text=True  # shell-true
    ).stdout

def check_output_list(cmd_parts: list) -> str:
    """check_output with list — no shell but still audit-worthy."""
    return subprocess.check_output(cmd_parts, text=True)  # subprocess-audit


# ── Section 4: One-liner patterns ────────────────────────────────────

# Semicolon-separated dangerous statements
def multi_statement(cmd: str): os.system(cmd); print("done")  # os-system

def eval_oneliner(expr: str): return eval(expr)  # eval-usage

def exec_oneliner(code: str): exec(code)  # exec-usage

# Lambda with dangerous calls (already tested but boundary check)
dangerous_eval = lambda x: eval(x)  # eval-usage
dangerous_exec = lambda x: exec(x)  # exec-usage
dangerous_system = lambda x: os.system(x)  # os-system
dangerous_sql = lambda conn, q: conn.execute(f"SELECT * FROM t WHERE x = '{q}'")  # sql-injection

# Ternary with dangerous calls
def ternary_eval(expr, safe=False): return eval(expr) if not safe else None  # eval-usage
def ternary_system(cmd, dry=False): return os.system(cmd) if not dry else 0  # os-system


# ── Section 5: Walrus operator edge cases ────────────────────────────

def walrus_eval(data: dict):
    """Walrus with eval."""
    if (expr := data.get("expr")) and (result := eval(expr)):  # eval-usage
        return result

def walrus_sql(conn, data: dict):
    """Walrus with SQL."""
    if query := data.get("query"):
        return conn.execute(f"SELECT * FROM t WHERE {query}").fetchall()  # sql-injection

def walrus_subprocess(data: dict):
    """Walrus with subprocess."""
    if cmd := data.get("command"):
        return subprocess.run(cmd, shell=True, capture_output=True)  # shell-true


# ── Section 6: Chained method calls ──────────────────────────────────

def chained_sql(conn, user: str):
    """Chained execute + fetchall."""
    return conn.execute(
        f"SELECT * FROM users WHERE name = '{user}'"  # sql-injection
    ).fetchall()

def chained_sql_fetchone(conn, user_id: str):
    """Chained execute + fetchone."""
    return conn.execute(
        f"SELECT * FROM users WHERE id = {user_id}"  # sql-injection
    ).fetchone()

def chained_subprocess(cmd: str):
    """Chained subprocess + decode."""
    return subprocess.check_output(
        cmd, shell=True  # shell-true
    ).decode("utf-8").strip()

def chained_pickle_read(path: str):
    """Chained Path.read_bytes + pickle.loads."""
    return pickle.loads(Path(path).read_bytes())  # pickle-unsafe

from pathlib import Path


# ── Section 7: Unusual import patterns ───────────────────────────────

def dynamic_import_exec():
    """__import__ + exec combo."""
    mod = __import__("os")
    mod.system("echo pwned")  # os-system via __import__

def from_import_eval():
    """Import and immediately use."""
    from builtins import eval as safe_eval  # misleading alias
    # In real code this would use the alias

def importlib_exec(module_name: str):
    """importlib for dynamic import."""
    import importlib
    mod = importlib.import_module(module_name)  # dynamic-import
    return mod


# ── Section 8: Weak hash edge cases ─────────────────────────────────

def md5_update_pattern(data: bytes) -> str:
    """MD5 via update pattern."""
    h = hashlib.md5()  # weak-hash
    h.update(data)
    return h.hexdigest()

def sha1_update_pattern(data: bytes) -> str:
    """SHA1 via update pattern."""
    h = hashlib.sha1()  # weak-hash
    h.update(data)
    return h.hexdigest()

def md5_copy(data1: bytes, data2: bytes) -> str:
    """MD5 with copy."""
    h = hashlib.md5(data1)  # weak-hash
    h2 = h.copy()
    h2.update(data2)
    return h2.hexdigest()

def hmac_md5_ref(key: bytes, msg: bytes) -> str:
    """HMAC with md5 as reference (no parens)."""
    return hmac.new(key, msg, hashlib.md5).hexdigest()  # weak-hash


# ── Section 9: Pickle edge cases ─────────────────────────────────────

def pickle_load_rb(path: str):
    """pickle.load with explicit rb mode."""
    f = open(path, "rb")  # open-without-with
    data = pickle.load(f)  # pickle-unsafe
    f.close()
    return data

def pickle_loads_decompress(data: bytes):
    """pickle.loads after decompression."""
    import zlib
    raw = zlib.decompress(data)
    return pickle.loads(raw)  # pickle-unsafe — compressed payload

def unpickler_find_class(data: bytes):
    """Unpickler with custom find_class."""
    import io
    unpickler = pickle.Unpickler(io.BytesIO(data))  # pickle-unsafe — Unpickler
    return unpickler.load()


# ── Section 10: SSL/TLS edge cases ───────────────────────────────────

def requests_session_no_verify(url: str):
    """Session with verify=False."""
    import requests
    s = requests.Session()
    s.verify = False  # ssl-no-verify on session
    return s.get(url).text

def urllib_ssl_no_verify(url: str):
    """urllib with ssl context."""
    import ssl
    import urllib.request
    ctx = ssl._create_unverified_context()  # ssl-unverified-context
    return urllib.request.urlopen(url, context=ctx).read()

def httpx_no_verify(url: str):
    """httpx with verify=False."""
    import httpx
    return httpx.get(url, verify=False)  # ssl-no-verify — httpx variant


# ── Section 11: Assert boundaries ────────────────────────────────────

def assert_auth(user): assert user.is_authenticated  # assert-statement
def assert_perm(user, perm): assert user.has_perm(perm)  # assert-statement
def assert_owner(item, user): assert item.owner_id == user.id  # assert-statement

# Assert in class
class SecureResource:
    def access(self, user):
        assert user.role in ("admin", "staff")  # assert-statement
        return self.data


# ── Section 12: Mixed realistic chain ────────────────────────────────

class ReportEngine:
    """Report engine with comprehensive vulnerability coverage."""

    ENGINE_SECRET = "report-engine-key-production-2024"  # hardcoded-secret

    def __init__(self, db_path: str = "reports.db"):
        self.conn = sqlite3.connect(db_path)

    def query_data(self, sql_where: str) -> list:
        return self.conn.execute(
            f"SELECT * FROM report_data WHERE {sql_where}"  # sql-injection
        ).fetchall()

    def transform(self, data: list, expr: str) -> list:
        return [eval(expr, {"row": row}) for row in data]  # eval-usage in comprehension

    def render(self, template_code: str, context: dict):
        exec(template_code, context)  # exec-usage

    def export_csv(self, filename: str):
        subprocess.run(
            f"sqlite3 reports.db -csv 'SELECT * FROM report_data' > {filename}",
            shell=True,  # shell-true
        )

    def cache_result(self, key: str, data: Any):
        path = f"/tmp/report_cache_{key}.pkl"  # hardcoded-tmp
        with open(path, "wb") as f:
            pickle.dump(data, f)

    def load_cached(self, key: str) -> Any:
        path = f"/tmp/report_cache_{key}.pkl"  # hardcoded-tmp
        with open(path, "rb") as f:
            return pickle.load(f)  # pickle-unsafe

    def hash_report(self, data: bytes) -> str:
        return hashlib.md5(data).hexdigest()  # weak-hash

    def verify_signature(self, payload: bytes, sig: str) -> bool:
        expected = hmac.new(
            self.ENGINE_SECRET.encode(), payload, hashlib.sha256
        ).hexdigest()
        return sig == expected  # timing attack
