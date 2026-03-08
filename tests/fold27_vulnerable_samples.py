"""Fold 27: Maximum evasion — encoding tricks, multi-hop indirection,
string construction to hide patterns, and stdlib edge cases that
neither regex nor simple AST typically catches.

This fold intentionally pushes past what static regex/AST can do,
to map the true ceiling of the approach.
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
import base64
import codecs
from pathlib import Path
from typing import Any, Dict, List, Optional
from string import Template

logger = logging.getLogger(__name__)


# ── Section 1: String construction to hide function names ────────────

def eval_via_getattr(expr: str):
    """eval via getattr on builtins — hides 'eval' from regex."""
    fn = getattr(__builtins__, "eval") if isinstance(__builtins__, dict) else getattr(__builtins__, "eval")
    return fn(expr)


def exec_via_getattr(code: str):
    """exec via getattr."""
    fn = getattr(__builtins__, "exec")
    fn(code)


def system_via_getattr(cmd: str):
    """os.system via getattr."""
    fn = getattr(os, "system")
    return fn(cmd)


def eval_via_globals(expr: str):
    """eval from globals() dict."""
    return globals()["__builtins__"]["eval"](expr)


def subprocess_via_getattr(cmd: str):
    """subprocess.run via getattr — hides shell=True."""
    run = getattr(subprocess, "run")
    return run(cmd, shell=True)  # shell-true — but getattr hides the call


# ── Section 2: Base64/rot13 encoded payloads ─────────────────────────

def exec_base64(payload: str):
    """Decode and exec base64 payload."""
    code = base64.b64decode(payload).decode()
    exec(code)  # exec-usage — decoded payload


def exec_rot13(payload: str):
    """Decode and exec rot13 payload."""
    code = codecs.decode(payload, "rot_13")
    exec(code)  # exec-usage — decoded payload


def eval_base64(payload: str):
    """Decode and eval base64 payload."""
    expr = base64.b64decode(payload).decode()
    return eval(expr)  # eval-usage — decoded payload


def system_from_base64(payload: str):
    """Decode and run base64 command."""
    cmd = base64.b64decode(payload).decode()
    os.system(cmd)  # os-system — decoded payload


# ── Section 3: Template-based injection ──────────────────────────────

def template_eval(template_str: str, context: dict):
    """string.Template with eval — SSTI variant."""
    tmpl = Template(template_str)
    result = tmpl.substitute(context)
    return eval(result)  # eval-usage — template output evaluated


def template_sql(conn, template_str: str, context: dict):
    """string.Template for SQL — injection."""
    tmpl = Template(template_str)
    query = tmpl.substitute(context)
    return conn.execute(query).fetchall()  # sql via Template — no parameterization


def template_command(template_str: str, context: dict):
    """string.Template for commands — injection."""
    tmpl = Template(template_str)
    cmd = tmpl.substitute(context)
    return os.system(cmd)  # os-system — template-built command


def fstring_eval(data: dict) -> Any:
    """f-string in eval — nested injection."""
    key = data.get("key", "1+1")
    return eval(f"{key}")  # eval-usage with f-string


# ── Section 4: os module — lesser-known dangerous functions ─────────

def os_startfile(path: str):
    """os.startfile — opens file with default handler (Windows)."""
    os.startfile(path)  # arbitrary file open — could launch executables


def os_putenv_injection(key: str, value: str):
    """os.putenv — modify environment variables."""
    os.putenv(key, value)  # env injection — LD_PRELOAD, PATH, etc.


def os_environ_update(env_vars: dict):
    """os.environ update — bulk env injection."""
    os.environ.update(env_vars)  # env injection — all vars at once


def os_kill_signal(pid: int, sig: int):
    """os.kill — send signal to arbitrary process."""
    os.kill(pid, sig)  # could kill critical processes


def os_link_arbitrary(src: str, dst: str):
    """os.link — create hard link."""
    os.link(src, dst)  # could link sensitive files to accessible location


def os_symlink_arbitrary(src: str, dst: str):
    """os.symlink — create symlink."""
    os.symlink(src, dst)  # symlink attack — point to sensitive files


# ── Section 5: subprocess — every variant ────────────────────────────

def subprocess_popen_shell(cmd: str):
    """Popen with shell=True."""
    return subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE)  # shell-true


def subprocess_call_shell(cmd: str):
    """call with shell=True."""
    return subprocess.call(cmd, shell=True)  # shell-true


def subprocess_check_call_shell(cmd: str):
    """check_call with shell=True."""
    return subprocess.check_call(cmd, shell=True)  # shell-true


def subprocess_check_output_shell(cmd: str) -> bytes:
    """check_output with shell=True."""
    return subprocess.check_output(cmd, shell=True)  # shell-true


def subprocess_getoutput(cmd: str) -> str:
    """getoutput — always uses shell."""
    return subprocess.getoutput(cmd)  # shell execution — no shell= needed


def subprocess_getstatusoutput(cmd: str):
    """getstatusoutput — always uses shell."""
    return subprocess.getstatusoutput(cmd)  # shell execution


# ── Section 6: SQL injection — every string building method ─────────

def sql_fstring(conn, user: str):
    """SQL via f-string."""
    conn.execute(f"SELECT * FROM users WHERE name = '{user}'")  # sql-injection


def sql_percent(conn, user: str):
    """SQL via % format."""
    conn.execute("SELECT * FROM users WHERE name = '%s'" % user)  # sql-injection


def sql_concat(conn, user: str):
    """SQL via + concatenation."""
    conn.execute("SELECT * FROM users WHERE name = '" + user + "'")  # sql-injection


def sql_format(conn, user: str):
    """SQL via .format()."""
    conn.execute("SELECT * FROM users WHERE name = '{}'".format(user))  # sql-injection


def sql_join(conn, parts: list):
    """SQL via join."""
    query = " ".join(parts)
    conn.execute(query)  # sql via join — can't detect statically


def sql_template(conn, user: str):
    """SQL via string.Template."""
    tmpl = Template("SELECT * FROM users WHERE name = '$user'")
    conn.execute(tmpl.substitute(user=user))  # sql via Template


# ── Section 7: Pickle — every entry point ────────────────────────────

def pickle_loads_bytes(data: bytes):
    """pickle.loads from bytes."""
    return pickle.loads(data)  # pickle-unsafe


def pickle_load_file(path: str):
    """pickle.load from file."""
    with open(path, "rb") as f:
        return pickle.load(f)  # pickle-unsafe


def pickle_unpickler(data: bytes):
    """pickle.Unpickler — same risk."""
    return pickle.Unpickler(data).load()  # pickle-unsafe


def shelve_open(path: str):
    """shelve uses pickle internally."""
    import shelve
    return dict(shelve.open(path))  # unsafe-deserialization


# ── Section 8: hashlib — comprehensive weak patterns ─────────────────

def hash_md5(data: bytes) -> str:
    return hashlib.md5(data).hexdigest()  # weak-hash


def hash_sha1(data: bytes) -> str:
    return hashlib.sha1(data).hexdigest()  # weak-hash


def hash_md5_new(data: bytes) -> str:
    return hashlib.new("md5", data).hexdigest()  # weak-hash via new()


def hash_sha1_new(data: bytes) -> str:
    return hashlib.new("sha1", data).hexdigest()  # weak-hash via new()


def hmac_md5(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.md5).hexdigest()  # weak-hash in HMAC


def hmac_sha1(key: bytes, msg: bytes) -> str:
    return hmac.new(key, msg, hashlib.sha1).hexdigest()  # weak-hash in HMAC


def pbkdf2_low_iterations(password: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100)  # low iterations


# ── Section 9: SSL/TLS misconfig — comprehensive ─────────────────────

def requests_no_verify(url: str):
    """requests with verify=False."""
    import requests
    return requests.get(url, verify=False)  # ssl-no-verify


def requests_no_timeout(url: str):
    """requests without timeout."""
    import requests
    return requests.get(url)  # requests-no-timeout


def ssl_unverified_context():
    """Create unverified SSL context."""
    import ssl
    return ssl._create_unverified_context()  # ssl-unverified-context


def ssl_cert_none():
    """SSL with CERT_NONE."""
    import ssl
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # ssl-cert-none
    return ctx


# ── Section 10: Hardcoded secrets — comprehensive patterns ──────────

# Variable assignment patterns
API_KEY = "ak_live_prod_1a2b3c4d5e6f7g8h"  # hardcoded-secret
SECRET_KEY = "sk_production_9z8y7x6w5v4u3t2s"  # hardcoded-secret
AUTH_TOKEN = "at_bearer_production_abcdef123456"  # hardcoded-secret
JWT_SECRET = "jwt_signing_key_production_2024_xyzabc"  # hardcoded-secret
ENCRYPTION_KEY = "enc_key_aes256_production_materials"  # hardcoded-secret

# Dict patterns
config = {
    "api_key": "dict_api_key_production_12345678",  # hardcoded-secret in dict
    "secret_key": "dict_secret_key_prod_abcdefgh",  # hardcoded-secret in dict
    "password": "DictPasswordProd2024!Secure",  # hardcoded-secret in dict
    "database_password": "DictDbPassword2024!",  # hardcoded-secret in dict
}

# Connection strings
DB_URL = "postgresql://user:DbPassword2024@prod.db:5432/app"  # db-connection-string
REDIS_URL = "redis://:RedisPass2024@redis.prod:6379"  # db-connection-string

# Function defaults
def connect(host: str, password: str = "DefaultProdPassword2024!"):  # hardcoded-password-default
    pass

def auth(token: str = "default_auth_token_production"):  # hardcoded-password-default
    pass


# ── Section 11: Assert for security ──────────────────────────────────

def check_admin(user: dict):
    assert user["role"] == "admin"  # assert-statement
    return True

def check_auth(request: dict):
    assert "auth_token" in request.headers  # assert-statement
    return True

def check_balance(amount: float, balance: float):
    assert amount <= balance  # assert-statement
    return True


# ── Section 12: Mixed realistic chain ────────────────────────────────

class DataProcessor:
    """Data processor combining every vulnerability class."""

    PROCESSOR_KEY = "data-processor-secret-key-2024"  # hardcoded-secret

    def __init__(self, db_path: str = "processor.db"):
        self.conn = sqlite3.connect(db_path)

    def query(self, table: str, field: str, value: str):
        return self.conn.execute(
            f"SELECT * FROM {table} WHERE {field} = '{value}'"  # sql-injection
        ).fetchall()

    def transform(self, expression: str, data: Any) -> Any:
        return eval(expression, {"data": data})  # eval-usage

    def execute_pipeline(self, pipeline_code: str):
        exec(pipeline_code, {"os": os, "subprocess": subprocess})  # exec-usage

    def shell(self, cmd: str) -> str:
        result = subprocess.run(
            cmd, shell=True, capture_output=True, text=True  # shell-true
        )
        return result.stdout

    def deserialize(self, data: bytes) -> Any:
        return pickle.loads(data)  # pickle-unsafe

    def fetch(self, url: str) -> bytes:
        import urllib.request
        return urllib.request.urlopen(url).read()  # ssrf-risk

    def hash(self, data: bytes) -> str:
        return hashlib.md5(data).hexdigest()  # weak-hash

    def export(self, path: str):
        subprocess.run(
            f"cp processor.db {path}",
            shell=True,  # shell-true
        )
