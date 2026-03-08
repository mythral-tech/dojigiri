"""Fold 8: AST ceiling-breakers + real-world framework patterns.

Targets the two known regex-resistant gaps (multiline shell=True, getattr
dispatch) via AST, plus FastAPI/Starlette, asyncio, pathlib, and
subprocess env/cwd manipulation patterns.
"""

import os
import sys
import subprocess
import sqlite3
import hashlib
import asyncio
import socket
import json
import logging
import pickle
from pathlib import Path
from contextlib import asynccontextmanager


# ── Section 1: Multiline subprocess — shell=True on different line ──────
# This is the #1 regex-resistant gap. shell=True appears on a different
# line than subprocess.run(, so single-line regex can't match.

def multiline_shell_true_run(user_cmd):
    """subprocess.run with shell=True split across lines."""
    result = subprocess.run(
        user_cmd,
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def multiline_shell_true_popen(cmd):
    """Popen with shell=True on separate line."""
    proc = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
    )
    return proc.communicate()


def multiline_shell_true_call(cmd):
    """call with shell=True on separate line."""
    return subprocess.call(
        cmd,
        shell=True,
    )


def multiline_shell_true_check(cmd):
    """check_output with shell=True on separate line."""
    return subprocess.check_output(
        cmd,
        shell=True,
    )


def shell_false_safe(cmd_list):
    """subprocess.run with shell=False — should NOT be flagged as shell-true."""
    return subprocess.run(
        cmd_list,
        shell=False,
        capture_output=True,
    )


# ── Section 2: getattr-based dangerous calls ───────────────────────────
# The #2 regex-resistant gap. getattr(module, "func") evades literal match.

def getattr_eval_indirect(expr):
    """eval via getattr on builtins."""
    fn = getattr(__builtins__, "eval") if hasattr(__builtins__, "eval") else eval
    return fn(expr)


def getattr_os_system_indirect(cmd):
    """os.system via getattr."""
    runner = getattr(os, "system")
    return runner(cmd)


def getattr_subprocess_popen(cmd):
    """subprocess.Popen via getattr."""
    cls = getattr(subprocess, "Popen")
    return cls(cmd, shell=True)


def getattr_pickle_indirect(data):
    """pickle.loads via getattr."""
    loader = getattr(pickle, "loads")
    return loader(data)


def getattr_safe_example():
    """getattr on non-dangerous attribute — should NOT flag."""
    return getattr(os.path, "exists")("/tmp")


# ── Section 3: FastAPI / Starlette patterns ─────────────────────────────

def fastapi_sql_injection(user_id: str):
    """SQL injection in FastAPI endpoint handler."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = '{user_id}'")  # sql-injection
    return cursor.fetchone()


def fastapi_path_traversal(filename: str):
    """Path traversal in file download endpoint."""
    filepath = Path("/uploads") / filename  # safe? No — filename could be ../../etc/passwd
    return filepath.read_bytes()


def fastapi_ssrf(url: str):
    """SSRF in proxy endpoint."""
    import requests  # type: ignore
    resp = requests.get(url, timeout=10)  # ssrf-risk — user controls URL
    return resp.json()


def fastapi_eval_query(expression: str):
    """eval in query processing — seen in analytics dashboards."""
    result = eval(expression)  # eval-usage
    return {"result": result}


# ── Section 4: asyncio footguns ─────────────────────────────────────────

async def async_shell_command(cmd):
    """create_subprocess_shell — same as subprocess shell=True."""
    proc = await asyncio.create_subprocess_shell(
        cmd,  # injection if cmd is user-controlled
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, stderr = await proc.communicate()
    return stdout.decode()


async def async_exec_command(cmd_parts):
    """create_subprocess_exec — safer but still needs audit."""
    proc = await asyncio.create_subprocess_exec(
        *cmd_parts,
        stdout=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    return stdout.decode()


async def async_open_connection_no_tls(host, port):
    """asyncio.open_connection without TLS."""
    reader, writer = await asyncio.open_connection(host, port)  # no TLS
    return reader, writer


async def async_start_server_all_interfaces(handler, port):
    """Server listening on all interfaces."""
    server = await asyncio.start_server(handler, "0.0.0.0", port)  # bind-all-interfaces
    return server


# ── Section 5: subprocess with env/cwd manipulation ────────────────────

def subprocess_custom_env(cmd):
    """subprocess with modified environment — PATH injection."""
    env = os.environ.copy()
    env["PATH"] = "/tmp/evil:" + env.get("PATH", "")
    return subprocess.run(cmd, env=env)  # subprocess-audit with PATH poisoning


def subprocess_cwd_user(cmd, user_dir):
    """subprocess with user-controlled cwd."""
    return subprocess.run(cmd, cwd=user_dir)  # user controls working directory


def subprocess_preexec(cmd):
    """subprocess with preexec_fn — runs before exec in child."""
    return subprocess.run(
        cmd,
        preexec_fn=os.setpgrp,  # preexec_fn is dangerous in threaded programs
    )


# ── Section 6: Pathlib edge cases ──────────────────────────────────────

def pathlib_resolve_traversal(user_input):
    """Path.resolve doesn't prevent traversal if you don't check prefix."""
    base = Path("/safe/uploads")
    target = (base / user_input).resolve()
    # Missing check: if not str(target).startswith(str(base.resolve())): raise
    return target.read_text()  # path traversal


def pathlib_home_expansion(user_path):
    """Path.expanduser with user input."""
    return Path(user_path).expanduser()  # ~user expansion — info leak


def pathlib_glob_injection(pattern):
    """User-controlled glob pattern."""
    return list(Path("/").glob(pattern))  # can traverse filesystem


# ── Section 7: Weak key derivation ──────────────────────────────────────

def derive_key_md5(password, salt):
    """MD5 for key derivation — way too fast."""
    return hashlib.md5((salt + password).encode()).digest()  # weak-hash for KDF


def derive_key_sha256_no_iterations(password, salt):
    """Single SHA-256 hash — no stretching."""
    return hashlib.sha256((salt + password).encode()).digest()  # no iterations = too fast


def derive_key_pbkdf2_weak(password, salt):
    """PBKDF2 with too few iterations."""
    return hashlib.pbkdf2_hmac("sha256", password.encode(), salt.encode(), iterations=100)  # 100 is way too low


# ── Section 8: Logging with sensitive data patterns ─────────────────────

logger = logging.getLogger(__name__)


def log_full_request(request):
    """Logging full request including headers/cookies."""
    logger.info(f"Request: {request}")  # may contain auth headers, cookies


def log_user_creation(username, password, email):
    """Logging password during user creation."""
    logger.info(f"Created user {username} with password {password}")  # logging-sensitive-data


def log_api_response(response):
    """Logging full API response including tokens."""
    logger.debug(f"API response: {json.dumps(response)}")  # may contain tokens


# ── Section 9: Socket patterns ──────────────────────────────────────────

def socket_reuse_addr(port):
    """SO_REUSEADDR — can hijack port."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)  # port hijacking risk
    s.bind(("0.0.0.0", port))  # bind-all-interfaces
    return s


def socket_no_timeout(host, port):
    """Socket without timeout — can hang indefinitely."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))  # no timeout set
    return s.recv(4096)


# ── Section 10: Mixed vulnerability chains ──────────────────────────────

def chain_sqli_to_rce(user_input):
    """SQL injection result passed to os.system."""
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT command FROM jobs WHERE id = '{user_input}'")  # sql-injection
    row = cursor.fetchone()
    if row:
        os.system(row[0])  # os-system — RCE from SQL result


def chain_ssrf_to_pickle(url):
    """SSRF fetching data that gets deserialized."""
    import requests  # type: ignore
    resp = requests.get(url, timeout=30)  # ssrf-risk
    return pickle.loads(resp.content)  # pickle-unsafe — RCE from remote data


def chain_path_traversal_to_eval(user_path):
    """Path traversal reading file that gets eval'd."""
    content = Path(user_path).read_text()
    return eval(content)  # eval-usage — RCE via file content


def chain_env_to_sql(cursor):
    """Environment variable used in SQL."""
    table = os.environ.get("TABLE", "users")
    cursor.execute(f"SELECT * FROM {table}")  # sql-injection from env
