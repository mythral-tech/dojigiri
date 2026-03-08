"""Fold 16: Stdlib dark corners and patterns neither Doji nor bandit catch.

Probes: http.client request smuggling, mmap shared memory, linecache/tokenize
file reads, cProfile output injection, catastrophic regex in user code,
hardcoded IPv6, random.seed predictability, subprocess with startupinfo,
yaml.safe_load pitfalls, and creative multiline evasion of existing rules.
"""

import os
import re
import gc
import sys
import dis
import json
import mmap
import random
import socket
import pickle
import sqlite3
import hashlib
import logging
import secrets
import linecache
import tokenize
import http.client
import subprocess
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any
from io import BytesIO

logger = logging.getLogger(__name__)


# ── Section 1: http.client — cleartext + header injection ───────────

def http_get_cleartext(host: str, path: str) -> str:
    """HTTP GET over cleartext — credentials visible on wire."""
    conn = http.client.HTTPConnection(host)  # http-connection-cleartext
    conn.request("GET", path)
    resp = conn.getresponse()
    return resp.read().decode()


def http_header_injection(host: str, path: str, user_header: str):
    """HTTP request with user-controlled header — CRLF injection."""
    conn = http.client.HTTPConnection(host)  # http-connection-cleartext
    # User-controlled header value can inject additional headers via \r\n
    conn.request("GET", path, headers={"X-Custom": user_header})
    return conn.getresponse().read()


def http_post_with_creds(host: str, path: str, username: str, password: str):
    """HTTP POST with credentials over cleartext."""
    conn = http.client.HTTPConnection(host)  # http-connection-cleartext
    import base64
    auth = base64.b64encode(f"{username}:{password}".encode()).decode()
    conn.request("POST", path, headers={"Authorization": f"Basic {auth}"})
    return conn.getresponse().read()


# ── Section 2: mmap shared memory ────────────────────────────────────

def mmap_shared_read(filepath: str) -> bytes:
    """Memory-map file for reading — exposes file content in process memory."""
    with open(filepath, "rb") as f:
        mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
        data = mm.read()
        mm.close()
    return data


def mmap_shared_write(filepath: str, data: bytes):
    """Memory-map file for writing — can corrupt shared files."""
    with open(filepath, "r+b") as f:
        mm = mmap.mmap(f.fileno(), 0)
        mm.write(data)  # overwrites file content at current position
        mm.close()


def mmap_anonymous(size: int) -> mmap.mmap:
    """Anonymous mmap — shared memory between processes."""
    return mmap.mmap(-1, size)  # anonymous shared memory


# ── Section 3: linecache / tokenize — file read via stdlib ───────────

def read_file_via_linecache(filepath: str) -> list:
    """Read arbitrary file via linecache — bypasses typical file read detection."""
    lines = linecache.getlines(filepath)  # reads arbitrary file
    return lines


def read_file_via_tokenize(filepath: str):
    """Read and parse arbitrary Python file via tokenize."""
    with open(filepath, "rb") as f:
        tokens = list(tokenize.tokenize(f.readline))
    return tokens


def read_source_via_linecache(module_name: str) -> str:
    """Read module source via linecache — info disclosure."""
    import importlib
    mod = importlib.import_module(module_name)  # dynamic-import
    filepath = mod.__file__
    return "".join(linecache.getlines(filepath))


# ── Section 4: dis — bytecode inspection info leak ──────────────────

def disassemble_function(func):
    """Disassemble function bytecode — reveals implementation details."""
    output = BytesIO()
    dis.dis(func, file=output)
    return output.getvalue().decode()


def get_code_constants(func) -> tuple:
    """Extract constants from function code — can reveal hardcoded secrets."""
    return func.__code__.co_consts  # reveals all string literals in function


def get_code_names(func) -> tuple:
    """Extract names from function code object."""
    return func.__code__.co_names  # reveals attribute access patterns


# ── Section 5: random.seed predictability ────────────────────────────

def predictable_seed_time():
    """Seed random with time — predictable."""
    import time
    random.seed(int(time.time()))  # weak-random — time-based seed is guessable


def predictable_seed_pid():
    """Seed random with PID — very predictable."""
    random.seed(os.getpid())  # weak-random — PID is small and guessable


def generate_token_weak(length: int = 32) -> str:
    """Generate 'token' using random module — not cryptographic."""
    chars = "abcdefghijklmnopqrstuvwxyz0123456789"
    return "".join(random.choice(chars) for _ in range(length))  # weak-random for token


def generate_otp_weak() -> str:
    """Generate OTP using random — predictable."""
    return str(random.randint(100000, 999999))  # weak-random for OTP


# ── Section 6: Catastrophic regex in user code ──────────────────────

def validate_email_bad(email: str) -> bool:
    """Email validation with catastrophic backtracking regex."""
    # This regex is vulnerable to ReDoS with inputs like "a" * 50 + "!"
    pattern = r"^([a-zA-Z0-9_.+-]+)+@([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


def validate_url_bad(url: str) -> bool:
    """URL validation with nested quantifiers — ReDoS."""
    pattern = r"^(https?://)?([a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(/.*)*$"
    return bool(re.match(pattern, url))


def parse_log_bad(line: str) -> dict:
    """Log parsing with backtracking regex."""
    pattern = r"(\w+\s*=\s*\w+\s*;?\s*)+"
    match = re.match(pattern, line)
    return {"parsed": match.group(0)} if match else {}


# ── Section 7: gc / tracemalloc info leaks ──────────────────────────

def dump_gc_objects():
    """Dump all objects tracked by GC — massive info disclosure."""
    all_objects = gc.get_objects()
    # This reveals every object in memory, including passwords, keys, tokens
    return [repr(obj) for obj in all_objects[:1000]]


def dump_gc_referrers(target):
    """Find what references a target object — info disclosure."""
    return gc.get_referrers(target)


# ── Section 8: Subprocess edge cases ─────────────────────────────────

def subprocess_startupinfo_hidden(cmd: str):
    """Subprocess with hidden window — suspicious for malware."""
    startupinfo = subprocess.STARTUPINFO()
    startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
    startupinfo.wShowWindow = 0  # SW_HIDE
    return subprocess.run(
        cmd,
        shell=True,  # shell-true
        startupinfo=startupinfo,
        capture_output=True,
    )


def subprocess_devnull_stderr(cmd: str):
    """Subprocess hiding errors in /dev/null."""
    return subprocess.run(
        cmd,
        shell=True,  # shell-true
        stderr=subprocess.DEVNULL,  # hiding errors
        capture_output=False,
    )


def subprocess_with_input(cmd: str, stdin_data: str):
    """Subprocess with piped input."""
    proc = subprocess.Popen(
        cmd,
        shell=True,  # shell-true
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    stdout, _ = proc.communicate(input=stdin_data.encode())
    return stdout.decode()


# ── Section 9: XML parsing patterns ──────────────────────────────────

def parse_xml_string(xml_data: str):
    """Parse XML from string — XXE risk."""
    root = ET.fromstring(xml_data)  # xxe-risk
    return {child.tag: child.text for child in root}


def parse_xml_file(filepath: str):
    """Parse XML from file — XXE risk."""
    tree = ET.parse(filepath)  # xxe-risk
    return tree.getroot()


def iterparse_xml(filepath: str):
    """Iterative XML parsing — same XXE risk."""
    events = []
    for event, elem in ET.iterparse(filepath, events=["start", "end"]):  # xxe-risk
        events.append((event, elem.tag))
    return events


# ── Section 10: Pickle via alternative patterns ──────────────────────

def unpickle_from_bytesio(data: bytes):
    """Pickle from BytesIO — less obvious pattern."""
    buf = BytesIO(data)
    return pickle.load(buf)  # pickle-unsafe


def pickle_via_unpickler(data: bytes):
    """Pickle via Unpickler class."""
    unpickler = pickle.Unpickler(BytesIO(data))
    return unpickler.load()  # still pickle-unsafe but different pattern


def persistent_load_override(data: bytes):
    """Custom Unpickler with persistent_load — still dangerous."""
    class CustomUnpickler(pickle.Unpickler):
        def persistent_load(self, pid):
            return pid  # custom handler — still runs pickle machinery

    return CustomUnpickler(BytesIO(data)).load()


# ── Section 11: SQL injection — boundary testing ────────────────────

def sql_with_backticks(conn, table: str, column: str):
    """SQL with backticks (MySQL style) — still injectable."""
    conn.execute(f"SELECT `{column}` FROM `{table}`")  # sql-injection


def sql_with_brackets(conn, table: str, column: str):
    """SQL with brackets (SQL Server style)."""
    conn.execute(f"SELECT [{column}] FROM [{table}]")  # sql-injection


def sql_multiline_heredoc(conn, user_id: str):
    """SQL in multiline string — tests f-string AST detection."""
    query = f"""
        SELECT u.name,
               u.email,
               COUNT(o.id) as order_count
        FROM users u
        LEFT JOIN orders o ON u.id = o.user_id
        WHERE u.id = {user_id}
        GROUP BY u.name, u.email
    """
    return conn.execute(query).fetchall()


# ── Section 12: Hardcoded IPv6 and unusual network patterns ──────────

# IPv6 addresses — not caught by IPv4 regex
INTERNAL_SERVICE = "[::1]:8080"  # loopback
MONITORING_HOST = "[2001:db8::1]:9090"  # documentation prefix but still hardcoded
API_ENDPOINT = "http://[fd12:3456:789a::1]:8080/api"  # private IPv6

# Mixed pattern
BACKUP_SERVER = "192.168.1.100"  # hardcoded-ip — internal IP
FAILOVER_HOST = "10.0.0.50"  # hardcoded-ip — private IP


# ── Section 13: Eval/exec with string methods ───────────────────────

def eval_strip(expr: str):
    """eval after strip — still dangerous."""
    return eval(expr.strip())  # eval-usage


def eval_lower(expr: str):
    """eval after lower — still dangerous."""
    return eval(expr.lower())  # eval-usage


def exec_decode(encoded: bytes):
    """exec of decoded bytes."""
    exec(encoded.decode("utf-8"))  # exec-usage


def exec_format(template: str, **kwargs):
    """exec of formatted string — double injection."""
    code = template.format(**kwargs)
    exec(code)  # exec-usage


# ── Section 14: Hashlib patterns — expanded ──────────────────────────

def md5_for_password(password: str) -> str:
    """MD5 for password hashing — absolutely wrong."""
    return hashlib.md5(password.encode()).hexdigest()  # weak-hash


def sha1_for_signature(data: bytes, key: bytes) -> str:
    """SHA1 for HMAC — weak."""
    import hmac
    return hmac.new(key, data, hashlib.sha1).hexdigest()  # weak-hash in HMAC


def md5_for_session_id(user_id: int) -> str:
    """MD5 for session ID generation."""
    return hashlib.md5(f"session:{user_id}:{random.random()}".encode()).hexdigest()  # weak-hash + weak-random


# ── Section 15: Mixed chains — deeper ────────────────────────────────

def chain_dns_to_connect(hostname: str, port: int):
    """DNS resolution → raw connection — SSRF via hostname."""
    addrs = socket.getaddrinfo(hostname, port)
    addr = addrs[0][4]
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(addr)
    return s


def chain_file_to_pickle(filepath: str):
    """Read file → pickle → RCE."""
    with open(filepath, "rb") as f:
        return pickle.load(f)  # pickle-unsafe


def chain_env_to_eval():
    """Env var → eval → RCE."""
    expr = os.environ.get("CALC_EXPR", "0")
    return eval(expr)  # eval-usage


def chain_sql_to_system(conn, job_id: str):
    """SQL → os.system → RCE."""
    row = conn.execute(
        f"SELECT command FROM jobs WHERE id = '{job_id}'"  # sql-injection
    ).fetchone()
    if row:
        os.system(row[0])  # os-system from DB result
