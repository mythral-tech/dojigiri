"""Fold 6: Deep edge cases — ORM injection, async resource leaks, multiline
string construction, indirect eval/exec, inheritance-based vulns, regex
injection, logging format vuln, and Python-specific footguns.

Attack surfaces NOT covered in folds 2-5.
"""

import os
import re
import ast
import sys
import json
import copy
import logging
import sqlite3
import hashlib
import asyncio
import secrets
import subprocess
import http.client
import urllib.request
from collections import defaultdict
from functools import lru_cache


# ── Section 1: ORM / query builder injection ───────────────────────────

def django_raw_sql(user_input):
    """Django raw SQL — ORM doesn't protect raw()."""
    from django.db import connection  # type: ignore
    cursor = connection.cursor()
    cursor.execute(f"SELECT * FROM auth_user WHERE username = '{user_input}'")  # sql-injection
    return cursor.fetchall()


def django_extra_where(field_val):
    """Django .extra(where=...) — deprecated and injectable."""
    # User.objects.extra(where=[f"username = '{field_val}'"])  # sql-injection pattern
    query = f"username = '{field_val}'"  # built for .extra(where=[...])
    return query


def sqlalchemy_text_injection(user_id):
    """SQLAlchemy text() with f-string."""
    from sqlalchemy import text  # type: ignore
    stmt = text(f"SELECT * FROM users WHERE id = {user_id}")  # sql-injection
    return stmt


def sqlite_executemany_injection(data_list):
    """executemany with format string."""
    conn = sqlite3.connect(":memory:")
    # Building query with untrusted table name
    table = data_list[0].get("table", "users")
    conn.executemany(f"INSERT INTO {table} VALUES (?, ?)", data_list)  # sql-injection in table name


# ── Section 2: Indirect eval/exec variants ──────────────────────────────

def compile_and_exec(code_str):
    """compile() + exec() — two-step eval."""
    compiled = compile(code_str, "<string>", "exec")  # compile arbitrary code
    exec(compiled)  # exec-usage


def ast_literal_eval_bypass(user_input):
    """ast.literal_eval is safe, but devs sometimes use ast.parse + compile instead."""
    tree = ast.parse(user_input, mode="eval")
    code = compile(tree, "<input>", "eval")  # compiling user AST
    return eval(code)  # eval-usage — ast.parse doesn't restrict to literals


def type_call_exec(class_name, bases_str, body_str):
    """type() three-arg form creates classes dynamically — code injection."""
    # type(name, bases, dict) with exec'd body
    namespace = {}
    exec(body_str, namespace)  # exec-usage — arbitrary class body
    return type(class_name, (), namespace)


def globals_setitem(key, value):
    """Writing to globals() — arbitrary attribute injection."""
    globals()[key] = value  # can overwrite any global, including builtins


def builtins_override():
    """Overriding builtins — catastrophic if user-controlled."""
    import builtins
    builtins.open = lambda *a, **k: None  # overriding built-in open!


# ── Section 3: Async resource leak patterns ─────────────────────────────

async def async_file_leak(path):
    """Async function opening file without context manager."""
    f = open(path, "r")  # open-without-with in async context
    data = f.read()
    # If await below raises, file is never closed
    await asyncio.sleep(0.1)
    f.close()
    return data


async def async_connection_leak():
    """DB connection opened in async without cleanup."""
    conn = sqlite3.connect("async_app.db")
    cursor = conn.cursor()
    cursor.execute("SELECT 1")
    await asyncio.sleep(0)
    # If task is cancelled here, conn never closes
    conn.close()


async def async_subprocess_leak(cmd):
    """Async subprocess without proper cleanup."""
    proc = await asyncio.create_subprocess_shell(
        cmd,  # user input in shell command
        stdout=asyncio.subprocess.PIPE,
    )
    # If we don't await communicate(), process zombies
    return proc


# ── Section 4: Multiline string construction ───────────────────────────

def multiline_sql(username, role):
    """SQL injection across multiple lines."""
    query = (
        "SELECT u.*, r.name "
        "FROM users u "
        "JOIN roles r ON u.role_id = r.id "
        f"WHERE u.username = '{username}' "  # sql-injection — line 4 of multiline
        f"AND r.name = '{role}'"  # sql-injection — line 5
    )
    return sqlite3.connect(":memory:").execute(query)


def multiline_command(host, port):
    """Command injection across multiple lines."""
    cmd = (
        f"nmap -sV "
        f"-p {port} "  # injection point
        f"{host}"  # injection point
    )
    os.system(cmd)  # os-system with constructed command


def multiline_html(user_name, user_bio):
    """XSS via multiline HTML construction."""
    html = f"""
    <div class="profile">
        <h1>{user_name}</h1>
        <p>{user_bio}</p>
    </div>
    """
    return html  # reflected XSS if rendered without escaping


# ── Section 5: Logging vulnerabilities ──────────────────────────────────

logger = logging.getLogger(__name__)


def log_format_string_vuln(user_input):
    """User input as format string — log injection / info leak."""
    logger.info(user_input)  # if user_input contains %(secret)s, leaks logger context


def log_exception_password(password):
    """Logging exception with password in scope."""
    try:
        authenticate(password)
    except Exception:
        logger.exception("Authentication failed")  # logs full traceback including local vars


def log_with_percent_format(user_data):
    """%-style formatting with user data — can crash logger."""
    logger.info("Processing: %s %s" % (user_data, user_data))  # old-style format


# ── Section 6: Regex injection ──────────────────────────────────────────

def regex_from_user(pattern, text):
    """User-controlled regex — ReDoS + info leak."""
    return re.search(pattern, text)  # ReDoS if pattern is (a+)+$


def regex_compile_user(pattern):
    """Compiling user regex — persistent ReDoS."""
    compiled = re.compile(pattern)  # same issue, cached
    return compiled


def regex_sub_user(pattern, replacement, text):
    """re.sub with user pattern — can cause DoS."""
    return re.sub(pattern, replacement, text)  # ReDoS


# ── Section 7: Inheritance / metaclass vulnerabilities ──────────────────

class PermissiveBase:
    """Base class that trusts all input."""
    def execute(self, query):
        conn = sqlite3.connect(":memory:")
        return conn.execute(query)  # sql-injection inherited by subclasses


class AdminPanel(PermissiveBase):
    """Inherits unsafe execute method."""
    def search_users(self, search_term):
        return self.execute(f"SELECT * FROM users WHERE name LIKE '%{search_term}%'")  # sql-injection


class DynamicDispatch:
    """Unsafe dynamic method dispatch."""
    def handle(self, action, *args):
        method = getattr(self, f"do_{action}", None)  # user controls method name
        if method:
            return method(*args)

    def do_delete(self, path):
        os.remove(path)  # path traversal via dynamic dispatch


# ── Section 8: Copy/deepcopy with side effects ─────────────────────────

class ResourceHolder:
    """Class where copy creates duplicate resource handles."""
    def __init__(self, path):
        self.file = open(path, "r")  # open-without-with
        self.conn = sqlite3.connect("app.db")

    def __copy__(self):
        """Shallow copy shares file handle — double-close bug."""
        new = ResourceHolder.__new__(ResourceHolder)
        new.file = self.file  # shared file handle!
        new.conn = self.conn  # shared connection!
        return new


# ── Section 9: Insecure defaults and config ─────────────────────────────

DEFAULT_CONFIG = {
    "debug": True,
    "allow_registration": True,
    "max_upload_size": 999999999,  # ~1GB upload — DoS
    "session_timeout": 0,  # never expires
    "cors_origin": "*",  # CORS wildcard
    "rate_limit": None,  # no rate limit
}


def create_app(config=None):
    """App factory with insecure defaults."""
    cfg = DEFAULT_CONFIG.copy()
    if config:
        cfg.update(config)
    return cfg


# ── Section 10: HTTP client patterns ───────────────────────────────────

def http_client_raw(host, path):
    """Raw http.client without TLS."""
    conn = http.client.HTTPConnection(host)  # unencrypted HTTP
    conn.request("GET", path)
    return conn.getresponse().read()


def http_client_with_header_injection(host, user_header):
    """Header injection via user input."""
    conn = http.client.HTTPSConnection(host)
    conn.request("GET", "/api", headers={"X-Custom": user_header})  # header injection if \r\n in value
    return conn.getresponse().read()


def urllib_with_redirect(url):
    """urllib follows redirects by default — SSRF amplification."""
    return urllib.request.urlopen(url)  # url-scheme-audit — follows 3xx redirects


# ── Section 11: Pickle via alternative interfaces ──────────────────────

def pickle_via_copy(obj):
    """copy.deepcopy uses pickle protocol — triggers __reduce__."""
    return copy.deepcopy(obj)  # if obj is from untrusted source, RCE via __reduce__


def pickle_via_multiprocessing(func, args):
    """multiprocessing pickles arguments — injection point."""
    from multiprocessing import Process
    p = Process(target=func, args=args)  # args are pickled for IPC
    p.start()
    return p


# ── Section 12: Integer parsing edge cases ──────────────────────────────

def parse_port(raw_port):
    """int() with base=0 accepts 0x, 0o, 0b prefixes."""
    return int(raw_port, 0)  # "0x1234" parses as 4660 — unexpected behavior


def parse_bool_string(value):
    """Common bug: bool('False') is True in Python."""
    return bool(value)  # bool('False') == True, bool('0') == True


# ── Section 13: File descriptor leaks ───────────────────────────────────

def subprocess_fd_leak():
    """Popen without closing stdin/stdout — FD leak."""
    procs = []
    for i in range(100):
        p = subprocess.Popen(["echo", str(i)], stdout=subprocess.PIPE)
        procs.append(p)
    # Never call p.communicate() or close stdout — FD leak
    return [p.stdout.read() for p in procs]  # resource-leak


def socket_fd_leak(host, port):
    """Socket created but not closed on error path."""
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))  # if this raises, socket FD leaks
    data = s.recv(4096)
    s.close()  # not reached on connect failure
    return data


# ── Section 14: Mutable class attributes ────────────────────────────────

class SharedState:
    """Mutable class-level default — shared across all instances."""
    items = []  # shared across all instances — classic Python bug
    config = {}  # same issue

    def add_item(self, item):
        self.items.append(item)  # modifies class-level list


class Counter:
    """Mutable default in __init__ doesn't help here."""
    _instances = defaultdict(int)  # class-level mutable — shared

    def __init__(self, name):
        Counter._instances[name] += 1


# ── Section 15: lru_cache with mutable args ─────────────────────────────

@lru_cache(maxsize=128)
def cached_query(query):
    """LRU cache on a function that has side effects (DB query)."""
    conn = sqlite3.connect("app.db")
    return conn.execute(query).fetchall()  # caches DB results — stale data


@lru_cache(maxsize=None)
def cached_user_lookup(user_id):
    """Unbounded cache — memory leak if user_id space is large."""
    import requests  # type: ignore
    return requests.get(f"http://api.internal/users/{user_id}").json()  # ssrf + insecure-http + unbounded cache


# ── Section 16: Secrets that look like non-secrets ──────────────────────

SALT = "fixed_salt_never_changes"  # hardcoded salt defeats the purpose
PEPPER = "global_pepper_value_2024"
NONCE = "static_nonce_reused_everywhere"  # nonce must be unique per use


def hash_password(password):
    """Using fixed salt — rainbow table vulnerable."""
    return hashlib.sha256((SALT + password).encode()).hexdigest()


def encrypt_with_nonce(data, key):
    """Reusing nonce — catastrophic for stream ciphers."""
    return {"nonce": NONCE, "data": data}  # reused nonce = key recovery


# ── Section 17: Error message information disclosure ────────────────────

def verbose_error_handler(request):
    """Returning internal error details to user."""
    try:
        process_request(request)
    except Exception as e:
        return {"error": str(e), "traceback": __import__("traceback").format_exc()}  # info disclosure


def database_error_leak(query):
    """Returning raw DB error to client."""
    conn = sqlite3.connect("app.db")
    try:
        return conn.execute(query).fetchall()
    except sqlite3.Error as e:
        return {"error": f"Database error: {e}", "query": query}  # leaks query + DB error


# ── Section 18: Unsafe tempfile patterns ────────────────────────────────

def predictable_filename(user_id):
    """Predictable temp filename — race condition."""
    path = f"/tmp/upload_{user_id}.dat"  # hardcoded-tmp + predictable name
    with open(path, "wb") as f:
        f.write(b"data")
    return path


def temp_no_cleanup():
    """Temp file without cleanup — disk exhaustion."""
    import tempfile
    files = []
    for i in range(1000):
        f = tempfile.NamedTemporaryFile(delete=False)  # never deleted
        f.write(b"x" * 1024 * 1024)
        files.append(f.name)
    return files  # 1GB of temp files — no cleanup


# ── Section 19: subprocess.PIPE without communication ──────────────────

def pipe_deadlock(cmd):
    """subprocess with PIPE on both stdout and stderr — deadlock risk."""
    proc = subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    # Reading one at a time can deadlock if buffer fills on the other
    stdout = proc.stdout.read()  # blocks if stderr buffer fills
    stderr = proc.stderr.read()
    return stdout, stderr


# ── Section 20: hashlib with timing-unsafe comparison ──────────────────

def verify_api_key(provided_key, stored_hash):
    """Timing-unsafe API key verification."""
    computed = hashlib.sha256(provided_key.encode()).hexdigest()
    return computed == stored_hash  # timing attack — use hmac.compare_digest


def verify_webhook_signature(payload, signature, secret):
    """Webhook verification with string comparison."""
    import hmac as hmac_mod
    expected = hmac_mod.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return signature == expected  # timing attack
