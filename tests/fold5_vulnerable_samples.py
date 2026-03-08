"""Fold 5: Exotic patterns — decorators hiding vulns, metaclass injection,
context manager misuse, generator leaks, protocol handlers, dynamic getattr,
framework anti-patterns, and encoding/serialization edge cases.

Each section targets attack surfaces NOT covered in folds 2-4.
"""

import os
import sys
import json
import base64
import struct
import ctypes
import signal
import mmap
import io
import functools
import contextlib
import importlib
import zipfile
import tarfile
import shutil
import webbrowser
import ftplib
import smtplib
import telnetlib  # type: ignore
import xmlrpc.client
from urllib.parse import urlparse, urljoin
from http.server import BaseHTTPRequestHandler


# ── Section 1: Decorator-masked vulnerabilities ─────────────────────────

def cache_result(func):
    """Decorator that hides what the inner function does."""
    _cache = {}
    @functools.wraps(func)
    def wrapper(*args):
        if args not in _cache:
            _cache[args] = func(*args)
        return _cache[args]
    return wrapper


@cache_result
def get_user_data(user_id):
    """SQL injection hidden behind a decorator."""
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # sql-injection
    return cursor.fetchone()


@cache_result
def fetch_config(key):
    """eval hidden behind decorator."""
    raw = os.environ.get(key, "None")
    return eval(raw)  # eval-usage


# ── Section 2: Dynamic attribute/module access ──────────────────────────

def dynamic_import_exec(module_name, func_name, *args):
    """importlib to load and call arbitrary code."""
    mod = importlib.import_module(module_name)  # arbitrary module load
    func = getattr(mod, func_name)
    return func(*args)


def getattr_chain(obj, attr_path):
    """Dynamic attribute traversal — could access anything."""
    for attr in attr_path.split("."):
        obj = getattr(obj, attr)  # unrestricted attribute access
    return obj


def dynamic_class_instantiation(class_name, *args):
    """Instantiate class by name from globals — code injection vector."""
    cls = globals().get(class_name)
    if cls:
        return cls(*args)


# ── Section 3: Archive/zip extraction vulnerabilities ───────────────────

def extract_zip_unsafe(zip_path, dest):
    """Zip extraction without path validation — zip slip attack."""
    with zipfile.ZipFile(zip_path) as zf:
        zf.extractall(dest)  # zip-slip: malicious paths like ../../etc/passwd


def extract_tar_unsafe(tar_path, dest):
    """Tar extraction without filtering — path traversal."""
    with tarfile.open(tar_path) as tf:
        tf.extractall(dest)  # tar-slip: same as zip but with tar


def read_zip_member(zip_path, member_name):
    """Reading zip member by user-controlled name."""
    with zipfile.ZipFile(zip_path) as zf:
        return zf.read(member_name)  # could read any path in the archive


# ── Section 4: Protocol handler abuse ───────────────────────────────────

def open_url_browser(user_url):
    """webbrowser.open with user input — can open file:// etc."""
    webbrowser.open(user_url)  # arbitrary URL scheme — file://, javascript:, etc.


def ftp_anonymous(host):
    """FTP connection without credentials."""
    ftp = ftplib.FTP(host)  # unencrypted FTP
    ftp.login()  # anonymous login
    return ftp.nlst()


def smtp_plain(host, user, password):
    """SMTP without TLS."""
    server = smtplib.SMTP(host, 25)  # unencrypted SMTP
    server.login(user, password)  # credentials sent in cleartext
    return server


def telnet_connect(host, port=23):
    """Telnet — inherently insecure."""
    return telnetlib.Telnet(host, port)  # unencrypted telnet


def xmlrpc_no_tls(url):
    """XML-RPC without TLS."""
    return xmlrpc.client.ServerProxy(url)  # possibly unencrypted


# ── Section 5: Context manager misuse ───────────────────────────────────

def context_manager_leak():
    """Opening resource but never entering context."""
    f = open("/etc/passwd")  # open-without-with
    # Forgot to close — resource leak if exception occurs
    data = f.read()
    f.close()  # not reached if read() raises
    return data


def suppressed_exception():
    """contextlib.suppress hiding errors."""
    with contextlib.suppress(Exception):  # swallows ALL exceptions silently
        result = dangerous_operation()
        return result
    return None  # silently returns None on any error


def nested_context_leak():
    """Inner resource leaks when outer fails."""
    outer = open("/tmp/outer.txt", "w")
    inner = open("/tmp/inner.txt", "w")  # leaks if outer.write raises
    outer.write("data")
    inner.write("data")
    outer.close()
    inner.close()


# ── Section 6: Encoding/serialization edge cases ───────────────────────

def base64_decode_exec(encoded_cmd):
    """Decode and execute base64 payload."""
    cmd = base64.b64decode(encoded_cmd).decode()
    os.system(cmd)  # os-system with decoded payload


def struct_unpack_overflow(data):
    """struct.unpack without length validation — buffer issues."""
    # No check that data is at least 12 bytes
    a, b, c = struct.unpack("!III", data[:12])
    return a, b, c


def json_loads_with_eval_fallback(raw):
    """Fallback to eval when json.loads fails — antipattern."""
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return eval(raw)  # eval-usage — fallback defeats the purpose


# ── Section 7: Signal handler vulnerabilities ───────────────────────────

def unsafe_signal_handler():
    """Signal handler that does non-reentrant operations."""
    def handler(signum, frame):
        # File I/O in signal handler — not async-signal-safe
        with open("/tmp/crash.log", "a") as f:
            f.write(f"Signal {signum} received\n")
        sys.exit(1)

    signal.signal(signal.SIGINT, handler)


# ── Section 8: Memory-mapped file issues ────────────────────────────────

def mmap_world_readable(path):
    """Memory-mapped file with no access control."""
    f = open(path, "r+b")
    mm = mmap.mmap(f.fileno(), 0)  # maps entire file — no size limit
    return mm


def mmap_shared_secret(secret_data):
    """Shared memory for secrets — visible to other processes."""
    mm = mmap.mmap(-1, len(secret_data))  # anonymous shared mapping
    mm.write(secret_data)
    return mm  # secret in shared memory — accessible via /proc/*/maps


# ── Section 9: ctypes / FFI abuse ───────────────────────────────────────

def ctypes_load_user_lib(lib_path):
    """Loading shared library from user-controlled path."""
    lib = ctypes.cdll.LoadLibrary(lib_path)  # arbitrary code execution
    return lib


def ctypes_cast_unsafe(ptr, size):
    """Unsafe memory access via ctypes."""
    buf = ctypes.create_string_buffer(size)
    ctypes.memmove(buf, ptr, size)  # arbitrary memory read if ptr is controlled
    return buf.raw


# ── Section 10: URL manipulation vulnerabilities ────────────────────────

def open_redirect(base_url, user_path):
    """URL join can create open redirect."""
    return urljoin(base_url, user_path)  # if user_path is //evil.com, redirects


def ssrf_via_urlparse(user_url):
    """urlparse doesn't validate — SSRF via parser confusion."""
    parsed = urlparse(user_url)
    if parsed.scheme in ("http", "https"):
        import requests
        return requests.get(user_url).text  # ssrf-risk — urlparse is not security validation


# ── Section 11: Unsafe HTTP handler patterns ────────────────────────────

class UnsafeHandler(BaseHTTPRequestHandler):
    """HTTP handler with multiple vulnerabilities."""

    def do_GET(self):
        """Command injection via URL path."""
        path = self.path
        os.system(f"cat /var/www{path}")  # os-system + path injection

    def do_POST(self):
        """Deserialization from POST body."""
        import pickle
        length = int(self.headers["Content-Length"])
        body = self.rfile.read(length)
        data = pickle.loads(body)  # pickle-unsafe from network
        self.send_response(200)


# ── Section 12: Environment variable injection ──────────────────────────

def ld_preload_attack():
    """Setting LD_PRELOAD — can hijack library loading."""
    os.environ["LD_PRELOAD"] = "/tmp/evil.so"  # library injection


def path_manipulation():
    """Prepending to PATH for command hijacking."""
    os.environ["PATH"] = "/tmp/bin:" + os.environ.get("PATH", "")  # PATH injection


def pythonpath_inject():
    """Modifying PYTHONPATH for module hijacking."""
    sys.path.insert(0, "/tmp/modules")  # module injection via sys.path


# ── Section 13: Hardcoded secrets in unusual forms ──────────────────────

# Hex-encoded secret
HEX_SECRET = bytes.fromhex("7365637265745f6b65795f313233")  # "secret_key_123"

# Bytes literal
BYTES_KEY = b"production-api-key-do-not-share"

# Multi-assignment
DB_HOST, DB_PORT, DB_PASS = "db.prod.com", 5432, "Pr0duction!Pass"

# F-string constructed URL with credentials
API_URL = f"https://api_user:{'hardcoded_secret_key'}@api.example.com/v2"


# ── Section 14: Generator / iterator resource leaks ─────────────────────

def leaky_file_generator(pattern):
    """Generator that opens files but caller may not exhaust it."""
    import glob
    for path in glob.glob(pattern):
        f = open(path)  # open-without-with — never closed if generator abandoned
        yield f.read()
        f.close()  # only reached if next() is called


def db_cursor_generator(query):
    """Generator holding DB connection open."""
    import sqlite3
    conn = sqlite3.connect("app.db")
    cursor = conn.cursor()
    cursor.execute(query)  # potential sql-injection if query has user input
    for row in cursor:
        yield row
    conn.close()  # never reached if generator is abandoned


# ── Section 15: Insecure comparison patterns ────────────────────────────

def timing_safe_fail(stored_hash, user_input):
    """Direct string comparison for cryptographic values."""
    computed = __import__("hashlib").sha256(user_input.encode()).hexdigest()
    if computed == stored_hash:  # timing attack
        return True
    return False


def admin_check_by_string(role):
    """Role check via string — case sensitivity issues."""
    return role == "Admin"  # case-sensitive — "admin" fails, "ADMIN" fails


# ── Section 16: Dangerous shutil operations ─────────────────────────────

def copy_with_symlinks(src, dst):
    """shutil.copytree follows symlinks by default."""
    shutil.copytree(src, dst)  # follows symlinks — can copy sensitive files


def rmtree_user_path(user_path):
    """shutil.rmtree on user-controlled path — path traversal deletion."""
    shutil.rmtree(user_path)  # could delete anything if user_path is ../../


# ── Section 17: Flask/Django response patterns ──────────────────────────

def render_user_html(user_content):
    """Returning user content as HTML without escaping."""
    return f"<html><body>{user_content}</body></html>"  # reflected XSS


def set_cors_wildcard():
    """CORS wildcard — allows any origin."""
    headers = {"Access-Control-Allow-Origin": "*"}  # CORS wildcard
    return headers


def cookie_without_flags():
    """Cookie without security flags."""
    # Set-Cookie: session=abc123  (no Secure, no HttpOnly, no SameSite)
    return "Set-Cookie: session=abc123; Path=/"  # missing security flags


# ── Section 18: Integer overflow / boundary issues ──────────────────────

def unchecked_allocation(user_size):
    """Allocating memory based on user input."""
    buf = bytearray(int(user_size))  # DoS — huge allocation if user_size is large
    return buf


def slice_overflow(data, start, end):
    """No bounds checking on slice indices."""
    return data[int(start):int(end)]  # no validation — negative indices, huge ranges
