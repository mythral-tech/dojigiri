"""Fold 7: Adversarial evasion — patterns specifically designed to bypass
regex-based detection. Obfuscated calls, indirect references, string
building, getattr tricks, lambda wrappers, and encoding bypasses.

If Doji catches these, the blade is truly sharp.
"""

import os
import sys
import subprocess
import sqlite3
import pickle
import hashlib
import base64
import json
import socket


# ── Section 1: getattr-based evasion ────────────────────────────────────

def getattr_os_system(cmd):
    """os.system via getattr — evades literal regex."""
    func = getattr(os, "system")  # indirection
    func(cmd)


def getattr_pickle_loads(data):
    """pickle.loads via getattr."""
    load_fn = getattr(pickle, "loads")
    return load_fn(data)


def getattr_subprocess(cmd):
    """subprocess.Popen via getattr."""
    popen = getattr(subprocess, "Popen")
    return popen(cmd, shell=True)


def getattr_hashlib(data):
    """hashlib.md5 via getattr."""
    hasher = getattr(hashlib, "md5")
    return hasher(data).hexdigest()


# ── Section 2: String concatenation to build function names ─────────────

def concat_eval(user_input):
    """eval built from string parts."""
    fn_name = "ev" + "al"
    return __builtins__[fn_name](user_input) if isinstance(__builtins__, dict) else getattr(__builtins__, fn_name)(user_input)


def concat_exec(code):
    """exec from concatenated name."""
    fn = getattr(__builtins__ if not isinstance(__builtins__, dict) else type("", (), __builtins__)(), "ex" + "ec")
    fn(code)


def concat_os_module(cmd):
    """Import os via __import__ and call system."""
    mod = __import__("o" + "s")
    mod.system(cmd)


# ── Section 3: Lambda/closure wrappers ──────────────────────────────────

# Dangerous functions wrapped in lambdas
run_shell = lambda cmd: os.system(cmd)  # os-system hidden in lambda
deserialize = lambda data: pickle.loads(data)  # pickle-unsafe in lambda
weak_hash = lambda d: hashlib.md5(d).hexdigest()  # weak-hash in lambda
run_eval = lambda x: eval(x)  # eval-usage in lambda


def make_executor(shell=True):
    """Factory that returns a dangerous closure."""
    def executor(cmd):
        return subprocess.run(cmd, shell=shell)  # shell-true inside closure
    return executor


def make_deserializer(protocol="pickle"):
    """Factory returning deserialization closure."""
    if protocol == "pickle":
        return lambda data: pickle.loads(data)  # pickle-unsafe in returned lambda
    return json.loads


# ── Section 4: String-built SQL queries (non-f-string) ──────────────────

def sql_concat_plus(username):
    """SQL via + operator."""
    conn = sqlite3.connect(":memory:")
    query = "SELECT * FROM users WHERE name = '" + username + "'"  # sql-injection via +
    return conn.execute(query)


def sql_percent_format(table, user_id):
    """SQL via % formatting."""
    conn = sqlite3.connect(":memory:")
    query = "SELECT * FROM %s WHERE id = %s" % (table, user_id)  # sql-injection via %
    return conn.execute(query)


def sql_join_build(columns, table, conditions):
    """SQL built with join."""
    parts = ["SELECT", ", ".join(columns), "FROM", table]
    if conditions:
        parts.append("WHERE " + " AND ".join(conditions))
    query = " ".join(parts)  # sql-injection if conditions has user input
    conn = sqlite3.connect(":memory:")
    return conn.execute(query)


def sql_template_string(user_id):
    """SQL via string.Template — less common pattern."""
    from string import Template
    tmpl = Template("SELECT * FROM users WHERE id = $uid")
    query = tmpl.substitute(uid=user_id)  # sql-injection — no escaping
    return sqlite3.connect(":memory:").execute(query)


# ── Section 5: Encoding-based secret hiding ─────────────────────────────

# Base64-encoded credentials
_ENCODED_PASS = base64.b64decode(b"UHIwZHVjdGlvblBAc3N3MHJk").decode()  # "Pr0ductionP@ssw0rd"
_ENCODED_KEY = base64.b64decode(b"c2stcHJvai1hYmMxMjNkZWY0NTY=").decode()  # "sk-proj-abc123def456"

# Hex-encoded
_HEX_SECRET = bytes.fromhex("73757065725f7365637265745f6b6579").decode()  # "super_secret_key"

# ROT13 (lol)
import codecs
_ROT13_PASS = codecs.decode("cebqhpgvba_cnffjbeq", "rot_13")  # "production_password"

# Reversed string
_REVERSED_KEY = "drowssap_terces_ym"[::-1]  # "my_secret_password"


# ── Section 6: Indirect file operations ─────────────────────────────────

def pathlib_open_user(user_path):
    """pathlib.Path.open without sanitization."""
    from pathlib import Path
    p = Path(user_path)
    return p.read_text()  # path traversal if user_path is ../../etc/passwd


def io_open_user(path):
    """io.open — same as open() but via different module."""
    import io
    return io.open(path, "r").read()  # open-without-with via io module


def os_open_raw(path):
    """os.open — low-level file descriptor."""
    fd = os.open(path, os.O_RDONLY)  # low-level open — no context manager possible
    data = os.read(fd, 4096)
    os.close(fd)  # not reached if os.read raises
    return data


# ── Section 7: Network patterns that evade SSRF detection ──────────────

def urllib3_request(url):
    """urllib3 — not in standard SSRF patterns."""
    import urllib3  # type: ignore
    http = urllib3.PoolManager()
    return http.request("GET", url)  # SSRF via urllib3


def httpx_async(url):
    """httpx — modern HTTP client not in patterns."""
    import httpx  # type: ignore
    with httpx.Client() as client:
        return client.get(url)  # SSRF via httpx


def aiohttp_session(url):
    """aiohttp — async HTTP not in patterns."""
    import aiohttp  # type: ignore
    async def fetch():
        async with aiohttp.ClientSession() as session:
            async with session.get(url) as resp:
                return await resp.text()
    return fetch()


def socket_raw_http(host, port, path):
    """Raw socket HTTP — bypasses all HTTP client detection."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((host, port))
    s.send(f"GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n".encode())
    return s.recv(4096)


# ── Section 8: Subprocess evasion patterns ──────────────────────────────

def os_exec_family(cmd, args):
    """os.exec* family — replaces current process."""
    os.execvp(cmd, args)  # not caught — different from os.system


def os_spawn(cmd):
    """os.spawn* family."""
    os.spawnl(os.P_NOWAIT, cmd, cmd)  # process spawning — not in patterns


def popen_via_os(cmd):
    """os.popen variant — stream interface."""
    stream = os.popen(cmd)  # os-popen — already caught?
    return stream.read()


def subprocess_check_output_shell(cmd):
    """check_output with shell=True."""
    return subprocess.check_output(cmd, shell=True)  # shell-true


# ── Section 9: Pickle alternatives that are equally dangerous ───────────

def dill_loads(data):
    """dill — pickle alternative, equally dangerous."""
    import dill  # type: ignore
    return dill.loads(data)  # same risk as pickle.loads


def cloudpickle_loads(data):
    """cloudpickle — another pickle variant."""
    import cloudpickle  # type: ignore
    return cloudpickle.loads(data)


def jsonpickle_decode(data):
    """jsonpickle — JSON wrapper around pickle, equally dangerous."""
    import jsonpickle  # type: ignore
    return jsonpickle.decode(data)  # RCE via crafted JSON


# ── Section 10: Yaml variants ──────────────────────────────────────────

def yaml_load_all(data):
    """yaml.load_all — same risk as yaml.load."""
    import yaml
    return list(yaml.load_all(data))  # yaml-unsafe variant


def yaml_unsafe_load(data):
    """yaml.unsafe_load — explicitly unsafe."""
    import yaml
    return yaml.unsafe_load(data)  # explicitly named "unsafe"!


# ── Section 11: Hash comparison timing attacks ──────────────────────────

def verify_token_eq(provided, stored):
    """Direct == for auth tokens."""
    return provided == stored  # timing attack — but how to distinguish from normal ==?


def verify_hmac_manual(msg, sig, key):
    """Manual HMAC with == comparison."""
    import hmac
    expected = hmac.new(key, msg, hashlib.sha256).hexdigest()
    if sig == expected:  # timing attack on HMAC
        return True
    return False


def verify_digest_concat(data, expected_hash):
    """Hash verification with ==."""
    actual = hashlib.sha256(data).hexdigest()
    return actual == expected_hash  # timing attack


# ── Section 12: Multiline patterns that regex won't catch ───────────────

def multiline_subprocess(user_input):
    """subprocess.run across multiple lines."""
    result = subprocess.run(
        user_input,    # user-controlled
        shell=True,    # dangerous — but shell= is on different line than run(
        capture_output=True,
    )
    return result


def multiline_eval_call(
    expression,   # user-controlled
    namespace=None,
):
    """eval with args split across lines."""
    return eval(
        expression,   # eval-usage — but eval( is line above
        namespace or {},
    )


def multiline_pickle(
    data,
    protocol=None,
):
    """pickle.loads split across lines."""
    return pickle.loads(
        data,   # pickle-unsafe but loads( is on previous line
    )


# ── Section 13: Decorator-based auth bypass ─────────────────────────────

def require_admin(func):
    """Auth decorator that uses assert — stripped with -O."""
    def wrapper(user, *args, **kwargs):
        assert user.is_admin, "Admin required"  # assert-statement — bypassed with -O!
        return func(user, *args, **kwargs)
    return wrapper


@require_admin
def delete_all_users(user):
    """Protected by assert-based decorator."""
    conn = sqlite3.connect("app.db")
    conn.execute("DELETE FROM users")  # catastrophic if auth is bypassed
    conn.commit()


# ── Section 14: Class variable mutation via method ──────────────────────

class ConfigStore:
    """Class with mutable class-level defaults."""

    _secrets = {}  # mutable class attribute — shared across instances
    _cache = []    # same issue

    def store_secret(self, key, value):
        """Stores to class-level dict — visible to all instances."""
        self._secrets[key] = value  # mutating class attribute

    def get_all_secrets(self):
        """Returns class-level secrets — information leak across instances."""
        return self._secrets


# ── Section 15: Exception info leak patterns ────────────────────────────

def api_error_handler(request):
    """Returns full exception details to client."""
    try:
        process(request)
    except Exception as e:
        import traceback
        return {
            "error": str(e),
            "type": type(e).__name__,
            "traceback": traceback.format_exc(),  # full stack trace to client!
            "locals": {k: str(v) for k, v in locals().items()},  # leaks all locals!
        }


def log_then_reraise_with_context(password, token):
    """Re-raising exception that includes sensitive vars in traceback."""
    try:
        authenticate(password, token)
    except Exception:
        raise  # traceback includes password and token in frame locals
