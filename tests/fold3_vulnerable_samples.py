"""Fold 3: Edge cases — aliased imports, async patterns, class-level vulns,
chained calls, decorator misuse, nested contexts, and multiline patterns.

Each section targets a DIFFERENT attack surface than folds 1-2.
"""

# ── Aliased imports (import X as Y) ─────────────────────────────────────

import subprocess as sp
import os as operating_system
import pickle as pkl
import yaml as yml
import hashlib as hl
import random as rng
import marshal as marsh
import shelve as shelf
import tempfile as tmp
import xml.etree.ElementTree as ET
from xml.dom import minidom as mdom
from xml.sax import handler as sax_handler
import xml.sax as xsax
from http.server import HTTPServer
import ssl
import socket as sock
import sqlite3 as db


# ── Section 1: Aliased subprocess/os ────────────────────────────────────

def aliased_subprocess_shell(user_cmd):
    """subprocess via alias with shell=True."""
    sp.run(user_cmd, shell=True)  # shell-true + subprocess-audit via alias
    sp.Popen(f"echo {user_cmd}", shell=True)  # shell-true via alias
    sp.call(user_cmd, shell=True)  # shell-true via alias


def aliased_os_system(cmd):
    """os.system via alias."""
    operating_system.system(cmd)  # os-system via alias — will Doji catch this?


def aliased_os_popen(cmd):
    """os.popen via alias."""
    operating_system.popen(cmd)  # os-popen via alias


# ── Section 2: Aliased deserialization ──────────────────────────────────

def aliased_pickle(data):
    """pickle via alias."""
    return pkl.loads(data)  # pickle-unsafe via alias


def aliased_yaml(raw):
    """yaml.load via alias."""
    return yml.load(raw)  # yaml-unsafe via alias


def aliased_marshal(data):
    """marshal via alias."""
    return marsh.loads(data)  # unsafe-deserialization via alias


def aliased_shelve_open(path):
    """shelve via alias."""
    return shelf.open(path)  # unsafe-deserialization via alias


# ── Section 3: Aliased crypto ───────────────────────────────────────────

def aliased_weak_hash(data):
    """hashlib via alias."""
    return hl.md5(data).hexdigest()  # weak-hash via alias


def aliased_weak_random():
    """random via alias."""
    return rng.randint(0, 999999)  # weak-random via alias


# ── Section 4: Aliased XML parsing ──────────────────────────────────────

def aliased_et_parse(path):
    """ET.parse via alias — already covered in fold 1."""
    return ET.parse(path)  # xxe-risk


def aliased_et_fromstring(xml_str):
    """ET.fromstring via alias — fold 2 addition."""
    return ET.fromstring(xml_str)  # xxe-risk


def aliased_et_iterparse(path):
    """ET.iterparse via alias — fold 2 addition."""
    return ET.iterparse(path)  # xxe-risk


def aliased_minidom_parse(path):
    """minidom.parse via mdom alias."""
    return mdom.parse(path)  # xxe-risk — will "mdom.parse" be caught?


def aliased_minidom_parsestring(xml_str):
    """minidom.parseString via mdom alias."""
    return mdom.parseString(xml_str)  # xxe-risk — will "mdom.parseString" be caught?


def aliased_sax_parse(path):
    """sax.parse via xsax alias."""
    xsax.parse(path, sax_handler.ContentHandler())  # xxe-risk — will "xsax.parse" be caught?


# ── Section 5: Async vulnerabilities ────────────────────────────────────

import asyncio
import aiohttp  # type: ignore


async def async_ssrf(url):
    """SSRF in async context."""
    async with aiohttp.ClientSession() as session:
        async with session.get(url) as resp:  # ssrf? aiohttp not in Doji patterns
            return await resp.text()


async def async_subprocess(user_input):
    """Async subprocess with shell."""
    proc = await asyncio.create_subprocess_shell(  # shell process — not in Doji
        f"grep {user_input} /etc/passwd",
        stdout=asyncio.subprocess.PIPE,
    )
    return await proc.communicate()


async def async_eval(expr):
    """eval in async function."""
    return eval(expr)  # eval-usage — should still be caught


async def async_sql_injection(conn, user_id):
    """SQL injection in async context."""
    await conn.execute(f"SELECT * FROM users WHERE id = {user_id}")  # sql-injection


# ── Section 6: Class-level vulnerabilities ──────────────────────────────

class InsecureService:
    """Class with multiple vulnerability patterns."""

    SECRET_KEY = "HardcodedClassSecret2024"  # hardcoded-secret as class attr
    DB_PASSWORD = "MyClassDbPass!123"  # hardcoded-secret as class attr

    _users = {}  # shared mutable class state (not a bug per se, but...)

    def __init__(self):
        self.conn = db.connect(":memory:")  # resource-leak if not closed
        self.sock = sock.socket(sock.AF_INET, sock.SOCK_STREAM)

    def query_user(self, username):
        """SQL injection via class method."""
        cursor = self.conn.cursor()
        cursor.execute(f"SELECT * FROM users WHERE name = '{username}'")  # sql-injection
        return cursor.fetchall()

    def run_command(self, cmd):
        """os.system in method."""
        os.system(cmd)  # os-system

    def bind_public(self, port):
        """Bind to all interfaces."""
        self.sock.bind(("0.0.0.0", port))  # bind-all-interfaces

    def serialize_state(self):
        """pickle.dumps is fine, but document the pattern."""
        import pickle
        return pickle.dumps(self._users)

    def deserialize_state(self, data):
        """pickle.loads from method."""
        import pickle
        self._users = pickle.loads(data)  # pickle-unsafe

    @staticmethod
    def static_eval(expr):
        """eval in static method."""
        return eval(expr)  # eval-usage

    @classmethod
    def from_yaml(cls, raw_yaml):
        """yaml.load in classmethod."""
        import yaml
        config = yaml.load(raw_yaml)  # yaml-unsafe
        return cls()


# ── Section 7: Chained / nested calls ──────────────────────────────────

def chained_hash():
    """Chained weak hash call."""
    return hashlib.md5(b"data").hexdigest().upper()  # weak-hash


def nested_eval(data):
    """eval inside other calls."""
    result = json.loads(eval(data))  # eval-usage
    return result


def format_sql_in_method_chain(table, user_id):
    """SQL injection through method chain."""
    query = "SELECT * FROM {} WHERE id = {}".format(table, user_id)
    return db.connect(":memory:").execute(query)  # sql-injection (via .format on SQL)


# ── Section 8: Tempfile and permission edge cases ───────────────────────

def aliased_mktemp():
    """tempfile.mktemp via alias."""
    return tmp.mktemp()  # insecure-tempfile via alias


def chmod_world_writable(path):
    """os.chmod with 0o777."""
    os.chmod(path, 0o777)  # insecure-file-permissions


def chmod_group_writable(path):
    """os.chmod with 0o775 — still permissive."""
    os.chmod(path, 0o775)  # insecure-file-permissions


def chmod_world_readable_exec(path):
    """os.chmod with 0o755."""
    os.chmod(path, 0o755)  # insecure-file-permissions


def chmod_safe(path):
    """os.chmod with 0o600 — should NOT be flagged."""
    os.chmod(path, 0o600)  # safe — no finding expected


# ── Section 9: SSL/TLS misconfigurations ────────────────────────────────

def insecure_ssl_context():
    """SSL context with verification disabled."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False  # dangerous
    ctx.verify_mode = ssl.CERT_NONE  # dangerous — no cert verification
    return ctx


def ssl_wrap_no_verify():
    """ssl.wrap_socket without cert verification."""
    s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    return ssl.wrap_socket(s)  # deprecated, no cert check


# ── Section 10: Hardcoded secrets in various forms ──────────────────────

# Dict-style secrets
config = {
    "database_password": "Pr0duction_P@ss!",  # hardcoded-secret in dict
    "api_key": "sk-proj-abc123def456ghi789",  # hardcoded-secret in dict
    "auth_token": "eyJhbGciOiJIUzI1NiJ9.secretpayload",  # hardcoded-secret in dict
}

# Multiline / concatenated secrets
LONG_SECRET = (
    "super_secret_"  # split across lines
    "value_12345678"
)

# Env-style but hardcoded
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # aws-credentials
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # aws-credentials


# ── Section 11: Network / socket patterns ───────────────────────────────

def create_server():
    """HTTP server on all interfaces."""
    server = HTTPServer(("0.0.0.0", 8080), None)  # bind-all-interfaces
    return server


def raw_socket_bind():
    """Raw socket bind to 0.0.0.0."""
    s = sock.socket(sock.AF_INET, sock.SOCK_STREAM)
    s.bind(("0.0.0.0", 9090))  # bind-all-interfaces
    s.listen(5)
    return s


# ── Section 12: Jinja2 edge cases ──────────────────────────────────────

from jinja2 import Environment, FileSystemLoader  # type: ignore


def jinja_no_autoescape():
    """Environment() with no args — autoescape defaults to False."""
    env = Environment()  # jinja2-autoescape-off
    return env.from_string("{{ user_input }}")


def jinja_explicit_off():
    """Environment with autoescape=False."""
    env = Environment(loader=FileSystemLoader("."), autoescape=False)  # jinja2-autoescape-off
    return env


def jinja_safe():
    """Environment with autoescape=True — should NOT be flagged."""
    env = Environment(loader=FileSystemLoader("."), autoescape=True)
    return env


# ── Section 13: HTTP URLs (non-localhost) ───────────────────────────────

API_ENDPOINT = "http://api.example.com/v1/data"  # insecure-http
WEBHOOK_URL = "http://hooks.slack.com/services/T0/B0/xxx"  # insecure-http
SAFE_LOCAL = "http://localhost:8080/health"  # should NOT be flagged


# ── Section 14: pyCrypto patterns ───────────────────────────────────────

from Crypto.Cipher import AES  # pycrypto-deprecated
from Crypto.Cipher import DES  # pycrypto-deprecated + insecure-crypto


def pycrypto_ecb():
    """AES in ECB mode via pyCrypto."""
    cipher = AES.new(b"0123456789abcdef", AES.MODE_ECB)  # insecure-ecb-mode
    return cipher


def pycrypto_des():
    """DES via pyCrypto."""
    cipher = DES.new(b"01234567", DES.MODE_ECB)  # insecure-crypto + insecure-ecb-mode
    return cipher


# ── Section 15: Assert and debug patterns ───────────────────────────────

def auth_check_with_assert(user):
    """assert for auth — stripped with -O."""
    assert user.is_authenticated, "Not authenticated"  # assert-statement
    return user.data


def debug_breakpoint():
    """breakpoint() left in code — not caught by either tool currently."""
    breakpoint()  # potential blind spot


# ── Section 16: Exception handling edge cases ───────────────────────────

def broad_except_log():
    """Bare except with only logging — still bad."""
    try:
        do_something()
    except:  # bare-except
        pass  # exception-swallowed / empty-exception-handler


def except_continue_in_loop():
    """except: continue pattern."""
    for item in range(10):
        try:
            process(item)
        except:  # bare-except
            continue  # exception-swallowed-continue


def keyboardinterrupt_catch():
    """Catching KeyboardInterrupt — usually wrong."""
    try:
        long_running()
    except KeyboardInterrupt:
        pass  # swallowing ctrl+C — not caught by Doji?


# ── Section 17: requests patterns ───────────────────────────────────────

import requests


def requests_no_timeout(url):
    """requests.get without timeout."""
    return requests.get(url)  # ssrf-risk (caught), but no timeout warning


def requests_post_no_timeout(url, data):
    """requests.post without timeout."""
    return requests.post(url, json=data)  # ssrf-risk, no timeout


def requests_with_verify_false(url):
    """requests with verify=False — disables SSL verification."""
    return requests.get(url, verify=False, timeout=30)  # verify=False not caught


def requests_session_no_verify():
    """Session-level verify=False."""
    s = requests.Session()
    s.verify = False  # session-level SSL disable — not caught
    return s.get("https://api.example.com/data")


# ── Section 18: Path traversal edge cases ───────────────────────────────

def path_join_traversal(user_path):
    """os.path.join with user input — traversal possible."""
    return os.path.join("/safe/base", user_path)  # traversal if user_path is absolute


def open_user_path(filename):
    """open() with user-controlled filename."""
    f = open(f"/uploads/{filename}", "rb")  # open-without-with + potential traversal
    return f.read()


# ── Section 19: Logging sensitive data edge cases ───────────────────────

import logging

logger = logging.getLogger(__name__)


def log_password(password):
    """Logging password directly."""
    logger.info(f"User password: {password}")  # logging-sensitive-data


def log_token(token):
    """Logging auth token."""
    logger.debug(f"Auth token = {token}")  # should catch "token" in log


def print_credentials(api_key):
    """Print with sensitive var name."""
    print(f"Using api_key: {api_key}")  # logging-sensitive-data


# ── Section 20: SSRF via different HTTP libraries ───────────────────────

import urllib.request


def urllib_ssrf(url):
    """urllib.request.urlopen — SSRF + scheme risk."""
    return urllib.request.urlopen(url)  # ssrf-risk + url-scheme-audit


def urllib_retrieve(url, path):
    """urllib.request.urlretrieve — SSRF."""
    return urllib.request.urlretrieve(url, path)  # url-scheme-audit
