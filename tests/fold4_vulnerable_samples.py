"""Fold 4: Beyond bandit — patterns NEITHER tool catches but should.

Targets: Django/Flask security misconfig, regex DoS, hardcoded JWT secrets,
unsafe __init__ side effects, type confusion, TOCTOU races, debug mode in
production, unclosed generators, dangerous default configs, and more.
"""

import os
import re
import jwt  # type: ignore
import hashlib
import hmac
import logging
import sqlite3
import subprocess
import pickle
import json
import socket
import tempfile
import threading
from pathlib import Path
from typing import Any


# ── Section 1: Django/Flask security misconfigurations ──────────────────

# Flask debug mode in production
# from flask import Flask
# app = Flask(__name__)
# app.run(debug=True)  # DEBUG MODE — exposes Werkzeug debugger with RCE

# Django settings patterns
DEBUG = True  # Django DEBUG=True in production — information disclosure
SECRET_KEY = "django-insecure-abc123def456ghi789jkl012"  # hardcoded Django secret
ALLOWED_HOSTS = ["*"]  # allows any host — HTTP host header injection
SESSION_COOKIE_SECURE = False  # cookies sent over HTTP
CSRF_COOKIE_SECURE = False  # CSRF token sent over HTTP
SESSION_COOKIE_HTTPONLY = False  # cookie accessible via JavaScript


# ── Section 2: JWT with hardcoded secret ────────────────────────────────

JWT_SECRET = "my-super-secret-jwt-key-2024"

def create_token(user_id):
    """JWT signed with hardcoded secret."""
    return jwt.encode({"user_id": user_id}, JWT_SECRET, algorithm="HS256")


def verify_token_none_algo(token):
    """JWT decoded allowing 'none' algorithm."""
    return jwt.decode(token, options={"verify_signature": False})  # no verification!


def verify_token_weak(token):
    """JWT with HS256 and weak secret."""
    return jwt.decode(token, "secret", algorithms=["HS256"])  # weak secret


# ── Section 3: Regex Denial of Service (ReDoS) ─────────────────────────

def redos_email(email):
    """Catastrophic backtracking regex."""
    pattern = re.compile(r"^([a-zA-Z0-9]+)*@([a-zA-Z0-9]+)*\.([a-zA-Z0-9]+)*$")
    return pattern.match(email)  # ReDoS: nested quantifiers


def redos_url(url):
    """Another ReDoS pattern."""
    return re.match(r"^(https?://)?([a-z0-9]+\.)*[a-z0-9]+\.[a-z]{2,}(/.*)*$", url)


def redos_nested(text):
    """Classic nested repetition."""
    return re.search(r"(a+)+b", text)  # exponential backtracking


# ── Section 4: TOCTOU (Time-of-check-time-of-use) races ────────────────

def toctou_file_read(filepath):
    """Check-then-use race condition."""
    if os.path.exists(filepath):  # TOCTOU: file could be replaced between check and open
        with open(filepath) as f:
            return f.read()
    return None


def toctou_file_write(filepath, data):
    """Check-then-write race."""
    if not os.path.exists(filepath):  # TOCTOU race
        with open(filepath, "w") as f:
            f.write(data)


def toctou_isfile(filepath):
    """isfile then open race."""
    if os.path.isfile(filepath):  # TOCTOU
        return open(filepath).read()
    return ""


# ── Section 5: Unsafe string formatting for logging ────────────────────

logger = logging.getLogger(__name__)


def log_format_injection(user_input):
    """User input in format string — log injection."""
    logger.info("User action: %s" % user_input)  # % formatting, not parameterized
    logger.warning(f"Failed login for {user_input}")  # f-string in log — injection risk


def log_sensitive_exception(password):
    """Logging exception that contains sensitive data."""
    try:
        authenticate(password)
    except Exception as e:
        logger.error(f"Auth failed with password {password}: {e}")  # logs password!


# ── Section 6: Dangerous __init__ patterns ──────────────────────────────

class UnsafeInit:
    """Class with dangerous side effects in __init__."""

    def __init__(self, config_path):
        # Network call in __init__ — blocks, hard to test, can fail silently
        self.data = self._fetch_remote("http://config.internal/api")  # insecure-http
        # Shell command in __init__
        os.system(f"chmod 777 {config_path}")  # os-system + injection
        # Pickle load in __init__
        with open(config_path, "rb") as f:
            self.config = pickle.load(f)  # pickle-unsafe

    def _fetch_remote(self, url):
        import requests
        return requests.get(url).json()  # ssrf-risk + no timeout


# ── Section 7: Type confusion / unsafe casting ─────────────────────────

def unsafe_int_cast(user_input):
    """int() on user input without validation — can raise."""
    port = int(user_input)  # no try/except — crashes on non-numeric
    return socket.create_connection(("localhost", port))


def unsafe_float(value):
    """float() on untrusted input — NaN/Inf injection."""
    return float(value) * 100  # NaN * 100 = NaN, Inf * 100 = Inf


# ── Section 8: Weak HMAC / comparison ──────────────────────────────────

def insecure_token_compare(user_token, valid_token):
    """String comparison for auth tokens — timing attack."""
    return user_token == valid_token  # timing attack! use hmac.compare_digest


def weak_hmac(data, key):
    """HMAC with MD5."""
    return hmac.new(key, data, hashlib.md5).hexdigest()  # weak hash in HMAC


def verify_signature_manual(data, signature, key):
    """Manual signature verification — timing unsafe."""
    expected = hashlib.sha256(key + data).hexdigest()
    return signature == expected  # timing attack + length extension attack


# ── Section 9: Subprocess with user-controlled args ─────────────────────

def subprocess_format(filename):
    """User input in subprocess via f-string."""
    subprocess.run(f"cat {filename}", shell=True)  # shell-true + injection


def subprocess_list_with_user_input(host):
    """Even list form can be dangerous with certain executables."""
    subprocess.run(["curl", host])  # SSRF via subprocess — no shell=True but still dangerous


def subprocess_env_override(cmd):
    """subprocess with modified PATH."""
    env = os.environ.copy()
    env["PATH"] = "/tmp:" + env["PATH"]  # PATH injection — /tmp executables take priority
    subprocess.run(cmd, env=env)  # subprocess-audit


# ── Section 10: Insecure randomness for security ───────────────────────

import random
import string
import secrets  # noqa: F811


def generate_password_weak(length=16):
    """Password generation with weak random."""
    chars = string.ascii_letters + string.digits
    return "".join(random.choice(chars) for _ in range(length))  # weak-random for password!


def generate_session_id():
    """Session ID with weak random."""
    return "%032x" % random.getrandbits(128)  # weak-random for session ID!


def generate_otp():
    """OTP with weak random."""
    return str(random.randint(100000, 999999))  # weak-random for OTP!


# ── Section 11: Hardcoded credentials in various formats ────────────────

DATABASE_URL = "postgresql://admin:s3cretP@ssw0rd@db.prod.example.com:5432/myapp"  # db-connection-string
REDIS_URL = "redis://:authpassword@redis.internal:6379/0"  # db-connection-string
MONGODB_URI = "mongodb://root:mongopass123@mongo.cluster.example.com:27017/admin"  # db-connection-string

# Base64-encoded secret (not caught by simple regex)
ENCODED_SECRET = "c2VjcmV0X2FwaV9rZXlfMTIzNDU2Nzg5MA=="  # base64 of secret_api_key_1234567890

# Connection string in env-like format
os.environ.setdefault("DATABASE_URL", "postgresql://user:password123@localhost/db")  # hardcoded in setdefault


# ── Section 12: File handling edge cases ────────────────────────────────

def read_symlink_unsafe(path):
    """Following symlinks without checking."""
    return Path(path).read_text()  # follows symlinks — path traversal if user-controlled


def world_writable_dir():
    """Creating world-writable directory."""
    os.makedirs("/tmp/myapp", mode=0o777, exist_ok=True)  # world-writable directory


def temp_in_tmp():
    """Predictable temp file location."""
    path = "/tmp/myapp_cache.dat"  # predictable path in /tmp — symlink attack
    with open(path, "w") as f:
        f.write("cached data")


# ── Section 13: Concurrency vulnerabilities ─────────────────────────────

shared_state = {"count": 0}


def race_condition_increment():
    """Unprotected shared state — race condition."""
    # No lock around read-modify-write
    shared_state["count"] += 1  # race condition in threaded context


def daemon_thread_with_cleanup():
    """Daemon thread holding resources."""
    def worker():
        conn = sqlite3.connect("app.db")
        while True:
            conn.execute("SELECT 1")  # resource-leak in daemon thread

    t = threading.Thread(target=worker, daemon=True)
    t.start()


# ── Section 14: Assertion-based security checks ────────────────────────

def check_admin(user):
    """Assert for authorization — stripped with -O."""
    assert user.role == "admin", "Unauthorized"  # assert-statement — security bypass with -O
    return get_admin_panel()


def validate_input(data):
    """Assert for input validation."""
    assert isinstance(data, dict), "Expected dict"  # stripped with -O
    assert "user_id" in data, "Missing user_id"  # stripped with -O
    return process(data)


# ── Section 15: Dangerous default function arguments ────────────────────

def connect_db(host="localhost", port=5432, password="default_password"):
    """Default password in function signature."""
    return f"postgresql://app:{password}@{host}:{port}/db"


def create_user(name, role="admin"):
    """Default role is admin — principle of least privilege violation."""
    return {"name": name, "role": role}


# ── Section 16: XML/HTML injection patterns ─────────────────────────────

def build_xml_response(user_data):
    """String interpolation in XML — injection."""
    return f"<response><user>{user_data}</user></response>"  # XML injection


def build_html_email(username):
    """HTML injection in email template."""
    return f"<html><body>Welcome {username}!</body></html>"  # stored XSS via email


# ── Section 17: Cryptographic misuse ────────────────────────────────────

def encrypt_ecb(data, key):
    """AES-ECB — patterns visible."""
    from Crypto.Cipher import AES  # pycrypto-deprecated
    cipher = AES.new(key, AES.MODE_ECB)  # insecure-ecb-mode
    return cipher.encrypt(data)


def hash_without_salt(password):
    """Password hashing without salt."""
    return hashlib.sha256(password.encode()).hexdigest()  # no salt — rainbow table vulnerable


def compare_hash_insecure(stored_hash, password):
    """Timing-unsafe hash comparison."""
    computed = hashlib.sha256(password.encode()).hexdigest()
    return computed == stored_hash  # timing attack


# ── Section 18: Deserialization from network ────────────────────────────

def receive_pickle_from_network(sock):
    """Pickle from network socket — RCE."""
    data = sock.recv(4096)
    return pickle.loads(data)  # pickle-unsafe from network!


def load_json_with_eval(raw):
    """Using eval instead of json.loads — legacy pattern."""
    return eval(raw)  # eval-usage — should use json.loads


def deserialize_from_request(request_body):
    """Pickle from HTTP request body."""
    return pickle.loads(request_body)  # pickle-unsafe from request!


# ── Section 19: Debug/development leftover patterns ─────────────────────

FLASK_DEBUG = True  # debug mode flag
DJANGO_DEBUG = True  # debug mode flag

def backdoor_endpoint(request):
    """Debug backdoor left in code."""
    if request.args.get("debug") == "true":
        return eval(request.args.get("cmd", ""))  # eval-usage — debug backdoor!


def test_credentials():
    """Test credentials left in code."""
    return {"username": "admin", "password": "admin123!test"}  # hardcoded test creds


# ── Section 20: Environment variable trust ──────────────────────────────

def run_from_env():
    """Executing command from environment variable."""
    cmd = os.environ.get("CUSTOM_CMD", "echo hello")
    os.system(cmd)  # os-system — env var could be manipulated


def sql_from_env(cursor):
    """SQL from environment variable — still injectable."""
    table = os.environ.get("TABLE_NAME", "users")
    cursor.execute(f"SELECT * FROM {table}")  # sql-injection from env
