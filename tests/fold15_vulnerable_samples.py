"""Fold 15: Framework views, crypto library misuse, protocol handlers,
and regex boundary stress tests.

Probes: Flask/Django view patterns, paramiko without host key verify,
jwt algorithm confusion, cryptography lib misuse (small key, ECB, no IV),
os.walk following symlinks, subprocess with bytes, and patterns designed
to test regex boundary conditions in existing Doji rules.
"""

import os
import re
import ssl
import sys
import json
import hmac
import socket
import pickle
import sqlite3
import hashlib
import logging
import subprocess
from pathlib import Path
from typing import Any, Dict, Optional

logger = logging.getLogger(__name__)


# ── Section 1: Flask-like view patterns ──────────────────────────────

def flask_route_sqli(request_args: dict):
    """Flask route handler with SQL injection."""
    user_id = request_args.get("user_id", "")
    conn = sqlite3.connect("app.db")
    # Direct interpolation of request parameter
    cursor = conn.execute(
        f"SELECT * FROM users WHERE id = '{user_id}'"  # sql-injection
    )
    return cursor.fetchall()


def flask_route_ssti(request_args: dict):
    """Flask route with template injection."""
    name = request_args.get("name", "World")
    # format() with user-controlled string
    template = request_args.get("template", "Hello, {name}!")
    return template.format(name=name)  # SSTI via .format()


def flask_route_redirect(request_args: dict):
    """Open redirect via unvalidated URL."""
    next_url = request_args.get("next", "/")
    # No validation — can redirect to external site
    return {"redirect": next_url}  # open redirect


def flask_file_send(request_args: dict):
    """Serve file from user-controlled path."""
    filename = request_args.get("file", "index.html")
    base = Path("/var/www/static")
    filepath = base / filename  # path traversal — no validation
    return filepath.read_bytes()


def flask_cookie_set(response, request_args: dict):
    """Set cookie without security flags."""
    value = request_args.get("session", "")
    response.set_cookie("session_id", value)  # missing Secure, HttpOnly, SameSite


# ── Section 2: Django-like patterns ──────────────────────────────────

def django_raw_sql(request_data: dict):
    """Django view using raw SQL."""
    from django.db import connection  # type: ignore
    search = request_data.get("q", "")
    with connection.cursor() as cursor:
        cursor.execute(f"SELECT * FROM products WHERE name LIKE '%{search}%'")  # sql-injection
        return cursor.fetchall()


def django_mark_safe(user_content: str):
    """Django mark_safe on user content — XSS."""
    from django.utils.safestring import mark_safe  # type: ignore
    return mark_safe(f"<div>{user_content}</div>")  # XSS via mark_safe


def django_extra_raw(queryset, order_field: str):
    """Django QuerySet.extra with raw SQL."""
    return queryset.extra(
        where=[f"name = '{order_field}'"],  # sql-injection
    )


# ── Section 3: JWT algorithm confusion ───────────────────────────────

def jwt_decode_no_verify(token: str) -> dict:
    """JWT decode without verification."""
    import jwt as pyjwt  # type: ignore
    return pyjwt.decode(token, options={"verify_signature": False})  # jwt-insecure


def jwt_decode_none_algorithm(token: str, key: str) -> dict:
    """JWT decode allowing 'none' algorithm."""
    import jwt as pyjwt  # type: ignore
    return pyjwt.decode(token, key, algorithms=["HS256", "none"])  # jwt-insecure — allows none


def jwt_weak_secret(payload: dict) -> str:
    """JWT with weak/short secret."""
    import jwt as pyjwt  # type: ignore
    return pyjwt.encode(payload, "secret", algorithm="HS256")  # weak JWT secret


def jwt_hs256_with_public_key(token: str, public_key: str) -> dict:
    """JWT algorithm confusion — HS256 with RSA public key."""
    import jwt as pyjwt  # type: ignore
    # Attacker can use public key as HMAC secret if algorithm isn't restricted
    return pyjwt.decode(token, public_key, algorithms=["HS256"])


# ── Section 4: paramiko SSH without host key verification ────────────

def ssh_connect_no_verify(hostname: str, username: str, password: str):
    """SSH connection without host key verification."""
    import paramiko  # type: ignore
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # auto-accept host keys
    client.connect(hostname, username=username, password=password)
    return client


def ssh_exec_command(client, command: str):
    """Execute command via SSH — injection if command is user-controlled."""
    stdin, stdout, stderr = client.exec_command(command)  # command injection
    return stdout.read().decode()


def sftp_download(hostname: str, remote_path: str, local_path: str):
    """SFTP download — path traversal on both ends."""
    import paramiko  # type: ignore
    transport = paramiko.Transport((hostname, 22))
    transport.connect(username="deploy", password="deploy123")  # hardcoded-secret
    sftp = paramiko.SFTPClient.from_transport(transport)
    sftp.get(remote_path, local_path)  # path traversal


# ── Section 5: cryptography library misuse ───────────────────────────

def weak_rsa_key():
    """RSA key too small — breakable."""
    from cryptography.hazmat.primitives.asymmetric import rsa  # type: ignore
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=1024,  # too small — NIST requires >= 2048
    )
    return private_key


def aes_ecb_mode(key: bytes, data: bytes) -> bytes:
    """AES in ECB mode — insecure."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
    cipher = Cipher(algorithms.AES(key), modes.ECB())  # insecure-ecb-mode
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def aes_static_iv(key: bytes, data: bytes) -> bytes:
    """AES-CBC with static IV — defeats randomization."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
    iv = b"\x00" * 16  # static IV — every message encrypts identically
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


def des_encryption(key: bytes, data: bytes) -> bytes:
    """DES encryption — broken cipher."""
    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes  # type: ignore
    cipher = Cipher(algorithms.TripleDES(key), modes.CBC(b"\x00" * 8))
    encryptor = cipher.encryptor()
    return encryptor.update(data) + encryptor.finalize()


# ── Section 6: os.walk following symlinks ────────────────────────────

def walk_with_symlinks(root_dir: str):
    """os.walk following symlinks — can escape directory tree."""
    results = []
    for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=True):
        for fname in filenames:
            fpath = os.path.join(dirpath, fname)
            results.append(fpath)
    return results


def recursive_delete(root_dir: str):
    """Delete all files in tree — dangerous with symlinks."""
    for dirpath, dirnames, filenames in os.walk(root_dir, followlinks=True):
        for fname in filenames:
            os.remove(os.path.join(dirpath, fname))  # follows symlinks — can delete outside tree


def process_uploaded_archive(archive_path: str, extract_dir: str):
    """Extract and walk archive — zip slip + symlink following."""
    import zipfile
    with zipfile.ZipFile(archive_path) as zf:
        zf.extractall(extract_dir)  # archive-slip
    # Now walk the extracted contents following symlinks
    for dirpath, _, filenames in os.walk(extract_dir, followlinks=True):
        for fname in filenames:
            process_file(os.path.join(dirpath, fname))


# ── Section 7: Subprocess with bytes and various entry points ────────

def subprocess_bytes_cmd(cmd_bytes: bytes):
    """Subprocess with bytes command."""
    subprocess.run(cmd_bytes, shell=True)  # shell-true with bytes


def subprocess_env_cmd():
    """Subprocess command from environment."""
    cmd = os.environ.get("BUILD_CMD", "make")
    subprocess.run(cmd, shell=True)  # shell-true + env source


def subprocess_path_concat(base_cmd: str, user_arg: str):
    """Command built via concatenation."""
    full_cmd = base_cmd + " " + user_arg
    subprocess.Popen(full_cmd, shell=True)  # shell-true via concat


def subprocess_fstring_popen(host: str, port: int):
    """Popen with f-string command."""
    proc = subprocess.Popen(
        f"nc {host} {port}",
        shell=True,
        stdout=subprocess.PIPE,
    )
    return proc.communicate()


# ── Section 8: Regex boundary stress — secrets with dots/special ─────

# Secrets with dots (e.g. Sendgrid, JWTs) — tests the char class
SENDGRID_API_KEY = "SG.aBcDeFgHiJkLmN.oPqRsTuVwXyZ0123456789_-"  # has dots — outside [A-Za-z0-9+/=_\-!@#$%^&*]
STRIPE_SECRET_KEY = "doji_fake_51ABC123defGHI456jklMNO"  # standard format
TWILIO_AUTH_TOKEN = "a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6"  # 32-char hex

# Secrets with colons and equals (config-style)
DATABASE_PASSWORD = "P@ssw0rd!2024#Prod"  # matches existing pattern
ADMIN_SECRET = "admin-secret-key-do-not-share-v2"  # matches \w+[_-]secret


# ── Section 9: eval/exec with indirection ────────────────────────────

EVAL_FUNC = eval  # reference to eval
EXEC_FUNC = exec  # reference to exec


def indirect_eval(expr: str):
    """Call eval via variable reference."""
    fn = eval  # local reference
    return fn(expr)  # eval-usage — same line, different name


def indirect_exec(code: str):
    """Call exec via variable reference."""
    fn = exec  # local reference
    fn(code)  # exec-usage


def eval_via_builtins(expr: str):
    """eval via __builtins__."""
    return __builtins__["eval"](expr) if isinstance(__builtins__, dict) else eval(expr)  # eval-usage


def exec_via_type(code: str):
    """exec via type() — construct function from string."""
    func = type("F", (), {"__init__": lambda self: exec(code)})  # exec-usage in type()
    func()


# ── Section 10: SQL injection via cursor methods ─────────────────────

def executemany_injection(conn, table: str, rows: list):
    """executemany with interpolated table name."""
    if not rows:
        return
    cols = ", ".join(rows[0].keys())
    placeholders = ", ".join(["?" for _ in rows[0]])
    conn.executemany(
        f"INSERT INTO {table} ({cols}) VALUES ({placeholders})",  # sql-injection in table
        [tuple(r.values()) for r in rows],
    )


def executescript_injection(conn, table: str):
    """executescript with interpolated SQL."""
    conn.executescript(f"""
        DROP TABLE IF EXISTS {table};
        CREATE TABLE {table} (id INTEGER PRIMARY KEY, data TEXT);
    """)  # sql-injection via executescript


def fetchone_injection(conn, username: str):
    """SQL injection with fetchone pattern."""
    row = conn.execute(
        f"SELECT password_hash FROM users WHERE username = '{username}'"  # sql-injection
    ).fetchone()
    return row


# ── Section 11: Hardcoded secrets in multiline strings ───────────────

CONFIG_JSON = """
{
    "database": {
        "host": "db.production.internal",
        "port": 5432,
        "password": "Pr0duction_DB_P@ss!"
    },
    "api": {
        "secret_key": "sk-api-9a8b7c6d5e4f3g2h1i0j"
    }
}
"""

YAML_CONFIG = """
database:
  password: SuperSecretDBPassword123
redis:
  auth_token: redis-auth-tok-abc123xyz
"""


# ── Section 12: Logging expanded ─────────────────────────────────────

def log_database_query(query: str, params: tuple):
    """Log SQL query with parameters — may contain sensitive data."""
    logger.debug(f"SQL: {query} params={params}")  # query params may contain passwords


def log_with_password_field(data: dict):
    """Log dict that has password field."""
    logger.info(f"Processing: {data}")  # data['password'] logged


def log_api_key_in_url(url: str):
    """Log URL containing API key."""
    logger.info(f"Requesting: {url}")  # URL may contain ?api_key=XXX


def log_stack_trace_with_locals():
    """Log full stack trace including local variables."""
    import traceback
    logger.error(f"Stack: {traceback.format_exc()}")  # may include sensitive locals


# ── Section 13: Pickle via class methods ─────────────────────────────

class DataStore:
    """Data store using pickle for serialization."""

    def __init__(self, filepath: str):
        self.filepath = filepath

    def save(self, data: Any):
        """Pickle dump to file."""
        with open(self.filepath, "wb") as f:
            pickle.dump(data, f)

    def load(self) -> Any:
        """Pickle load from file."""
        with open(self.filepath, "rb") as f:
            return pickle.load(f)  # pickle-unsafe

    def load_from_bytes(self, data: bytes) -> Any:
        """Pickle loads from bytes."""
        return pickle.loads(data)  # pickle-unsafe

    @classmethod
    def from_network(cls, sock: socket.socket):
        """Receive and unpickle from network."""
        data = sock.recv(65536)
        return pickle.loads(data)  # pickle-unsafe from network


# ── Section 14: Mixed vulnerability chains ───────────────────────────

def config_to_rce(config_path: str):
    """Config file → eval → RCE."""
    with open(config_path) as f:
        config = json.load(f)
    if "startup_expr" in config:
        result = eval(config["startup_expr"])  # eval-usage from config
    if "startup_cmd" in config:
        os.system(config["startup_cmd"])  # os-system from config


def url_to_pickle_rce(url: str):
    """URL → fetch → pickle → RCE."""
    import requests  # type: ignore
    resp = requests.get(url, timeout=30)  # ssrf-risk
    return pickle.loads(resp.content)  # pickle-unsafe


def sql_to_eval_rce(conn, key: str):
    """SQL injection → eval → RCE."""
    row = conn.execute(
        f"SELECT expr FROM formulas WHERE key = '{key}'"  # sql-injection
    ).fetchone()
    if row:
        return eval(row[0])  # eval-usage from DB


def file_to_exec_rce(filepath: str):
    """Read file → exec → RCE."""
    code = open(filepath).read()  # open-without-with
    exec(code)  # exec-usage from file
