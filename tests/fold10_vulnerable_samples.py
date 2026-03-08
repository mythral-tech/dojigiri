"""Fold 10: OWASP comprehensive + self-scan prep.

Final fold targets remaining CWE gaps: integer handling, race conditions
in web apps, CORS misconfig, cookie issues, response splitting, open
redirects, mass assignment, insecure defaults, and comprehensive
combinations that chain multiple vulnerabilities.
"""

import os
import re
import sys
import json
import time
import hmac
import socket
import struct
import hashlib
import logging
import sqlite3
import secrets
import threading
import subprocess
import http.server
import http.cookies
import email.mime.text
from pathlib import Path
from functools import wraps
from typing import Any, Dict, Optional
from xml.etree.ElementTree import parse as xml_parse  # aliased import of XXE-risk
from urllib.parse import urlparse, urljoin, quote


logger = logging.getLogger(__name__)


# ── Section 1: OWASP A01 — Broken Access Control ───────────────────────

def insecure_direct_object_ref(user_id: int, requested_id: int):
    """No authz check — user can access any record."""
    conn = sqlite3.connect("app.db")
    # Missing: if user_id != requested_id and not is_admin(user_id): raise
    return conn.execute(f"SELECT * FROM orders WHERE id = {requested_id}").fetchone()  # sql-injection


def path_traversal_download(base_dir: str, filename: str):
    """File download with insufficient path validation."""
    full_path = os.path.join(base_dir, filename)
    # "Validation" that doesn't work:
    if ".." in filename:
        return None  # can be bypassed with ..%2f or ....// or symlinks
    with open(full_path, "rb") as f:
        return f.read()


def admin_panel_no_auth():
    """Admin functionality without authentication check."""
    conn = sqlite3.connect("admin.db")
    return conn.execute("SELECT * FROM users").fetchall()  # no auth check


# ── Section 2: OWASP A02 — Cryptographic Failures ──────────────────────

def encrypt_user_data(data: str, key: str) -> str:
    """XOR 'encryption' — not real encryption."""
    encrypted = bytes(a ^ b for a, b in zip(data.encode(), (key * len(data)).encode()))
    return encrypted.hex()  # XOR is not encryption


def store_password_plaintext(username: str, password: str):
    """Storing password without hashing."""
    conn = sqlite3.connect("users.db")
    conn.execute(
        f"INSERT INTO users (username, password) VALUES ('{username}', '{password}')"  # sql-injection + plaintext password
    )
    conn.commit()


def generate_iv_static():
    """Static IV for CBC — defeats the purpose."""
    return b"\x00" * 16  # static IV — every message encrypted identically


def md5_file_checksum(filepath: str) -> str:
    """MD5 for file integrity — collision attacks possible."""
    h = hashlib.md5()  # weak-hash
    with open(filepath, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            h.update(chunk)
    return h.hexdigest()


# ── Section 3: OWASP A03 — Injection (comprehensive) ──────────────────

def ldap_injection(username: str):
    """LDAP injection via string formatting."""
    query = f"(&(uid={username})(objectClass=person))"  # LDAP injection
    return query


def xpath_injection(xml_doc, username: str):
    """XPath injection."""
    return xml_doc.find(f".//user[@name='{username}']")  # XPath injection


def header_injection(header_value: str):
    """HTTP header injection via CRLF."""
    return f"X-Custom: {header_value}\r\n"  # CRLF injection


def template_injection(template_str: str, context: dict):
    """Direct string format as template — SSTI."""
    return template_str.format(**context)  # SSTI via format()


def command_from_config(config: dict):
    """Command from configuration — injection if config is user-editable."""
    cmd = config.get("post_process_cmd", "echo done")
    os.system(cmd)  # os-system from config


# ── Section 4: OWASP A04 — Insecure Design ─────────────────────────────

def rate_limit_by_ip(request_ip: str) -> bool:
    """Rate limiting by IP — bypassed with X-Forwarded-For."""
    # Missing: validating X-Forwarded-For against trusted proxies
    return True  # always allows — no actual rate limiting


def password_reset_predictable(user_email: str) -> str:
    """Predictable reset token."""
    import random
    timestamp = int(time.time())
    return hashlib.md5(f"{user_email}:{timestamp}:{random.randint(0, 99)}".encode()).hexdigest()  # weak-hash + weak-random + small range


def session_fixation(session_id: str) -> str:
    """Accepting session ID from URL parameter."""
    # Missing: regenerate session after login
    return session_id  # session fixation


# ── Section 5: OWASP A05 — Security Misconfiguration ───────────────────

DEBUG = True  # debug-enabled
ALLOWED_HOSTS = ["*"]
SECURE_SSL_REDIRECT = False
SESSION_COOKIE_SECURE = False
CSRF_COOKIE_SECURE = False
X_FRAME_OPTIONS = "ALLOW"  # clickjacking


def create_server_permissive():
    """HTTP server with permissive config."""
    server = http.server.HTTPServer(("0.0.0.0", 8080), None)  # bind-all-interfaces
    return server


def cors_config():
    """Permissive CORS."""
    return {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE, OPTIONS",
        "Access-Control-Allow-Headers": "*",
        "Access-Control-Allow-Credentials": "true",  # wildcard + credentials = very bad
    }


# ── Section 6: OWASP A06 — Vulnerable Components ───────────────────────

def check_package_version(package_name: str):
    """Check package version via pip — command injection."""
    result = subprocess.run(
        f"pip show {package_name}",  # command injection via package name
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def install_package(package_spec: str):
    """Install package — supply chain attack vector."""
    subprocess.run(
        f"pip install {package_spec}",  # command injection + typosquatting
        shell=True,
    )


# ── Section 7: OWASP A07 — Auth Failures ───────────────────────────────

ADMIN_PASSWORD = "admin123!@#SuperSecure"  # hardcoded-secret


def authenticate(username: str, password: str) -> bool:
    """Authentication with timing leak."""
    conn = sqlite3.connect("users.db")
    row = conn.execute(
        f"SELECT password_hash, salt FROM users WHERE username = '{username}'"  # sql-injection
    ).fetchone()
    if not row:
        return False
    stored_hash, salt = row
    computed = hashlib.sha256((salt + password).encode()).hexdigest()
    return computed == stored_hash  # timing attack


def create_jwt_token(payload: dict, secret: str = "default-jwt-secret") -> str:
    """JWT with default secret."""
    import jwt  # type: ignore
    return jwt.encode(payload, secret, algorithm="HS256")


def brute_force_no_lockout(username: str, password: str) -> bool:
    """No account lockout — allows brute force."""
    # Missing: rate limiting, account lockout after N failures, CAPTCHA
    return authenticate(username, password)


# ── Section 8: OWASP A08 — Software/Data Integrity ─────────────────────

def load_config_from_url(url: str) -> dict:
    """Loading config from remote URL — supply chain risk."""
    import requests  # type: ignore
    resp = requests.get(url)  # ssrf-risk + no TLS verification
    return json.loads(resp.text)


def eval_webhook_payload(payload: str):
    """Evaluating webhook body — RCE."""
    return eval(payload)  # eval-usage


def install_from_url(url: str, dest: str):
    """Download and extract — no integrity check."""
    import requests  # type: ignore
    resp = requests.get(url)  # ssrf-risk
    archive_path = Path(dest) / "download.tar.gz"
    archive_path.write_bytes(resp.content)
    import tarfile
    with tarfile.open(archive_path) as tf:
        tf.extractall(dest)  # archive-slip


# ── Section 9: OWASP A09 — Logging Failures ───────────────────────────

def log_login_attempt(username: str, password: str, success: bool):
    """Logging password in login attempt."""
    logger.info(f"Login attempt: user={username} password={password} success={success}")  # logging-sensitive-data


def log_api_call(endpoint: str, headers: dict, body: Any):
    """Logging full request including auth headers."""
    logger.debug(f"API call to {endpoint} headers={headers} body={body}")
    # headers may contain Authorization, cookies, tokens


def no_audit_trail(user_id: int, action: str):
    """Critical action without logging."""
    conn = sqlite3.connect("app.db")
    conn.execute(f"DELETE FROM records WHERE user_id = {user_id}")  # sql-injection
    # Missing: no audit log of deletion


# ── Section 10: OWASP A10 — SSRF ───────────────────────────────────────

def fetch_url(url: str) -> str:
    """Classic SSRF — no URL validation."""
    import requests  # type: ignore
    return requests.get(url, timeout=10).text  # ssrf-risk


def fetch_internal_api(service_name: str, path: str) -> dict:
    """SSRF via service name resolution."""
    import requests  # type: ignore
    url = f"http://{service_name}.internal:8080{path}"  # insecure-http + SSRF
    return requests.get(url, timeout=10).json()  # ssrf-risk


def image_proxy(image_url: str) -> bytes:
    """Image proxy — SSRF + denial of service."""
    import requests  # type: ignore
    resp = requests.get(image_url, timeout=30, stream=True)  # ssrf-risk
    # No content-length check — could download gigabytes
    return resp.content


# ── Section 11: XML parsing via aliased import ──────────────────────────

def parse_config_xml(path: str):
    """XML parse via aliased import at top of file."""
    tree = xml_parse(path)  # xxe-risk via 'from ... import parse as xml_parse'
    return tree.getroot()


# ── Section 12: Comprehensive vulnerability chains ──────────────────────

def full_chain_attack(user_input: str):
    """Multiple vulnerabilities chained together."""
    # Step 1: SQL injection to read data
    conn = sqlite3.connect("app.db")
    cursor = conn.execute(f"SELECT config FROM settings WHERE key = '{user_input}'")  # sql-injection
    row = cursor.fetchone()

    if row:
        config = json.loads(row[0])

        # Step 2: SSRF from config value
        import requests  # type: ignore
        resp = requests.get(config.get("callback_url", ""))  # ssrf-risk

        # Step 3: Deserialization of response
        import pickle
        result = pickle.loads(resp.content)  # pickle-unsafe

        # Step 4: Command execution from result
        os.system(str(result.get("command", "")))  # os-system

    return None
