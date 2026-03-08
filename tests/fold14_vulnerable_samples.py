"""Fold 14: Assertion-based security, error swallowing, SSL context misuse,
sandbox escapes, and creative multiline evasion.

Targets patterns not yet probed in folds 2-13.
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
import secrets
import string
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


# ── Section 1: Assert used as security check ─────────────────────────
# assert is stripped with python -O, so any security check using assert
# silently disappears in optimized mode.

def assert_auth_check(user, required_role: str):
    """Assert for authorization — removed with -O flag."""
    assert user.role == required_role, "Unauthorized"  # assert-statement as auth
    return get_sensitive_data()


def assert_input_validation(user_input: str):
    """Assert for input validation — removed with -O flag."""
    assert len(user_input) < 1000, "Input too long"  # assert-statement as validation
    assert not any(c in user_input for c in ";<>&|"), "Invalid chars"  # assert-statement
    os.system(f"echo {user_input}")  # os-system — assert validation is gone with -O


def assert_bounds_check(index: int, data: list):
    """Assert for bounds check — removed with -O flag."""
    assert 0 <= index < len(data), "Out of bounds"  # assert-statement as bounds check
    return data[index]


# ── Section 2: try/except that swallows security errors ──────────────

def swallow_auth_error(username: str, password: str) -> bool:
    """Catch all exceptions including auth failures."""
    try:
        authenticate(username, password)
        return True
    except:  # bare-except — swallows AuthenticationError
        return True  # BUG: returns True on ANY error, including auth failure


def swallow_permission_error(filepath: str) -> bytes:
    """Swallow PermissionError — continues with wrong data."""
    try:
        return Path(filepath).read_bytes()
    except:  # bare-except
        return b""  # silently returns empty instead of denying access


def swallow_ssl_error(url: str) -> str:
    """Catch SSL errors and retry without verification."""
    import requests  # type: ignore
    try:
        return requests.get(url, timeout=10).text
    except Exception:
        # Retry without SSL verification — downgrades security
        return requests.get(url, verify=False, timeout=10).text  # requests-no-verify


# ── Section 3: SSL context misuse ────────────────────────────────────

def create_unverified_ssl_context():
    """Create SSL context that doesn't verify certificates."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE  # disables certificate verification
    return ctx


def ssl_wrap_no_hostname(sock, server_hostname: str):
    """SSL wrap without hostname verification."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False  # no hostname verification
    ctx.verify_mode = ssl.CERT_NONE  # no cert verification
    return ctx.wrap_socket(sock, server_hostname=server_hostname)


def ssl_old_protocol():
    """SSL context with deprecated protocol."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)  # TLS 1.0 is deprecated/insecure
    return ctx


def connect_ssl_unverified(host: str, port: int) -> ssl.SSLSocket:
    """Connect with SSL but skip all verification."""
    ctx = ssl._create_unverified_context()  # underscore = internal/unsafe
    sock = socket.create_connection((host, port))
    return ctx.wrap_socket(sock, server_hostname=host)


# ── Section 4: string.Template injection ─────────────────────────────

def template_substitute(template_str: str, context: dict) -> str:
    """string.Template with user-controlled template."""
    tmpl = string.Template(template_str)  # SSTI if template_str is user-controlled
    return tmpl.substitute(context)


def template_from_db(conn, template_id: str, context: dict) -> str:
    """Load template from DB and render — SSTI + SQLi."""
    row = conn.execute(
        f"SELECT body FROM templates WHERE id = '{template_id}'"  # sql-injection
    ).fetchone()
    if row:
        tmpl = string.Template(row[0])
        return tmpl.substitute(context)
    return ""


# ── Section 5: __subclasses__ sandbox escape ─────────────────────────

def find_subclass(base_class, target_name: str):
    """Walk __subclasses__ to find specific class — sandbox escape technique."""
    for cls in base_class.__subclasses__():
        if cls.__name__ == target_name:
            return cls
        result = find_subclass(cls, target_name)
        if result:
            return result
    return None


def exploit_subclasses():
    """Classic sandbox escape via object.__subclasses__()."""
    # Find a class that has os or subprocess available
    for cls in object.__subclasses__():
        if hasattr(cls, "__init__"):
            if "os" in str(cls.__init__.__globals__):
                return cls.__init__.__globals__["os"].system  # os-system via subclass


# ── Section 6: sys.modules manipulation ──────────────────────────────

def inject_module(name: str, module):
    """Inject fake module into sys.modules — import hijacking."""
    sys.modules[name] = module  # can override any module


def get_module_attr(module_name: str, attr: str):
    """Get attribute from sys.modules — bypasses import restrictions."""
    mod = sys.modules.get(module_name)
    if mod:
        return getattr(mod, attr)  # arbitrary attribute access


# ── Section 7: compile() with different modes ────────────────────────

def compile_eval_mode(source: str):
    """compile() in eval mode — evaluates expressions."""
    code = compile(source, "<user>", "eval")  # compile-usage
    return eval(code)  # eval-usage


def compile_exec_mode(source: str):
    """compile() in exec mode — runs statements."""
    code = compile(source, "<user>", "exec")  # compile-usage
    exec(code)  # exec-usage


def compile_single_mode(source: str):
    """compile() in single mode — interactive statement."""
    code = compile(source, "<user>", "single")  # compile-usage
    exec(code)  # exec-usage


# ── Section 8: Frozen dataclass with secrets ─────────────────────────

@dataclass(frozen=True)
class APICredentials:
    """Frozen dataclass — secrets still visible in repr/str."""
    service: str = "production"
    api_key: str = "ak_live_xK9mN2pQ7rS4tU6v"  # hardcoded-secret
    secret_key: str = "doji_fake_wA3bC5dE7fG9hI1j"  # hardcoded-secret
    webhook_secret: str = "whsec_K2L4M6N8P0Q2R4S6"  # hardcoded-secret


@dataclass
class DatabaseConfig:
    host: str = "db.internal"
    port: int = 5432
    password: str = "ProductionDbPass!2024"  # hardcoded-password-default
    connection_string: str = "postgresql://admin:ProductionDbPass!2024@db.internal:5432/app"  # db-connection-string


# ── Section 9: Multiline string building for SQL ─────────────────────

def build_query_parts(conn, table: str, conditions: dict, order: str):
    """Build SQL from multiple string parts — harder to detect."""
    query_parts = [
        f"SELECT * FROM {table}",
        "WHERE 1=1",
    ]
    for key, value in conditions.items():
        query_parts.append(f"AND {key} = '{value}'")
    query_parts.append(f"ORDER BY {order}")

    full_query = " ".join(query_parts)
    return conn.execute(full_query).fetchall()  # sql-injection — built from parts


def sql_multiline_concat(conn, user_id: str):
    """SQL via multiline string concatenation."""
    query = (
        "SELECT u.name, u.email "
        "FROM users u "
        f"WHERE u.id = '{user_id}' "  # sql-injection in multiline concat
        "ORDER BY u.name"
    )
    return conn.execute(query).fetchall()


def sql_triple_quote_fstring(conn, table: str, user_id: str):
    """SQL in triple-quoted f-string."""
    return conn.execute(
        f"""
        SELECT *
        FROM {table}
        WHERE id = '{user_id}'
        """  # sql-injection
    ).fetchall()


# ── Section 10: hashlib with usedforsecurity not set ─────────────────

def hash_for_security_check(data: str) -> str:
    """MD5 used for security without usedforsecurity=False."""
    return hashlib.md5(data.encode()).hexdigest()  # weak-hash


def hash_for_integrity(data: bytes) -> str:
    """SHA1 for integrity check."""
    return hashlib.sha1(data).hexdigest()  # weak-hash


def pbkdf2_too_few_iterations(password: str, salt: bytes) -> bytes:
    """PBKDF2 with insufficient iterations."""
    return hashlib.pbkdf2_hmac(
        "sha256", password.encode(), salt,
        iterations=1000,  # way too few — OWASP recommends 600,000+
    )


# ── Section 11: Logging sensitive data — expanded patterns ───────────

def log_full_user(user: dict):
    """Log entire user object including password."""
    logger.info(f"User created: {user}")  # may contain password field


def log_auth_header(headers: dict):
    """Log authorization header."""
    logger.debug(f"Request headers: {headers}")  # contains auth_token


def log_credit_card(card_number: str, expiry: str):
    """Log credit card info."""
    logger.info(f"Processing payment: card={card_number} exp={expiry}")  # PCI violation


def log_exception_with_locals(e: Exception):
    """Log exception with local variables — may contain secrets."""
    import traceback
    logger.error(f"Exception: {e}\nLocals: {locals()}")  # locals may have passwords


# ── Section 12: Dangerous default mutable + state mutation ───────────

def cached_queries(conn, query: str, cache: dict = {}):
    """Mutable default cache + SQL injection."""
    if query not in cache:
        cache[query] = conn.execute(f"SELECT * FROM data WHERE q = '{query}'").fetchall()  # sql-injection
    return cache[query]


def accumulate_commands(cmd: str, history: list = []):
    """Mutable default + os.system on accumulated commands."""
    history.append(cmd)
    if len(history) >= 5:
        combined = " && ".join(history)
        os.system(combined)  # os-system with accumulated commands
        history.clear()


# ── Section 13: Path operations without validation ───────────────────

def read_user_file(base_dir: str, user_path: str) -> str:
    """Read file with insufficient path validation."""
    full_path = os.path.join(base_dir, user_path)
    # "Validation" that doesn't work:
    if ".." not in user_path:
        return open(full_path).read()  # path traversal — ..%2f bypass
    return ""


def write_user_file(base_dir: str, filename: str, content: str):
    """Write to user-specified path."""
    path = Path(base_dir) / filename  # no traversal check
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)


def delete_user_file(base_dir: str, filename: str):
    """Delete file — path traversal."""
    path = os.path.join(base_dir, filename)
    if os.path.exists(path):
        os.remove(path)  # no validation — can delete arbitrary files


# ── Section 14: Network operations — SSRF patterns ──────────────────

def dns_lookup(hostname: str) -> list:
    """DNS lookup — can be used for SSRF/info gathering."""
    return socket.getaddrinfo(hostname, None)  # resolves arbitrary hostnames


def reverse_dns(ip_addr: str) -> str:
    """Reverse DNS lookup — info gathering."""
    return socket.gethostbyaddr(ip_addr)[0]  # resolves arbitrary IPs


def connect_to_host(host: str, port: int, data: bytes) -> bytes:
    """Raw socket connection — SSRF."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(10)
    s.connect((host, port))
    s.sendall(data)
    response = s.recv(4096)
    s.close()
    return response


# ── Section 15: Timing-unsafe comparison expanded ────────────────────

def check_admin_password(provided: str) -> bool:
    """Admin password check with timing leak."""
    ADMIN_PASS = "SuperSecretAdmin2024!"  # hardcoded-secret
    return provided == ADMIN_PASS  # timing attack


def check_session_token(provided: str, stored: str) -> bool:
    """Session token comparison — timing leak."""
    return provided == stored  # timing attack


def check_csrf_token(form_token: str, session_token: str) -> bool:
    """CSRF token verification — timing leak."""
    return form_token == session_token  # timing attack


# ── Section 16: Complex multiline subprocess ─────────────────────────

def run_pipeline(commands: list):
    """Run shell pipeline — multiple injection points."""
    pipeline = " | ".join(commands)
    result = subprocess.run(
        pipeline,
        shell=True,
        capture_output=True,
        text=True,
    )
    return result.stdout


def run_with_timeout(cmd: str, timeout: int = 30):
    """Run command with timeout — shell injection."""
    proc = subprocess.Popen(
        cmd,
        shell=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = proc.communicate(timeout=timeout)
        return stdout.decode()
    except subprocess.TimeoutExpired:
        proc.kill()
        return None


def run_remote_command(host: str, command: str) -> str:
    """SSH command execution — injection in both host and command."""
    result = subprocess.check_output(
        f"ssh {host} '{command}'",
        shell=True,
        timeout=30,
    )
    return result.decode()
