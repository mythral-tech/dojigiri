"""Fold 20: Network/protocol-level vulnerabilities.

Focus on cleartext protocols (FTP, telnet, SMTP without TLS), URL parsing
tricks, CORS misconfig, cookie security flags, JWT algorithm confusion,
WebSocket message injection, GraphQL introspection leaks, rate limiting
bypass, DNS resolution TOCTOU, HTTP header injection, and open redirects.
"""

import os
import re
import sys
import json
import hmac
import socket
import base64
import hashlib
import logging
import secrets
import sqlite3
import subprocess
import urllib.request
import urllib.parse
from pathlib import Path
from typing import Any, Dict, List, Optional
from http.server import HTTPServer, BaseHTTPRequestHandler

logger = logging.getLogger(__name__)


# ── Section 1: Cleartext protocol usage ──────────────────────────────

def ftp_upload(host: str, username: str, password: str, filepath: str):
    """FTP upload — cleartext credentials over the wire."""
    import ftplib
    ftp = ftplib.FTP(host)  # cleartext FTP connection
    ftp.login(username, password)  # credentials sent in plaintext
    with open(filepath, "rb") as f:
        ftp.storbinary(f"STOR {Path(filepath).name}", f)
    ftp.quit()


def telnet_connect(host: str, port: int = 23):
    """Telnet — cleartext protocol, no encryption."""
    import telnetlib
    tn = telnetlib.Telnet(host, port)  # cleartext telnet
    tn.read_until(b"login: ")
    tn.write(b"admin\n")
    tn.read_until(b"Password: ")
    tn.write(b"admin123\n")  # hardcoded credential over telnet
    return tn


def smtp_no_tls(host: str, port: int = 25):
    """SMTP without TLS — emails sent in cleartext."""
    import smtplib
    server = smtplib.SMTP(host, port)  # smtp-cleartext — no starttls
    server.login("user@example.com", "SmtpPassword123!")  # cleartext auth
    server.sendmail(
        "from@example.com",
        "to@example.com",
        "Subject: Test\n\nBody"
    )
    server.quit()


def pop3_cleartext(host: str):
    """POP3 without SSL — cleartext email retrieval."""
    import poplib
    pop = poplib.POP3(host)  # cleartext POP3
    pop.user("mailuser")
    pop.pass_("MailPassword2024!")  # cleartext password
    return pop.list()


def imap_cleartext(host: str):
    """IMAP without SSL — cleartext."""
    import imaplib
    imap = imaplib.IMAP4(host)  # cleartext IMAP
    imap.login("imapuser", "ImapSecret2024!")  # cleartext credentials
    imap.select("INBOX")
    return imap.search(None, "ALL")


# ── Section 2: URL parsing tricks / open redirect ────────────────────

def validate_redirect_url(url: str) -> bool:
    """Broken redirect validation — bypassable."""
    # Only checks startswith — attacker uses //evil.com or \/evil.com
    if url.startswith("/") and not url.startswith("//"):
        return True
    # Bypassable: url = "/\\evil.com" or url = "/%2F/evil.com"
    return False


def open_redirect(request_url: str) -> str:
    """Open redirect — no validation on target."""
    target = urllib.parse.parse_qs(
        urllib.parse.urlparse(request_url).query
    ).get("next", ["/"])[0]
    return f"HTTP/1.1 302 Found\r\nLocation: {target}\r\n\r\n"  # open redirect


def ssrf_via_urlopen(url: str) -> bytes:
    """urllib.request.urlopen — SSRF risk."""
    return urllib.request.urlopen(url).read()  # ssrf-risk — no URL validation


def ssrf_via_urlretrieve(url: str, dest: str):
    """urllib.request.urlretrieve — SSRF + arbitrary write."""
    urllib.request.urlretrieve(url, dest)  # ssrf + path traversal


# ── Section 3: Cookie security misconfig ─────────────────────────────

def set_insecure_cookie(response_headers: list, name: str, value: str):
    """Set cookie without Secure, HttpOnly, or SameSite flags."""
    response_headers.append(
        ("Set-Cookie", f"{name}={value}; Path=/")  # missing Secure, HttpOnly, SameSite
    )


def set_session_cookie_http(response_headers: list, session_id: str):
    """Session cookie without HttpOnly — XSS can steal it."""
    response_headers.append(
        ("Set-Cookie", f"session={session_id}; Path=/; Secure")  # missing HttpOnly
    )


def set_cookie_no_samesite(response_headers: list, csrf_token: str):
    """CSRF token cookie without SameSite — CSRF risk."""
    response_headers.append(
        ("Set-Cookie", f"csrf={csrf_token}; Path=/; Secure; HttpOnly")  # missing SameSite
    )


# ── Section 4: HTTP header injection ─────────────────────────────────

def build_response_header(user_value: str) -> str:
    """HTTP header injection via user-controlled value."""
    # user_value could contain \r\n to inject additional headers
    return f"X-Custom-Value: {user_value}\r\n"  # header injection


def redirect_with_header_injection(location: str) -> str:
    """Redirect with header injection possibility."""
    # location could contain \r\n\r\n to inject response body
    return f"HTTP/1.1 302 Found\r\nLocation: {location}\r\n\r\n"


def log_user_agent(user_agent: str):
    """Log injection via User-Agent."""
    # user_agent with \n can forge log entries
    logger.info(f"User-Agent: {user_agent}")  # log injection


# ── Section 5: JWT vulnerabilities ───────────────────────────────────

def jwt_none_algorithm(payload: dict) -> str:
    """JWT with 'none' algorithm — no signature verification."""
    header = base64.urlsafe_b64encode(
        json.dumps({"alg": "none", "typ": "JWT"}).encode()
    ).rstrip(b"=").decode()
    body = base64.urlsafe_b64encode(
        json.dumps(payload).encode()
    ).rstrip(b"=").decode()
    return f"{header}.{body}."  # unsigned JWT


def jwt_hs256_with_public_key(token: str, public_key: str) -> dict:
    """JWT algorithm confusion — verify HS256 with RSA public key."""
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("Invalid JWT")
    # Algorithm confusion: accepting HS256 when RS256 expected
    header = json.loads(base64.urlsafe_b64decode(parts[0] + "=="))
    body = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
    if header.get("alg") == "HS256":
        # Verify using public key as HMAC secret — algorithm confusion attack
        expected = hmac.new(
            public_key.encode(),
            f"{parts[0]}.{parts[1]}".encode(),
            hashlib.sha256  # weak-hash context but real vuln is algo confusion
        ).hexdigest()
    return body  # returns payload without proper verification


def jwt_hardcoded_secret():
    """JWT with hardcoded signing secret."""
    JWT_SECRET = "super-secret-jwt-key-2024-production"  # hardcoded-secret
    return JWT_SECRET


# ── Section 6: CORS misconfiguration ─────────────────────────────────

def cors_allow_all(request_origin: str) -> dict:
    """CORS with Access-Control-Allow-Origin: * — too permissive."""
    return {
        "Access-Control-Allow-Origin": "*",  # overly permissive CORS
        "Access-Control-Allow-Credentials": "true",  # dangerous with *
        "Access-Control-Allow-Methods": "GET, POST, PUT, DELETE",
    }


def cors_reflect_origin(request_origin: str) -> dict:
    """CORS reflecting arbitrary origin — equivalent to *."""
    return {
        "Access-Control-Allow-Origin": request_origin,  # reflects any origin
        "Access-Control-Allow-Credentials": "true",
    }


def cors_null_origin() -> dict:
    """CORS allowing null origin — iframe bypass."""
    return {
        "Access-Control-Allow-Origin": "null",  # null origin allowed
        "Access-Control-Allow-Credentials": "true",
    }


# ── Section 7: Subprocess with user input in various positions ───────

def subprocess_env_injection(cmd: str, user_env: dict):
    """Subprocess with user-controlled environment variables."""
    env = os.environ.copy()
    env.update(user_env)  # user controls LD_PRELOAD, PATH, etc.
    subprocess.run(cmd.split(), env=env)  # env injection


def subprocess_cwd_injection(cmd: list, user_cwd: str):
    """Subprocess with user-controlled working directory."""
    subprocess.run(cmd, cwd=user_cwd)  # cwd from user — symlink attacks


def subprocess_stdin_injection(cmd: list, user_input: str):
    """Subprocess with user input piped to stdin."""
    proc = subprocess.Popen(
        cmd,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
    )
    stdout, _ = proc.communicate(input=user_input.encode())
    return stdout


# ── Section 8: Weak randomness for security ──────────────────────────

import random

def generate_token_insecure(length: int = 32) -> str:
    """Token generation with random instead of secrets."""
    chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
    return "".join(random.choice(chars) for _ in range(length))  # weak random


def generate_session_id() -> str:
    """Session ID with random — predictable."""
    return hashlib.md5(  # weak-hash
        str(random.randint(0, 999999)).encode()  # weak random seed
    ).hexdigest()


def generate_otp() -> str:
    """OTP with random — predictable."""
    return str(random.randint(100000, 999999))  # weak random for OTP


def generate_password_reset_token(user_id: int) -> str:
    """Password reset token — predictable."""
    random.seed(user_id)  # predictable seed!
    return hashlib.sha1(  # weak-hash
        str(random.random()).encode()
    ).hexdigest()


# ── Section 9: SQL injection in ORM-like patterns ────────────────────

def raw_sql_in_orm(db, table: str, filters: dict):
    """Raw SQL in ORM context — injection."""
    conditions = " AND ".join(f"{k} = '{v}'" for k, v in filters.items())
    return db.execute(
        f"SELECT * FROM {table} WHERE {conditions}"  # sql-injection
    ).fetchall()


def sql_like_injection(conn, search_term: str):
    """SQL LIKE with user input — injection."""
    conn.execute(
        f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"  # sql-injection
    )


def sql_order_by_injection(conn, table: str, order_field: str):
    """SQL ORDER BY with user input — injection."""
    conn.execute(
        f"SELECT * FROM {table} ORDER BY {order_field}"  # sql-injection
    )


def sql_group_by_injection(conn, table: str, group_field: str):
    """SQL GROUP BY with user input — injection."""
    conn.execute(
        f"SELECT {group_field}, COUNT(*) FROM {table} GROUP BY {group_field}"  # sql-injection
    )


def sql_having_injection(conn, table: str, having_clause: str):
    """SQL HAVING with user input — injection."""
    conn.execute(
        f"SELECT type, COUNT(*) FROM {table} GROUP BY type HAVING {having_clause}"  # sql-injection
    )


# ── Section 10: Deserialization beyond pickle ─────────────────────────

def yaml_unsafe_load(data: str):
    """yaml.load without safe Loader — RCE."""
    import yaml
    return yaml.load(data)  # yaml-unsafe — no Loader specified


def yaml_fullloader(data: str):
    """yaml.load with FullLoader — still some risks."""
    import yaml
    return yaml.load(data, Loader=yaml.FullLoader)  # yaml-unsafe — FullLoader not fully safe


def marshal_load(data: bytes):
    """marshal.loads — can execute arbitrary code."""
    import marshal
    return marshal.loads(data)  # marshal-unsafe — like pickle


def shelve_open_untrusted(path: str):
    """shelve.open — uses pickle internally."""
    import shelve
    db = shelve.open(path)  # shelve uses pickle — unsafe with untrusted data
    return dict(db)


# ── Section 11: File operations — race conditions ────────────────────

def check_then_open(filepath: str) -> str:
    """TOCTOU — check exists then open."""
    if os.path.exists(filepath):  # check
        with open(filepath) as f:  # use — race condition
            return f.read()
    return ""


def check_permissions_then_read(filepath: str) -> bytes:
    """TOCTOU — check permissions then read."""
    if os.access(filepath, os.R_OK):  # check
        return open(filepath, "rb").read()  # use — TOCTOU + open-without-with
    raise PermissionError(f"Cannot read {filepath}")


def mkdir_then_write(dirpath: str, filename: str, data: bytes):
    """TOCTOU — check dir then write."""
    if not os.path.isdir(dirpath):
        os.makedirs(dirpath)  # race — dir could be created between check and makedirs
    with open(os.path.join(dirpath, filename), "wb") as f:
        f.write(data)


# ── Section 12: Eval/exec in unusual stdlib contexts ─────────────────

def eval_in_sorted_key(items: list, key_expr: str) -> list:
    """eval as sort key — user controls sort behavior."""
    return sorted(items, key=lambda x: eval(key_expr))  # eval-usage in sort key


def eval_in_filter(items: list, filter_expr: str) -> list:
    """eval as filter predicate."""
    return list(filter(lambda x: eval(filter_expr), items))  # eval-usage in filter


def eval_in_map(items: list, transform_expr: str) -> list:
    """eval in map — transform each item."""
    return list(map(lambda x: eval(transform_expr), items))  # eval-usage in map


def exec_in_timer():
    """exec in threading.Timer callback."""
    import threading
    code = "import os; os.system('id')"
    t = threading.Timer(0.1, exec, args=(code,))  # exec-usage via Timer
    t.start()


# ── Section 13: Hardcoded credentials — connection strings ───────────

# Database connection strings with embedded credentials
MYSQL_DSN = "mysql://root:RootPass2024!@db.prod.internal:3306/app"  # hardcoded-secret
POSTGRES_DSN = "postgresql://admin:PgAdmin2024!@pg.prod.internal:5432/prod"  # hardcoded-secret
REDIS_URL = "redis://:RedisSecret2024@redis.internal:6379/0"  # hardcoded-secret
MONGO_URI = "mongodb://appuser:MongoPass2024@mongo.internal:27017/appdb"  # hardcoded-secret
AMQP_URL = "amqp://guest:guest@rabbitmq.internal:5672/"  # hardcoded-secret

# AWS-style credentials
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"  # hardcoded-secret
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # hardcoded-secret


def get_db_connection(env: str = "production"):
    """Return connection string — hardcoded for all envs."""
    connections = {
        "production": "postgresql://prod_user:ProdPassword!@db.prod:5432/app",  # hardcoded in dict
        "staging": "postgresql://stage_user:StagePass123@db.stage:5432/app",  # hardcoded in dict
    }
    return connections.get(env, connections["production"])


# ── Section 14: Unsafe temporary file patterns ───────────────────────

def predictable_temp_path(prefix: str) -> str:
    """Predictable temp file path — race condition."""
    path = f"/tmp/{prefix}_{os.getpid()}.tmp"  # hardcoded-tmp — predictable
    with open(path, "w") as f:
        f.write("")
    return path


def temp_world_writable(data: str) -> str:
    """Create world-writable temp file."""
    path = "/tmp/app_shared_data.txt"  # hardcoded-tmp
    with open(path, "w") as f:
        f.write(data)
    os.chmod(path, 0o777)  # world-writable — anyone can modify
    return path


# ── Section 15: Mixed realistic attack chains ────────────────────────

class APIGateway:
    """API gateway with multiple vulnerability classes."""

    SECRET_KEY = "gateway-signing-key-production-2024"  # hardcoded-secret

    def __init__(self):
        self.conn = sqlite3.connect("gateway.db")

    def authenticate(self, token: str) -> dict:
        """Authenticate via JWT — multiple issues."""
        parts = token.split(".")
        if len(parts) != 3:
            raise ValueError("Invalid token")
        # Decode without verifying signature
        payload = json.loads(base64.urlsafe_b64decode(parts[1] + "=="))
        # SQL injection to check revocation
        row = self.conn.execute(
            f"SELECT revoked FROM tokens WHERE jti = '{payload.get('jti')}'"  # sql-injection
        ).fetchone()
        if row and row[0]:
            raise ValueError("Token revoked")
        return payload

    def proxy_request(self, target_url: str, headers: dict) -> bytes:
        """Proxy request — SSRF."""
        req = urllib.request.Request(target_url, headers=headers)
        return urllib.request.urlopen(req).read()  # ssrf-risk

    def log_request(self, method: str, path: str, user_id: str):
        """Log with SQL injection."""
        self.conn.execute(
            f"INSERT INTO logs (method, path, user_id) VALUES ('{method}', '{path}', '{user_id}')"  # sql-injection
        )
        self.conn.commit()

    def eval_template(self, template: str, context: dict) -> str:
        """Eval-based template rendering."""
        for key, val in context.items():
            template = template.replace(f"{{{key}}}", str(val))
        return eval(f'f"""{template}"""')  # eval-usage — SSTI

    def run_healthcheck(self, check_cmd: str) -> bool:
        """Health check via shell — command injection."""
        result = subprocess.run(
            check_cmd,
            shell=True,  # shell-true
            capture_output=True,
            timeout=5,
        )
        return result.returncode == 0
