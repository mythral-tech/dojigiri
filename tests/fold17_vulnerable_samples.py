"""Fold 17: Blind spots neither Doji nor bandit catch well.

Focus on patterns that genuinely matter in production:
concurrent.futures thread pool injection, email header injection,
__reduce__ pickle gadgets, dataclasses.asdict leaking secrets,
html.unescape leading to XSS, DNS rebinding, file descriptor leaks,
hardcoded credentials in connection kwargs, and boundary tests for
existing regex rules.
"""

import os
import re
import sys
import json
import hmac
import email
import socket
import pickle
import sqlite3
import hashlib
import logging
import secrets
import subprocess
import concurrent.futures
from pathlib import Path
from typing import Any, Dict
from dataclasses import dataclass, asdict, field
from html import unescape
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
import smtplib

logger = logging.getLogger(__name__)


# ── Section 1: concurrent.futures — thread/process pool injection ────

def thread_pool_eval(expressions: list) -> list:
    """Evaluate expressions in thread pool — parallel RCE."""
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
        futures = [pool.submit(eval, expr) for expr in expressions]  # eval-usage in pool
        return [f.result() for f in futures]


def thread_pool_system(commands: list) -> list:
    """Execute commands in thread pool — parallel RCE."""
    with concurrent.futures.ThreadPoolExecutor() as pool:
        futures = [pool.submit(os.system, cmd) for cmd in commands]  # os-system in pool
        return [f.result() for f in futures]


def process_pool_pickle(func, items: list):
    """ProcessPoolExecutor uses pickle for IPC — items must be safe."""
    with concurrent.futures.ProcessPoolExecutor() as pool:
        # Arguments are pickled/unpickled across process boundary
        results = list(pool.map(func, items))
    return results


def thread_pool_sql(queries: list, db_path: str):
    """SQL queries in thread pool — injection in each."""
    def run_query(q):
        conn = sqlite3.connect(db_path)
        return conn.execute(f"SELECT * FROM data WHERE key = '{q}'").fetchall()  # sql-injection
    with concurrent.futures.ThreadPoolExecutor() as pool:
        return list(pool.map(run_query, queries))


# ── Section 2: Email header injection ────────────────────────────────

def send_email_header_injection(to_addr: str, subject: str, body: str):
    """Email with user-controlled headers — header injection."""
    msg = MIMEText(body)
    msg["Subject"] = subject  # CRLF injection if subject contains \r\n
    msg["From"] = "app@example.com"
    msg["To"] = to_addr  # can inject additional recipients
    # Send via SMTP
    with smtplib.SMTP("localhost", 25) as server:  # smtp-cleartext
        server.send_message(msg)


def send_email_bcc_injection(to_addr: str, user_from: str, body: str):
    """Email with user-controlled From — can add BCC via CRLF."""
    msg = MIMEMultipart()
    msg["From"] = user_from  # CRLF injection: "attacker@evil.com\r\nBcc: victim@target.com"
    msg["To"] = to_addr
    msg["Subject"] = "Notification"
    msg.attach(MIMEText(body))
    with smtplib.SMTP("mail.internal", 587) as server:  # smtp-cleartext
        server.send_message(msg)


def format_email_template(template: str, user_data: dict) -> str:
    """Format email template with user data — SSTI."""
    return template.format(**user_data)  # SSTI if template is user-controlled


# ── Section 3: __reduce__ pickle gadgets ─────────────────────────────

class MaliciousPickle:
    """Class with __reduce__ — executes os.system on unpickle."""
    def __init__(self, cmd: str):
        self.cmd = cmd

    def __reduce__(self):
        return (os.system, (self.cmd,))  # os-system via pickle __reduce__


class EvalPickle:
    """Class with __reduce__ that evals."""
    def __reduce__(self):
        return (eval, ("__import__('os').system('id')",))  # eval-usage via __reduce__


def create_malicious_pickle(cmd: str) -> bytes:
    """Serialize malicious pickle payload."""
    return pickle.dumps(MaliciousPickle(cmd))


def load_untrusted_pickle(data: bytes):
    """Load pickle from untrusted source."""
    return pickle.loads(data)  # pickle-unsafe


# ── Section 4: dataclasses.asdict leaking secrets ────────────────────

@dataclass
class UserSession:
    user_id: int
    username: str
    password_hash: str
    session_token: str
    api_key: str = "doji_fake_prod_key_abc123xyz"  # hardcoded-secret


def serialize_session(session: UserSession) -> dict:
    """Convert session to dict — leaks all fields including secrets."""
    return asdict(session)  # leaks password_hash, session_token, api_key


def session_to_json(session: UserSession) -> str:
    """Session to JSON — includes all fields."""
    return json.dumps(asdict(session))  # leaks secrets in JSON


def log_session(session: UserSession):
    """Log session — leaks secrets."""
    logger.info(f"Session: {asdict(session)}")  # logging-sensitive-data via asdict


# ── Section 5: html.unescape leading to XSS ─────────────────────────

def render_user_content(escaped_html: str) -> str:
    """Unescape HTML then render — XSS if content was user-provided."""
    raw = unescape(escaped_html)  # unescapes &lt;script&gt; back to <script>
    return f"<div class='content'>{raw}</div>"  # XSS


def process_feed_entry(entry: dict) -> str:
    """Process RSS/Atom feed entry — unescape then display."""
    title = unescape(entry.get("title", ""))
    return f"<h2>{title}</h2>"  # XSS after unescape


# ── Section 6: Hardcoded creds in connection kwargs ──────────────────

def connect_mysql():
    """MySQL connection with hardcoded password in kwargs."""
    import mysql.connector  # type: ignore
    return mysql.connector.connect(
        host="db.production.internal",
        user="app_user",
        password="MySQL_Prod_Pass_2024!",  # hardcoded-password-default
        database="production",
    )


def connect_postgres():
    """PostgreSQL with hardcoded password."""
    import psycopg2  # type: ignore
    return psycopg2.connect(
        host="pg.internal",
        dbname="app",
        user="admin",
        password="Postgres_Admin_2024",  # hardcoded-password-default
    )


def connect_redis():
    """Redis with hardcoded password."""
    import redis  # type: ignore
    return redis.Redis(
        host="redis.internal",
        port=6379,
        password="Redis_Secret_Pass!",  # hardcoded-password-default
        db=0,
    )


def connect_mongodb():
    """MongoDB with hardcoded credentials."""
    import pymongo  # type: ignore
    return pymongo.MongoClient(
        "mongodb://admin:MongoDBProd2024@mongo.internal:27017/admin"  # db-connection-string
    )


# ── Section 7: File descriptor leaks ────────────────────────────────

def read_config_no_close(path: str) -> dict:
    """Open config file without closing — FD leak."""
    f = open(path)  # open-without-with
    data = json.load(f)
    # f.close() never called — FD leak
    return data


def read_multiple_no_close(paths: list) -> list:
    """Open multiple files without closing — FD exhaustion."""
    results = []
    for path in paths:
        f = open(path)  # open-without-with
        results.append(f.read())
        # Never closed — eventual FD exhaustion
    return results


def write_log_no_close(path: str, message: str):
    """Write to log file without closing."""
    f = open(path, "a")  # open-without-with
    f.write(f"{message}\n")
    # Not closed — data may not be flushed


# ── Section 8: DNS rebinding / TOCTOU on hostnames ──────────────────

def validate_and_fetch(url: str) -> bytes:
    """Validate hostname then fetch — DNS rebinding TOCTOU."""
    from urllib.parse import urlparse
    parsed = urlparse(url)
    hostname = parsed.hostname

    # Validate hostname resolves to external IP
    addr = socket.gethostbyname(hostname)  # first resolution
    if addr.startswith("10.") or addr.startswith("192.168.") or addr.startswith("127."):
        raise ValueError("Internal IP not allowed")

    # Fetch — but DNS may have changed between check and use (rebinding)
    import requests  # type: ignore
    return requests.get(url, timeout=10).content  # ssrf-risk — DNS rebinding


# ── Section 9: Boundary tests for existing regex patterns ────────────

# Test: hardcoded-secret with exactly 8 chars (boundary)
SHORT_SECRET = "password: 'Ab3d5f7h'"  # exactly 8 chars — should match
SEVEN_CHAR = "password: 'Ab3d5f7'"  # 7 chars — should NOT match (below threshold)

# Test: secret with all special chars
COMPLEX_SECRET_KEY = "sk_!@#$%^&*+=-_/="  # all special chars in charset

# Test: SQL injection patterns at boundaries
def sql_boundary_select(conn, val: str):
    """SELECT with f-string — standard pattern."""
    conn.execute(f"SELECT * FROM t WHERE x = '{val}'")  # sql-injection


def sql_boundary_insert(conn, val: str):
    """INSERT with f-string."""
    conn.execute(f"INSERT INTO t VALUES ('{val}')")  # sql-injection


def sql_boundary_update(conn, val: str):
    """UPDATE with f-string."""
    conn.execute(f"UPDATE t SET x = '{val}'")  # sql-injection


def sql_boundary_delete(conn, val: str):
    """DELETE with f-string."""
    conn.execute(f"DELETE FROM t WHERE x = '{val}'")  # sql-injection


# ── Section 10: Subprocess — creative patterns ──────────────────────

def subprocess_via_sh(cmd: str):
    """Subprocess via /bin/sh -c."""
    subprocess.run(["/bin/sh", "-c", cmd])  # command injection via -c


def subprocess_via_bash(cmd: str):
    """Subprocess via bash -c."""
    subprocess.run(["/bin/bash", "-c", cmd])  # command injection via -c


def subprocess_via_python(code: str):
    """Subprocess running Python code."""
    subprocess.run([sys.executable, "-c", code])  # arbitrary Python execution


def subprocess_pipe_chain(cmd1: str, cmd2: str):
    """Two subprocesses piped together."""
    p1 = subprocess.Popen(
        cmd1,
        shell=True,  # shell-true
        stdout=subprocess.PIPE,
    )
    p2 = subprocess.Popen(
        cmd2,
        shell=True,  # shell-true
        stdin=p1.stdout,
        stdout=subprocess.PIPE,
    )
    return p2.communicate()[0]


# ── Section 11: Weak hash — HMAC with weak algorithms ───────────────

def hmac_md5(key: bytes, message: bytes) -> str:
    """HMAC with MD5 — weak algorithm."""
    return hmac.new(key, message, hashlib.md5).hexdigest()  # weak-hash in HMAC


def hmac_sha1(key: bytes, message: bytes) -> str:
    """HMAC with SHA1 — weak algorithm."""
    return hmac.new(key, message, hashlib.sha1).hexdigest()  # weak-hash in HMAC


def double_md5(data: str) -> str:
    """Double MD5 — still weak."""
    first = hashlib.md5(data.encode()).hexdigest()  # weak-hash
    return hashlib.md5(first.encode()).hexdigest()  # weak-hash


# ── Section 12: Mixed chains — production-realistic ──────────────────

def webhook_handler(payload: bytes, signature: str, secret: str):
    """Webhook handler — timing-unsafe signature verification."""
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    if signature != expected:  # timing attack on signature
        raise ValueError("Invalid signature")
    data = json.loads(payload)
    if "callback_url" in data:
        import requests  # type: ignore
        requests.post(data["callback_url"], json={"status": "ok"})  # ssrf-risk


def api_key_auth(request_headers: dict, db_path: str):
    """API key auth with SQL injection + timing attack."""
    api_key = request_headers.get("X-API-Key", "")
    conn = sqlite3.connect(db_path)
    row = conn.execute(
        f"SELECT user_id FROM api_keys WHERE key = '{api_key}'"  # sql-injection
    ).fetchone()
    return row is not None


def process_upload(filename: str, content: bytes, db_path: str):
    """File upload with path traversal + SQL injection + command injection."""
    # Path traversal
    safe_name = filename.replace("..", "")  # insufficient sanitization
    dest = Path("/uploads") / safe_name
    dest.write_bytes(content)

    # Log to database — SQL injection
    conn = sqlite3.connect(db_path)
    conn.execute(f"INSERT INTO uploads (name) VALUES ('{filename}')")  # sql-injection
    conn.commit()

    # Generate thumbnail — command injection
    if filename.endswith((".jpg", ".png")):
        subprocess.run(
            f"convert /uploads/{safe_name} -resize 128x128 /uploads/thumb_{safe_name}",
            shell=True,  # shell-true with user filename
        )
