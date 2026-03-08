"""Fold 23: Web framework vulnerability patterns.

Focus on Django/Flask-specific issues: DEBUG=True in production, SECRET_KEY
hardcoded, raw SQL in views, mark_safe with user input, mass assignment,
CSRF exemptions, unsafe file uploads, session config, clickjacking headers,
ALLOWED_HOSTS wildcards, and mixed chains with ORM bypass.
"""

import os
import re
import sys
import json
import hmac
import hashlib
import logging
import sqlite3
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Section 1: Django DEBUG and SECRET_KEY ───────────────────────────

# Django settings patterns
DEBUG = True  # django-debug-true — never in production

SECRET_KEY = "django-insecure-x7&q2m#f8k^j!@9p4z5w6v3b1n0c"  # hardcoded-secret

ALLOWED_HOSTS = ["*"]  # django-allowed-hosts-wildcard

# Middleware missing security headers
MIDDLEWARE = [
    "django.middleware.common.CommonMiddleware",
    "django.contrib.sessions.middleware.SessionMiddleware",
    # Missing: SecurityMiddleware, XFrameOptionsMiddleware, CsrfViewMiddleware
]

# Insecure session settings
SESSION_COOKIE_SECURE = False  # session over HTTP
SESSION_COOKIE_HTTPONLY = False  # accessible to JS
CSRF_COOKIE_SECURE = False  # CSRF token over HTTP


# ── Section 2: Flask debug mode and secret ───────────────────────────

def create_flask_app():
    """Flask app with debug=True and hardcoded secret."""
    from flask import Flask
    app = Flask(__name__)
    app.secret_key = "flask-secret-key-hardcoded-2024"  # hardcoded-secret
    app.debug = True  # flask-debug-true — RCE via debugger
    return app


def run_flask_debug():
    """Flask run with debug=True."""
    from flask import Flask
    app = Flask(__name__)
    app.run(host="0.0.0.0", debug=True)  # bind-all + debug


def flask_config_from_env():
    """Flask with hardcoded fallback secret."""
    from flask import Flask
    app = Flask(__name__)
    app.config["SECRET_KEY"] = os.environ.get(
        "FLASK_SECRET", "fallback-secret-not-really-secret"  # hardcoded fallback
    )
    return app


# ── Section 3: Django mark_safe / SafeString abuse ───────────────────

def render_user_html(user_input: str) -> str:
    """mark_safe with user input — XSS."""
    from django.utils.safestring import mark_safe
    return mark_safe(f"<div>{user_input}</div>")  # django-mark-safe — XSS


def render_comment(comment_text: str) -> str:
    """mark_safe on user comment."""
    from django.utils.safestring import mark_safe
    formatted = f"<p class='comment'>{comment_text}</p>"
    return mark_safe(formatted)  # django-mark-safe — XSS


def render_user_bio(bio: str) -> str:
    """format_html is safe but mark_safe is not."""
    from django.utils.safestring import mark_safe
    # Should use format_html() instead
    return mark_safe("<div class='bio'>" + bio + "</div>")  # django-mark-safe


# ── Section 4: Django raw SQL / .extra() ─────────────────────────────

def django_raw_sql(user_id: str):
    """Django raw SQL — injection."""
    from django.db import connection
    with connection.cursor() as cursor:
        cursor.execute(
            f"SELECT * FROM auth_user WHERE id = {user_id}"  # sql-injection
        )
        return cursor.fetchall()


def django_raw_manager(search: str):
    """Model.objects.raw with interpolation."""
    from django.contrib.auth.models import User
    return User.objects.raw(
        f"SELECT * FROM auth_user WHERE username LIKE '%{search}%'"  # sql-injection
    )


def django_extra_where(field: str, value: str):
    """QuerySet.extra with user input."""
    from django.contrib.auth.models import User
    return User.objects.extra(
        where=[f"{field} = '{value}'"]  # django-extra-sql
    )


def django_extra_select(expr: str):
    """QuerySet.extra select with user input."""
    from django.contrib.auth.models import User
    return User.objects.extra(
        select={"custom": expr}  # django-extra-sql — arbitrary SQL expression
    )


# ── Section 5: CSRF exemptions ──────────────────────────────────────

def csrf_exempt_view(request):
    """View with CSRF exemption — should be rare."""
    from django.views.decorators.csrf import csrf_exempt

    @csrf_exempt  # csrf-exempt — disables CSRF protection
    def my_view(request):
        # Process POST without CSRF token
        data = request.POST.get("data")
        return {"status": "ok", "data": data}

    return my_view(request)


def csrf_exempt_api(request):
    """API view without CSRF — common but still flaggable."""
    from django.views.decorators.csrf import csrf_exempt

    @csrf_exempt
    def api_endpoint(request):
        body = json.loads(request.body)
        return body

    return api_endpoint(request)


# ── Section 6: Flask SQL injection patterns ──────────────────────────

def flask_sql_query(search_term: str):
    """Flask view with raw SQL."""
    from flask import g
    db = g.db
    results = db.execute(
        f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"  # sql-injection
    ).fetchall()
    return results


def flask_sql_insert(name: str, email: str):
    """Flask insert with f-string."""
    from flask import g
    g.db.execute(
        f"INSERT INTO users (name, email) VALUES ('{name}', '{email}')"  # sql-injection
    )
    g.db.commit()


# ── Section 7: Unsafe file upload handling ───────────────────────────

def save_upload_no_validation(upload_file, upload_dir: str):
    """Save uploaded file without validation."""
    filename = upload_file.filename  # user-controlled filename
    # No extension check, no content-type check, no size limit
    filepath = os.path.join(upload_dir, filename)  # path traversal via filename
    upload_file.save(filepath)
    return filepath


def save_upload_weak_check(upload_file, upload_dir: str):
    """Upload with bypassable extension check."""
    filename = upload_file.filename
    # Only checks extension — trivially bypassable (file.php.jpg, file.php%00.jpg)
    if not filename.endswith((".jpg", ".png", ".gif")):
        raise ValueError("Invalid file type")
    filepath = os.path.join(upload_dir, filename)
    upload_file.save(filepath)
    return filepath


def serve_file_direct(filename: str) -> bytes:
    """Serve file by user-provided name — path traversal."""
    filepath = os.path.join("/uploads", filename)  # path traversal
    return open(filepath, "rb").read()  # open-without-with


# ── Section 8: Jinja2 template injection ─────────────────────────────

def render_from_string(template_str: str, context: dict) -> str:
    """Jinja2 from_string — SSTI if template is user-controlled."""
    from jinja2 import Environment
    env = Environment()
    template = env.from_string(template_str)  # ssti-risk
    return template.render(**context)


def render_template_string_flask(template: str, **kwargs) -> str:
    """Flask render_template_string — SSTI."""
    from flask import render_template_string
    return render_template_string(template, **kwargs)  # ssti-risk


def unsafe_template_format(template: str, user_data: dict) -> str:
    """str.format with user-controlled template — SSTI."""
    return template.format(**user_data)  # ssti via format — can access __class__ etc


# ── Section 9: Pickle in web context ─────────────────────────────────

import pickle

def deserialize_cookie(cookie_value: str) -> dict:
    """Deserialize cookie with pickle — RCE."""
    import base64
    data = base64.b64decode(cookie_value)
    return pickle.loads(data)  # pickle-unsafe — from user cookie


def deserialize_session(session_data: bytes) -> dict:
    """Deserialize session with pickle."""
    return pickle.loads(session_data)  # pickle-unsafe — from session store


def cache_get_pickle(cache_key: str, cache_backend) -> Any:
    """Cache get with pickle deserialization."""
    raw = cache_backend.get(cache_key)
    if raw:
        return pickle.loads(raw)  # pickle-unsafe — from cache
    return None


# ── Section 10: Command injection in web handlers ────────────────────

def ping_host(hostname: str) -> str:
    """Ping via subprocess — command injection."""
    result = subprocess.run(
        f"ping -c 3 {hostname}",
        shell=True,  # shell-true — injection via hostname
        capture_output=True,
        text=True,
    )
    return result.stdout


def dns_lookup(domain: str) -> str:
    """DNS lookup via shell."""
    result = subprocess.run(
        f"nslookup {domain}",
        shell=True,  # shell-true
        capture_output=True,
        text=True,
    )
    return result.stdout


def whois_lookup(domain: str) -> str:
    """Whois via shell."""
    return subprocess.check_output(
        f"whois {domain}", shell=True, text=True  # shell-true
    )


def convert_image(input_path: str, output_path: str) -> None:
    """ImageMagick via shell — injection."""
    os.system(f"convert {input_path} {output_path}")  # os-system


# ── Section 11: Hardcoded credentials in web config ──────────────────

# Database config with hardcoded credentials
DATABASES = {
    "default": {
        "ENGINE": "django.db.backends.postgresql",
        "NAME": "production_db",
        "USER": "db_admin",
        "PASSWORD": "PostgresProd2024!Secure",  # hardcoded-secret in DATABASES
        "HOST": "db.production.internal",
        "PORT": "5432",
    }
}

# Cache config with hardcoded auth
CACHES = {
    "default": {
        "BACKEND": "django.core.cache.backends.memcached.PyMemcacheCache",
        "LOCATION": "cache.internal:11211",
        "OPTIONS": {
            "password": "MemcacheSecret2024!",  # hardcoded-secret
        },
    }
}

# Email config
EMAIL_HOST_PASSWORD = "SmtpPassword2024!"  # hardcoded-secret


# ── Section 12: Eval/exec in web context ─────────────────────────────

def eval_calculator(expression: str) -> float:
    """Calculator endpoint using eval — RCE."""
    return eval(expression)  # eval-usage — arbitrary code via "calculator"


def eval_filter(queryset, filter_expr: str):
    """Dynamic filter via eval."""
    return eval(f"queryset.filter({filter_expr})")  # eval-usage


def exec_migration(migration_code: str):
    """Run migration code via exec."""
    exec(migration_code)  # exec-usage — arbitrary migration code


def eval_json_transform(data: dict, transform: str) -> Any:
    """Transform JSON via eval — SSTI/RCE hybrid."""
    return eval(transform, {"data": data})  # eval-usage with data context


# ── Section 13: Weak hashing for auth tokens ────────────────────────

def generate_reset_token(email: str) -> str:
    """Password reset token with MD5 — predictable."""
    return hashlib.md5(  # weak-hash
        f"{email}:{os.getpid()}".encode()
    ).hexdigest()


def generate_api_key(user_id: int) -> str:
    """API key with SHA1 — weak."""
    return hashlib.sha1(  # weak-hash
        f"apikey:{user_id}:{SECRET_KEY}".encode()
    ).hexdigest()


def verify_webhook_signature(payload: bytes, signature: str, secret: str) -> bool:
    """Webhook verification with timing attack."""
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return signature == expected  # timing attack — use hmac.compare_digest


# ── Section 14: Mixed web service chain ──────────────────────────────

class AdminDashboard:
    """Admin dashboard with vulnerability chain."""

    ADMIN_SECRET = "admin-dashboard-secret-key-2024"  # hardcoded-secret

    def __init__(self, db_path: str = "admin.db"):
        self.conn = sqlite3.connect(db_path)

    def authenticate(self, username: str, password: str) -> bool:
        """Auth with SQL injection + weak hash + timing."""
        pw_hash = hashlib.md5(password.encode()).hexdigest()  # weak-hash
        row = self.conn.execute(
            f"SELECT password_hash FROM admins WHERE username = '{username}'"  # sql-injection
        ).fetchone()
        if row:
            return row[0] == pw_hash  # timing attack
        return False

    def search_users(self, query: str):
        """User search with SQL injection."""
        return self.conn.execute(
            f"SELECT * FROM users WHERE name LIKE '%{query}%' OR email LIKE '%{query}%'"  # sql-injection
        ).fetchall()

    def export_data(self, table: str, format_type: str) -> str:
        """Export data — SQL injection + command injection."""
        rows = self.conn.execute(
            f"SELECT * FROM {table}"  # sql-injection
        ).fetchall()
        if format_type == "csv":
            path = f"/tmp/export_{table}.csv"  # hardcoded-tmp
            with open(path, "w") as f:
                for row in rows:
                    f.write(",".join(str(c) for c in row) + "\n")
            return path
        elif format_type == "custom":
            # Command injection via table name
            subprocess.run(
                f"pg_dump -t {table} production_db > /tmp/dump_{table}.sql",
                shell=True,  # shell-true
            )
            return f"/tmp/dump_{table}.sql"

    def run_report(self, report_code: str) -> Any:
        """Run custom report — exec."""
        namespace = {"conn": self.conn, "os": os}
        exec(report_code, namespace)  # exec-usage
        return namespace.get("result")

    def render_notification(self, message: str) -> str:
        """Render notification — mark_safe equivalent."""
        from django.utils.safestring import mark_safe
        return mark_safe(f"<div class='alert'>{message}</div>")  # django-mark-safe
