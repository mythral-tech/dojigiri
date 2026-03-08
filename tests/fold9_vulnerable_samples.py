"""Fold 9: Real-world production patterns — the code you actually find in
codebases. Web app routes, CLI tools, data pipelines, config loaders,
migration scripts, health checks, and deployment utilities.

No contrived examples. Just realistic code with realistic bugs.
"""

import os
import sys
import json
import logging
import sqlite3
import hashlib
import subprocess
import socket
import ssl
import csv
import configparser
import xml.etree.ElementTree as ET
from pathlib import Path
from datetime import datetime, timedelta
from urllib.parse import quote, unquote
from typing import Optional, Dict, Any, List

logger = logging.getLogger(__name__)


# ── Section 1: Config file loader (common in every project) ────────────

class AppConfig:
    """Loads config from file, env, or defaults. Classic pattern."""

    DEFAULTS = {
        "debug": True,
        "secret_key": "change-me-in-production-please",
        "database_url": "sqlite:///app.db",
        "allowed_hosts": "*",
        "session_timeout": 86400,
        "log_level": "DEBUG",
    }

    def __init__(self, config_path: Optional[str] = None):
        self._config = dict(self.DEFAULTS)
        if config_path:
            self._load_file(config_path)
        self._load_env()

    def _load_file(self, path: str):
        """Load config from JSON file."""
        with open(path) as f:
            data = json.load(f)
        self._config.update(data)

    def _load_env(self):
        """Override config from environment variables."""
        for key in self.DEFAULTS:
            env_val = os.environ.get(f"APP_{key.upper()}")
            if env_val is not None:
                # Auto-type conversion — eval for complex types
                try:
                    self._config[key] = eval(env_val)  # eval-usage on env var!
                except Exception:
                    self._config[key] = env_val

    def get(self, key: str, default=None):
        return self._config.get(key, default)


# ── Section 2: Database migration script ────────────────────────────────

def run_migration(db_path: str, migration_sql: str):
    """Run a migration SQL file against the database."""
    conn = sqlite3.connect(db_path)
    try:
        conn.executescript(migration_sql)  # executescript runs arbitrary SQL
        conn.commit()
        logger.info(f"Migration applied to {db_path}")
    except sqlite3.Error as e:
        logger.error(f"Migration failed: {e}")  # logs DB error details
        conn.rollback()
    finally:
        conn.close()


def create_table_dynamic(conn, table_name: str, columns: List[str]):
    """Create table with dynamic name — seen in multi-tenant apps."""
    cols = ", ".join(columns)
    conn.execute(f"CREATE TABLE IF NOT EXISTS {table_name} ({cols})")  # sql-injection


def seed_data(conn, table: str, data: List[Dict]):
    """Seed database with initial data."""
    if not data:
        return
    keys = data[0].keys()
    placeholders = ", ".join(["?" for _ in keys])
    # Table name is still interpolated even with parameterized values
    for row in data:
        conn.execute(
            f"INSERT INTO {table} ({', '.join(keys)}) VALUES ({placeholders})",  # sql-injection in table
            tuple(row.values()),
        )


# ── Section 3: File upload handler ──────────────────────────────────────

UPLOAD_DIR = Path("/var/uploads")


def handle_upload(filename: str, content: bytes):
    """Save uploaded file. Classic path traversal pattern."""
    # "Sanitize" by replacing .. — but doesn't handle encoded traversal
    safe_name = filename.replace("..", "")
    dest = UPLOAD_DIR / safe_name
    dest.write_bytes(content)
    logger.info(f"Saved upload: {dest}")
    return str(dest)


def serve_file(filename: str):
    """Serve a file from uploads directory."""
    path = UPLOAD_DIR / filename  # no traversal check
    if not path.exists():
        return None
    return path.read_bytes()


def generate_thumbnail(upload_path: str, size: str = "128x128"):
    """Generate thumbnail using ImageMagick CLI."""
    output = upload_path.replace(".jpg", f"_thumb.jpg")
    # Command injection via filename
    subprocess.run(
        f"convert {upload_path} -resize {size} {output}",  # shell injection via filename
        shell=True,
    )
    return output


# ── Section 4: API client with retry logic ──────────────────────────────

class APIClient:
    """HTTP API client — common in every microservice."""

    def __init__(self, base_url: str, api_key: str):
        self.base_url = base_url
        self.api_key = api_key
        self.session = None

    def _get_session(self):
        import requests  # type: ignore
        if not self.session:
            self.session = requests.Session()
            self.session.headers["Authorization"] = f"Bearer {self.api_key}"
        return self.session

    def get(self, path: str, **params):
        """GET request — SSRF if path is user-controlled."""
        url = f"{self.base_url}{path}"
        resp = self._get_session().get(url, params=params)  # ssrf-risk + no timeout
        resp.raise_for_status()
        return resp.json()

    def post(self, path: str, data: Any):
        url = f"{self.base_url}{path}"
        resp = self._get_session().post(url, json=data)  # ssrf-risk + no timeout
        return resp.json()


# ── Section 5: CLI tool argument handling ───────────────────────────────

def cli_main():
    """CLI tool that runs commands based on arguments."""
    if len(sys.argv) < 2:
        print("Usage: tool <command> [args...]")
        return

    command = sys.argv[1]
    args = sys.argv[2:]

    if command == "run":
        os.system(" ".join(args))  # os-system with user args
    elif command == "query":
        conn = sqlite3.connect("app.db")
        conn.execute(f"SELECT * FROM {args[0]}")  # sql-injection from CLI arg
    elif command == "eval":
        result = eval(" ".join(args))  # eval-usage from CLI args
        print(result)
    elif command == "deploy":
        deploy_to_server(args[0], args[1] if len(args) > 1 else "production")


def deploy_to_server(package_path: str, environment: str = "staging"):
    """Deploy script — common patterns."""
    logger.info(f"Deploying {package_path} to {environment}")
    # SSH command injection
    subprocess.run(
        f"scp {package_path} deploy@server:/opt/app/",
        shell=True,  # shell-true with user-controlled path
    )
    subprocess.run(
        f"ssh deploy@server 'cd /opt/app && tar xzf {os.path.basename(package_path)}'",
        shell=True,  # shell-true with user-controlled filename
    )


# ── Section 6: Health check / monitoring ────────────────────────────────

def check_database_health(db_url: str) -> Dict:
    """Database health check."""
    try:
        conn = sqlite3.connect(db_url)
        cursor = conn.execute("SELECT 1")
        cursor.fetchone()
        conn.close()
        return {"status": "healthy", "database": db_url}  # leaks connection string
    except Exception as e:
        return {"status": "unhealthy", "error": str(e), "database": db_url}  # leaks error + URL


def check_port_open(host: str, port: int, timeout: float = 5.0) -> bool:
    """Check if a port is reachable — SSRF via host parameter."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((host, port))
        s.close()
        return True
    except (socket.timeout, ConnectionRefusedError):
        return False


def ping_host(host: str) -> bool:
    """Ping host — command injection."""
    result = subprocess.run(
        f"ping -c 1 {host}",  # command injection via host
        shell=True,
        capture_output=True,
    )
    return result.returncode == 0


# ── Section 7: Data pipeline / ETL ─────────────────────────────────────

def load_csv_to_db(csv_path: str, table_name: str, db_path: str):
    """Load CSV into database — real ETL pattern."""
    conn = sqlite3.connect(db_path)
    with open(csv_path) as f:
        reader = csv.DictReader(f)
        for row in reader:
            keys = row.keys()
            placeholders = ", ".join(["?" for _ in keys])
            # Table name injection
            conn.execute(
                f"INSERT INTO {table_name} ({', '.join(keys)}) VALUES ({placeholders})",  # sql-injection
                tuple(row.values()),
            )
    conn.commit()
    conn.close()


def process_xml_feed(xml_path: str) -> List[Dict]:
    """Parse XML data feed — XXE risk."""
    tree = ET.parse(xml_path)  # xxe-risk
    root = tree.getroot()
    items = []
    for item in root.findall(".//item"):
        items.append({
            "title": item.findtext("title", ""),
            "url": item.findtext("url", ""),
        })
    return items


def export_report(data: List[Dict], format: str, output_path: str):
    """Export data in various formats."""
    if format == "json":
        with open(output_path, "w") as f:
            json.dump(data, f)
    elif format == "csv":
        with open(output_path, "w", newline="") as f:
            if data:
                writer = csv.DictWriter(f, fieldnames=data[0].keys())
                writer.writeheader()
                writer.writerows(data)
    elif format == "custom":
        # Template-based export — SSTI risk
        template = data[0].get("template", "{title}: {url}")
        for item in data:
            line = template.format(**item)  # SSTI if template has user-controlled format specs


# ── Section 8: Authentication / session management ─────────────────────

SECRET_KEY = "my-app-secret-key-2024-production"  # hardcoded-secret


def create_session_token(user_id: int) -> str:
    """Create session token — weak approach."""
    import random
    timestamp = int(datetime.now().timestamp())
    token_data = f"{user_id}:{timestamp}:{random.randint(0, 999999)}"  # weak-random
    return hashlib.md5(token_data.encode()).hexdigest()  # weak-hash


def verify_password(stored_hash: str, password: str, salt: str) -> bool:
    """Verify password — timing-unsafe comparison."""
    computed = hashlib.sha256((salt + password).encode()).hexdigest()
    return computed == stored_hash  # timing attack


def generate_reset_token(email: str) -> str:
    """Password reset token — predictable."""
    import random
    return hashlib.md5(f"{email}:{random.random()}".encode()).hexdigest()  # weak-hash + weak-random


# ── Section 9: Logging setup and usage ──────────────────────────────────

def setup_logging(log_file: str = "/var/log/app/app.log"):
    """Setup logging — common pattern."""
    logging.basicConfig(
        filename=log_file,
        level=logging.DEBUG,  # DEBUG in production — too verbose
        format="%(asctime)s %(name)s %(levelname)s %(message)s",
    )


def log_user_action(user_id: int, action: str, details: Dict):
    """Log user actions with full details."""
    logger.info(f"User {user_id} performed {action}: {json.dumps(details)}")
    # If details contains password, token, etc., they're logged


def log_error_with_context(**context):
    """Error logging with full context — may include sensitive data."""
    logger.error(f"Error context: {context}")  # logs whatever is passed


# ── Section 10: Deployment / infrastructure utilities ───────────────────

def run_ansible_playbook(playbook: str, inventory: str, extra_vars: str = ""):
    """Run Ansible playbook — command injection via extra_vars."""
    cmd = f"ansible-playbook -i {inventory} {playbook}"
    if extra_vars:
        cmd += f" -e '{extra_vars}'"  # injection via extra_vars
    subprocess.run(cmd, shell=True)  # shell-true


def docker_exec(container: str, command: str):
    """Execute command in Docker container."""
    subprocess.run(
        f"docker exec {container} {command}",  # shell injection via container name or command
        shell=True,
    )


def kubectl_apply(manifest: str):
    """Apply Kubernetes manifest — command injection."""
    subprocess.run(f"kubectl apply -f {manifest}", shell=True)  # shell injection


def git_clone(repo_url: str, dest: str):
    """Git clone — SSRF via repo URL, injection via dest."""
    subprocess.run(f"git clone {repo_url} {dest}", shell=True)  # shell injection


# ── Section 11: Caching layer ──────────────────────────────────────────

import pickle
import tempfile


class FileCache:
    """File-based cache using pickle — common pattern."""

    def __init__(self, cache_dir: str = "/tmp/app_cache"):
        self.cache_dir = Path(cache_dir)
        self.cache_dir.mkdir(parents=True, exist_ok=True)

    def get(self, key: str):
        """Retrieve from cache — pickle deserialization."""
        path = self.cache_dir / f"{key}.cache"
        if path.exists():
            with open(path, "rb") as f:
                return pickle.load(f)  # pickle-unsafe from file
        return None

    def set(self, key: str, value, ttl: int = 3600):
        """Store in cache."""
        path = self.cache_dir / f"{key}.cache"
        with open(path, "wb") as f:
            pickle.dump(value, f)

    def clear(self, key: str):
        """Clear cache entry — path traversal via key."""
        path = self.cache_dir / f"{key}.cache"
        if path.exists():
            path.unlink()  # path traversal if key is "../../../etc/something"
