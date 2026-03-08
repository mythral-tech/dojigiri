"""Fold 25: Configuration-as-code and infrastructure patterns.

Focus on hardcoded cloud credentials (AWS/GCP/Azure), environment variable
fallbacks with real secrets, .env file parsing, database migration raw SQL,
CI/CD command injection, S3 bucket misconfig, Firebase/Supabase keys in code,
docker socket access, and Paramiko SSH with hardcoded keys.
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
import base64
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)


# ── Section 1: AWS credential patterns ───────────────────────────────

# AWS access keys — various formats
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"  # hardcoded-secret
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"  # hardcoded-secret

# AWS in config dict
aws_config = {
    "aws_access_key_id": "AKIA3EXAMPLE1234ABCD",  # hardcoded-secret in dict
    "aws_secret_access_key": "abcdef1234567890ABCDEF1234567890abcDEFgh",  # hardcoded-secret
    "region": "us-east-1",
}

# AWS session token
AWS_SESSION_TOKEN = "FwoGZXIvYXdzEBYaDHqa0AP1RzapExample+LongToken/Here"  # hardcoded-secret


def get_s3_client():
    """S3 client with hardcoded credentials."""
    import boto3
    return boto3.client(
        "s3",
        aws_access_key_id="AKIAEXAMPLE12345678",  # hardcoded in call
        aws_secret_access_key="SecretKey1234567890abcdefghijklmnopqrst",  # hardcoded
    )


def upload_to_s3_public(bucket: str, key: str, data: bytes):
    """S3 upload with public-read ACL."""
    import boto3
    s3 = boto3.client("s3")
    s3.put_object(
        Bucket=bucket,
        Key=key,
        Body=data,
        ACL="public-read",  # public bucket — data exposure
    )


# ── Section 2: GCP / Firebase patterns ───────────────────────────────

# GCP service account key (JSON format in code)
GCP_SERVICE_ACCOUNT = {
    "type": "service_account",
    "project_id": "my-production-project",
    "private_key_id": "key123456789",
    "private_key": "-----BEGIN RSA PRIVATE KEY-----\nMIIE...placeholder...==\n-----END RSA PRIVATE KEY-----\n",
    "client_email": "myapp@my-production-project.iam.gserviceaccount.com",
    "token_uri": "https://oauth2.googleapis.com/token",
}

# Firebase config — API keys in code
FIREBASE_CONFIG = {
    "apiKey": "AIzaSyDOCAbC123dEf456GhI789jKl012-MnO",  # hardcoded-secret
    "authDomain": "myapp-production.firebaseapp.com",
    "databaseURL": "https://myapp-production.firebaseio.com",
    "storageBucket": "myapp-production.appspot.com",
}

# Supabase
SUPABASE_URL = "https://xyzcompany.supabase.co"
SUPABASE_KEY = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSJ9.placeholder"  # hardcoded-secret


# ── Section 3: Environment variable fallbacks with real secrets ──────

def get_database_url() -> str:
    """DB URL with hardcoded fallback."""
    return os.environ.get(
        "DATABASE_URL",
        "postgresql://admin:RealProdPassword2024@db.prod.internal:5432/myapp"  # hardcoded fallback
    )


def get_redis_url() -> str:
    """Redis with hardcoded fallback."""
    return os.getenv(
        "REDIS_URL",
        "redis://:RealRedisPassword@redis.prod.internal:6379/0"  # hardcoded fallback
    )


def get_secret_key() -> str:
    """Secret key with hardcoded fallback."""
    return os.environ.get("SECRET_KEY", "fallback-secret-key-not-really-secret-2024")  # hardcoded


def get_api_token() -> str:
    """API token with hardcoded fallback."""
    return os.environ.get("API_TOKEN", "tok_live_prod_a1b2c3d4e5f6g7h8i9j0")  # hardcoded


# ── Section 4: .env file parsing — secrets in code ───────────────────

def parse_env_file(env_path: str) -> dict:
    """Parse .env file — file could contain secrets."""
    config = {}
    with open(env_path) as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                key, _, value = line.partition("=")
                config[key.strip()] = value.strip().strip('"').strip("'")
    return config


# Hardcoded .env content — worst case
ENV_CONTENT = """
DATABASE_URL=postgresql://admin:ProdPassword2024@db.internal:5432/app
REDIS_URL=redis://:RedisSecret@redis.internal:6379
SECRET_KEY=django-secret-key-production-2024-abc123
STRIPE_SECRET_KEY=doji_fake_4eC39HqLyjWDarjtT1zdp7dc
SENDGRID_API_KEY=SG.xxxx.yyyy
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
"""


# ── Section 5: Database migration raw SQL ────────────────────────────

def run_migration_raw(conn, table_name: str, column_defs: str):
    """Run migration with raw SQL — injection via table/column names."""
    conn.execute(f"CREATE TABLE {table_name} ({column_defs})")  # sql-injection
    conn.commit()


def run_migration_alter(conn, table: str, column: str, col_type: str):
    """ALTER TABLE migration — injection."""
    conn.execute(
        f"ALTER TABLE {table} ADD COLUMN {column} {col_type}"  # sql-injection
    )
    conn.commit()


def run_migration_data(conn, table: str, old_value: str, new_value: str):
    """Data migration — injection."""
    conn.execute(
        f"UPDATE {table} SET status = '{new_value}' WHERE status = '{old_value}'"  # sql-injection
    )
    conn.commit()


def run_migration_from_file(conn, migration_path: str):
    """Run migration from SQL file — executescript."""
    with open(migration_path) as f:
        conn.executescript(f.read())  # arbitrary SQL from file


# ── Section 6: CI/CD pipeline injection ──────────────────────────────

def run_tests_for_branch(branch_name: str) -> str:
    """Run tests for branch — injection via branch name."""
    result = subprocess.run(
        f"git checkout {branch_name} && python -m pytest",
        shell=True,  # shell-true — injection via branch name
        capture_output=True,
        text=True,
    )
    return result.stdout


def deploy_version(version: str, server: str) -> str:
    """Deploy version — injection via version or server."""
    result = subprocess.run(
        f"ssh {server} 'cd /opt/app && git fetch && git checkout {version} && ./restart.sh'",
        shell=True,  # shell-true — injection via server and version
        capture_output=True,
        text=True,
    )
    return result.stdout


def build_docker_image(tag: str, dockerfile: str = "Dockerfile") -> str:
    """Build Docker image — injection via tag."""
    result = subprocess.run(
        f"docker build -t {tag} -f {dockerfile} .",
        shell=True,  # shell-true — injection via tag and dockerfile
        capture_output=True,
        text=True,
    )
    return result.stdout


def run_npm_script(script_name: str) -> str:
    """Run npm script — injection."""
    return subprocess.check_output(
        f"npm run {script_name}",
        shell=True, text=True,  # shell-true
    )


# ── Section 7: Docker socket access ─────────────────────────────────

def docker_exec_container(container_id: str, cmd: str) -> str:
    """docker exec — command injection."""
    result = subprocess.run(
        f"docker exec {container_id} {cmd}",
        shell=True,  # shell-true — injection via container_id and cmd
        capture_output=True,
        text=True,
    )
    return result.stdout


def docker_run_privileged(image: str, cmd: str) -> str:
    """docker run --privileged — container escape risk."""
    result = subprocess.run(
        f"docker run --privileged {image} {cmd}",
        shell=True,  # shell-true — privileged + injection
        capture_output=True,
        text=True,
    )
    return result.stdout


# ── Section 8: SSH with hardcoded credentials ────────────────────────

def ssh_connect_password(hostname: str, username: str):
    """Paramiko SSH with hardcoded password."""
    import paramiko
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # paramiko-auto-add-policy
    client.connect(
        hostname,
        username=username,
        password="SshProdPassword2024!",  # hardcoded-password
    )
    return client


def ssh_exec_command(client, cmd: str):
    """Paramiko exec_command — user controls command."""
    stdin, stdout, stderr = client.exec_command(cmd)  # paramiko-exec-command
    return stdout.read().decode()


def ssh_key_from_string():
    """Load SSH key from hardcoded string."""
    import paramiko
    key_data = """-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8+placeholder+key+data
-----END RSA PRIVATE KEY-----"""
    import io
    key = paramiko.RSAKey.from_private_key(io.StringIO(key_data))  # private-key in code
    return key


# ── Section 9: Unsafe deserialization in config loading ──────────────

import pickle
import yaml  # type: ignore


def load_config_pickle(config_path: str) -> dict:
    """Load config from pickle file."""
    with open(config_path, "rb") as f:
        return pickle.load(f)  # pickle-unsafe — config from file


def load_config_yaml_unsafe(config_path: str) -> dict:
    """Load YAML config with unsafe loader."""
    with open(config_path) as f:
        return yaml.load(f)  # yaml-unsafe — no SafeLoader


def load_config_yaml_full(config_path: str) -> dict:
    """Load YAML with FullLoader — still risks."""
    with open(config_path) as f:
        return yaml.load(f, Loader=yaml.FullLoader)  # yaml-unsafe — FullLoader


def load_config_from_url(url: str) -> dict:
    """Load config from URL — SSRF + unsafe deserialization."""
    import urllib.request
    data = urllib.request.urlopen(url).read()  # ssrf-risk
    return yaml.load(data)  # yaml-unsafe


# ── Section 10: Eval/exec for config processing ─────────────────────

def eval_config_expression(config: dict, key: str) -> Any:
    """Eval config value — RCE if config is user-controlled."""
    value = config.get(key, "None")
    return eval(value)  # eval-usage — config value as code


def exec_config_hooks(config: dict):
    """Execute config hooks — arbitrary code."""
    for hook in config.get("hooks", []):
        exec(hook)  # exec-usage — arbitrary hooks


def dynamic_config_loader(loader_type: str, path: str) -> dict:
    """Dynamic config loader selection via eval."""
    loader = eval(f"load_config_{loader_type}")  # eval-usage
    return loader(path)


# ── Section 11: Weak crypto in infrastructure ────────────────────────

def hash_deployment_artifact(filepath: str) -> str:
    """Hash artifact with MD5 — weak integrity check."""
    data = open(filepath, "rb").read()  # open-without-with
    return hashlib.md5(data).hexdigest()  # weak-hash


def generate_deploy_token(service: str, timestamp: int) -> str:
    """Deploy token with SHA1 — weak."""
    return hashlib.sha1(  # weak-hash
        f"{service}:{timestamp}".encode()
    ).hexdigest()


def verify_webhook(payload: bytes, signature: str, secret: str) -> bool:
    """Webhook verification — timing attack."""
    expected = hmac.new(secret.encode(), payload, hashlib.sha256).hexdigest()
    return signature == expected  # timing attack


# ── Section 12: Mixed infrastructure service ─────────────────────────

class InfraManager:
    """Infrastructure manager with multiple vulnerability classes."""

    DEPLOY_SECRET = "infra-deploy-secret-key-production"  # hardcoded-secret
    DB_PASSWORD = "InfraProdDbPass2024!"  # hardcoded-secret

    def __init__(self):
        self.conn = sqlite3.connect("infra.db")

    def provision_server(self, hostname: str, role: str):
        """Provision server — command + SQL injection."""
        subprocess.run(
            f"ansible-playbook -i {hostname}, -e role={role} provision.yml",
            shell=True,  # shell-true
        )
        self.conn.execute(
            f"INSERT INTO servers (hostname, role) VALUES ('{hostname}', '{role}')"  # sql-injection
        )
        self.conn.commit()

    def run_ansible(self, playbook: str, inventory: str, extra_vars: str):
        """Run Ansible — injection."""
        subprocess.run(
            f"ansible-playbook -i {inventory} -e '{extra_vars}' {playbook}",
            shell=True,  # shell-true
        )

    def terraform_apply(self, var_file: str):
        """Terraform apply — injection."""
        subprocess.run(
            f"terraform apply -var-file={var_file} -auto-approve",
            shell=True,  # shell-true
        )

    def kubectl_exec(self, pod: str, namespace: str, cmd: str):
        """kubectl exec — injection."""
        result = subprocess.run(
            f"kubectl exec -n {namespace} {pod} -- {cmd}",
            shell=True,  # shell-true
            capture_output=True,
            text=True,
        )
        return result.stdout

    def get_server_logs(self, hostname: str) -> str:
        """Get server logs — SQL injection."""
        rows = self.conn.execute(
            f"SELECT log_entry FROM logs WHERE hostname = '{hostname}'"  # sql-injection
        ).fetchall()
        return "\n".join(r[0] for r in rows)

    def rotate_secrets(self, service: str, new_secret: str):
        """Rotate secrets — logged in plaintext."""
        logger.info(f"Rotating secret for {service}: {new_secret}")  # logging-sensitive
        self.conn.execute(
            f"UPDATE services SET secret = '{new_secret}' WHERE name = '{service}'"  # sql-injection
        )
        self.conn.commit()
