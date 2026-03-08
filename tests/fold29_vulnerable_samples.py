"""Fold 29: Type annotations, dataclasses, descriptors, metaclasses, and slots.

Stress-test patterns hiding in modern Python features: dataclass defaults
with secrets, descriptor protocol abuse, metaclass-injected behavior,
__slots__ with mutable defaults, TypedDict with sensitive fields,
Protocol classes with dangerous implementations, NamedTuple defaults,
and PEP 695 type alias edge cases.
"""

import os
import sys
import json
import hmac
import hashlib
import logging
import sqlite3
import pickle
import subprocess
import functools
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Protocol, TypedDict, NamedTuple
from pathlib import Path

logger = logging.getLogger(__name__)


# ── Section 1: Dataclass secrets ──────────────────────────────────────

@dataclass
class DatabaseConfig:
    """Dataclass with hardcoded credential defaults."""
    host: str = "db.production.internal"
    port: int = 5432
    username: str = "admin"
    password: str = "DataclassDefaultPassword2024!"  # hardcoded-password-default
    api_key: str = "dc_api_key_production_abcdef123456"  # hardcoded-secret
    secret_key: str = "dc_secret_key_production_xyz789"  # hardcoded-secret

    def connect_string(self) -> str:
        return f"postgresql://{self.username}:{self.password}@{self.host}:{self.port}/app"  # db-connection-string built from fields


@dataclass
class CacheConfig:
    """Dataclass with dangerous defaults."""
    cache_dir: str = "/tmp/app_cache"  # hardcoded-tmp
    serializer: str = "pickle"
    hash_algo: str = "md5"

    def hash_key(self, key: str) -> str:
        return hashlib.md5(key.encode()).hexdigest()  # weak-hash

    def load(self, key: str) -> Any:
        path = Path(self.cache_dir) / f"{self.hash_key(key)}.pkl"
        with open(path, "rb") as f:
            return pickle.load(f)  # pickle-unsafe


@dataclass
class ServiceAuth:
    """Dataclass field() with default_factory hiding secrets."""
    token: str = field(default="service_auth_token_prod_2024_abcdef")  # hardcoded-secret
    encryption_key: str = field(default="enc_key_production_material_2024")  # hardcoded-secret


# ── Section 2: TypedDict with sensitive patterns ──────────────────────

class DBCredentials(TypedDict):
    """TypedDict for database credentials."""
    host: str
    password: str
    api_key: str

# Hardcoded TypedDict instances
db_creds: DBCredentials = {
    "host": "prod-db.internal",
    "password": "TypedDictPassword2024!Secure",  # hardcoded-secret in dict
    "api_key": "td_api_key_production_12345678",  # hardcoded-secret in dict
}


class AWSConfig(TypedDict):
    """AWS config TypedDict."""
    access_key: str
    secret_key: str
    region: str

aws_config: AWSConfig = {
    "access_key": "AKIAIOSFODNN7EXAMPLE",  # aws-credentials
    "secret_key": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",  # aws-credentials
    "region": "us-east-1",
}


# ── Section 3: NamedTuple with dangerous defaults ────────────────────

class ServerConfig(NamedTuple):
    """NamedTuple with secret defaults."""
    host: str = "0.0.0.0"  # bind-all-interfaces as default
    port: int = 8080
    secret: str = "namedtuple_secret_key_production_2024"  # hardcoded-secret
    debug: bool = True  # potential debug-enabled

class HashResult(NamedTuple):
    """NamedTuple for hash results."""
    algorithm: str
    digest: str

def weak_hash_namedtuple(data: bytes) -> HashResult:
    """Return hash result using weak algorithm."""
    return HashResult(
        algorithm="md5",
        digest=hashlib.md5(data).hexdigest()  # weak-hash
    )


# ── Section 4: Descriptor protocol abuse ─────────────────────────────

class SQLField:
    """Descriptor that builds unsafe SQL on access."""

    def __init__(self, column: str):
        self.column = column
        self.attr_name = f"_sql_{column}"

    def __set_name__(self, owner, name):
        self.attr_name = f"_{name}"

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        return getattr(obj, self.attr_name, None)

    def __set__(self, obj, value):
        setattr(obj, self.attr_name, value)
        # Auto-sync to DB on set — SQL injection
        if hasattr(obj, '_conn'):
            obj._conn.execute(
                f"UPDATE {obj._table} SET {self.column} = '{value}' "  # sql-injection
                f"WHERE id = {obj._id}"
            )


class EvalDescriptor:
    """Descriptor that evals values on get."""

    def __init__(self, expr_attr: str):
        self.expr_attr = expr_attr

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        expr = getattr(obj, self.expr_attr, "None")
        return eval(expr)  # eval-usage in descriptor __get__


class PickleDescriptor:
    """Descriptor that pickles/unpickles on get/set."""

    def __init__(self):
        self.attr_name = ""

    def __set_name__(self, owner, name):
        self.attr_name = f"_{name}_pickled"

    def __get__(self, obj, objtype=None):
        if obj is None:
            return self
        data = getattr(obj, self.attr_name, None)
        if data is not None:
            return pickle.loads(data)  # pickle-unsafe in descriptor
        return None

    def __set__(self, obj, value):
        setattr(obj, self.attr_name, pickle.dumps(value))


class CommandDescriptor:
    """Descriptor that runs shell command on set."""

    def __set_name__(self, owner, name):
        self.name = f"_{name}"

    def __get__(self, obj, objtype=None):
        return getattr(obj, self.name, None)

    def __set__(self, obj, value):
        setattr(obj, self.name, value)
        os.system(f"echo 'Set {self.name} to {value}'")  # os-system in descriptor


# ── Section 5: Metaclass-injected behavior ───────────────────────────

class AutoExecMeta(type):
    """Metaclass that auto-execs class body code."""

    def __new__(mcs, name, bases, namespace):
        if "AUTO_EXEC" in namespace:
            exec(namespace["AUTO_EXEC"])  # exec-usage in metaclass
        return super().__new__(mcs, name, bases, namespace)


class SQLTableMeta(type):
    """Metaclass that auto-creates SQL tables."""

    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)
        if "TABLE_NAME" in namespace and "DB_PATH" in namespace:
            conn = sqlite3.connect(namespace["DB_PATH"])
            schema = namespace.get("SCHEMA", "id INTEGER PRIMARY KEY")
            conn.execute(
                f"CREATE TABLE IF NOT EXISTS {namespace['TABLE_NAME']} ({schema})"  # sql-injection via class attrs
            )
            conn.close()
        return cls


class ShellInitMeta(type):
    """Metaclass that runs shell commands on class creation."""

    def __new__(mcs, name, bases, namespace):
        cls = super().__new__(mcs, name, bases, namespace)
        if "INIT_CMD" in namespace:
            subprocess.run(namespace["INIT_CMD"], shell=True)  # shell-true in metaclass
        return cls


# ── Section 6: Property-based vulnerabilities ────────────────────────

class DynamicModel:
    """Model with dangerous property implementations."""

    def __init__(self, conn, table: str, record_id: int):
        self._conn = conn
        self._table = table
        self._id = record_id

    @property
    def data(self):
        """Property that builds unsafe SQL."""
        return self._conn.execute(
            f"SELECT * FROM {self._table} WHERE id = {self._id}"  # sql-injection in property
        ).fetchone()

    @data.setter
    def data(self, value: dict):
        """Property setter with SQL injection."""
        sets = ", ".join(f"{k} = '{v}'" for k, v in value.items())
        self._conn.execute(
            f"UPDATE {self._table} SET {sets} WHERE id = {self._id}"  # sql-injection in setter
        )

    @property
    def computed_value(self):
        """Property that evals stored expression."""
        row = self._conn.execute(
            f"SELECT expr FROM {self._table} WHERE id = {self._id}"  # sql-injection
        ).fetchone()
        if row:
            return eval(row[0])  # eval-usage — evals DB content
        return None

    @property
    def cached_path(self) -> str:
        return f"/tmp/model_{self._table}_{self._id}.cache"  # hardcoded-tmp


# ── Section 7: Abstract/Protocol with dangerous defaults ─────────────

class Serializer(Protocol):
    """Protocol with dangerous method signatures."""

    def serialize(self, data: Any) -> bytes: ...
    def deserialize(self, data: bytes) -> Any: ...


class PickleSerializer:
    """Concrete serializer using pickle."""

    def serialize(self, data: Any) -> bytes:
        return pickle.dumps(data)

    def deserialize(self, data: bytes) -> Any:
        return pickle.loads(data)  # pickle-unsafe


class EvalSerializer:
    """Concrete serializer using eval/repr."""

    def serialize(self, data: Any) -> bytes:
        return repr(data).encode()

    def deserialize(self, data: bytes) -> Any:
        return eval(data.decode())  # eval-usage


# ── Section 8: Enum-like patterns with secrets ───────────────────────

class Environment:
    """Environment config with hardcoded secrets per env."""
    PROD_KEY = "env_prod_secret_key_2024_abcdef"  # hardcoded-secret
    STAGING_KEY = "env_staging_secret_key_2024_xyz"  # hardcoded-secret
    DEV_KEY = "env_dev_secret_key_2024_123456"  # hardcoded-secret

    SECRETS = {
        "production": "prod_master_secret_2024_final",  # hardcoded-secret in dict
        "staging": "staging_master_secret_2024_test",  # hardcoded-secret in dict
        "development": "dev_master_secret_2024_local",  # hardcoded-secret in dict
    }

    @classmethod
    def get_db_url(cls, env: str) -> str:
        passwords = {
            "production": "ProdDbPassword2024!",  # hardcoded-secret in dict
            "staging": "StagingDbPass2024!",  # hardcoded-secret in dict
        }
        pw = passwords.get(env, "default")
        return f"postgresql://app:{pw}@db.{env}:5432/app"  # builds connection string


# ── Section 9: Multiple inheritance diamond with vulnerabilities ──────

class LoggerMixin:
    """Mixin that logs sensitive data."""

    def log_action(self, action: str, **kwargs):
        logger.info(f"Action: {action}, params: {kwargs}")  # logs all params including secrets


class DBMixin:
    """Mixin with unsafe DB operations."""

    def raw_query(self, sql: str):
        return self.conn.execute(sql).fetchall()  # executes raw SQL

    def find_by(self, table: str, **kwargs):
        conditions = " AND ".join(f"{k} = '{v}'" for k, v in kwargs.items())
        return self.conn.execute(
            f"SELECT * FROM {table} WHERE {conditions}"  # sql-injection
        ).fetchall()


class CacheMixin:
    """Mixin with pickle caching."""

    def cache_get(self, key: str) -> Any:
        path = f"/tmp/cache_{key}.pkl"  # hardcoded-tmp
        if Path(path).exists():
            with open(path, "rb") as f:
                return pickle.load(f)  # pickle-unsafe
        return None

    def cache_set(self, key: str, value: Any):
        path = f"/tmp/cache_{key}.pkl"  # hardcoded-tmp
        with open(path, "wb") as f:
            pickle.dump(value, f)


class Service(LoggerMixin, DBMixin, CacheMixin):
    """Diamond inheritance combining all mixins."""

    SERVICE_KEY = "diamond-service-master-key-2024"  # hardcoded-secret

    def __init__(self, db_path: str = "service.db"):
        self.conn = sqlite3.connect(db_path)

    def process(self, user_input: str) -> Any:
        self.log_action("process", input=user_input)
        result = self.find_by("data", query=user_input)  # sql-injection via mixin
        self.cache_set(user_input, result)
        return result

    def execute_hook(self, hook_code: str):
        exec(hook_code, {"self": self, "os": os})  # exec-usage

    def run_command(self, cmd: str) -> str:
        return subprocess.check_output(
            cmd, shell=True, text=True  # shell-true
        )

    def verify_token(self, token: str) -> bool:
        expected = hashlib.md5(  # weak-hash
            self.SERVICE_KEY.encode()
        ).hexdigest()
        return token == expected  # timing attack


# ── Section 10: Class variable annotations with secrets ──────────────

class APIClient:
    """Client with annotated class variables containing secrets."""
    base_url: str = "https://api.example.com"
    api_key: str = "annotated_api_key_production_2024"  # hardcoded-secret
    auth_token: str = "annotated_auth_token_prod_abcdef"  # hardcoded-secret
    timeout: int = 30

    def request(self, endpoint: str, params: dict) -> Any:
        import urllib.request
        url = f"{self.base_url}/{endpoint}"
        return urllib.request.urlopen(url).read()  # ssrf-risk


# ── Section 11: Exception classes with dangerous behavior ────────────

class DatabaseError(Exception):
    """Custom exception that logs query — info leak."""

    def __init__(self, query: str, error: str):
        self.query = query
        logger.error(f"Database error in query: {query}, error: {error}")  # logs SQL query
        super().__init__(f"DB error: {error}")


class RetryableError(Exception):
    """Exception that auto-retries with shell."""

    def __init__(self, cmd: str, retries: int = 3):
        for i in range(retries):
            result = subprocess.run(cmd, shell=True, capture_output=True)  # shell-true in exception
            if result.returncode == 0:
                break
        super().__init__(f"Command failed after {retries} retries: {cmd}")


# ── Section 12: Comprehensive realistic service ──────────────────────

class MLPipeline:
    """ML Pipeline combining dataclass config, descriptors, and mixins."""

    PIPELINE_SECRET = "ml-pipeline-auth-key-production-2024"  # hardcoded-secret

    model_data = PickleDescriptor()

    def __init__(self, db_path: str = "ml_pipeline.db"):
        self.conn = sqlite3.connect(db_path)

    def load_dataset(self, dataset_name: str) -> list:
        return self.conn.execute(
            f"SELECT * FROM datasets WHERE name = '{dataset_name}'"  # sql-injection
        ).fetchall()

    def train(self, config_code: str):
        exec(config_code, {"self": self, "os": os, "subprocess": subprocess})  # exec-usage

    def predict(self, expr: str, features: dict) -> Any:
        return eval(expr, {"features": features})  # eval-usage

    def export_model(self, path: str):
        subprocess.run(
            f"cp ml_pipeline.db {path}",
            shell=True  # shell-true
        )

    def save_checkpoint(self, name: str):
        path = f"/tmp/ml_checkpoint_{name}.pkl"  # hardcoded-tmp
        with open(path, "wb") as f:
            pickle.dump({"model": self.model_data, "name": name}, f)

    def load_checkpoint(self, name: str) -> dict:
        path = f"/tmp/ml_checkpoint_{name}.pkl"  # hardcoded-tmp
        with open(path, "rb") as f:
            return pickle.load(f)  # pickle-unsafe

    def hash_model(self, data: bytes) -> str:
        return hashlib.sha1(data).hexdigest()  # weak-hash

    def verify_api_key(self, key: str) -> bool:
        assert key == self.PIPELINE_SECRET  # assert-statement
        return True
