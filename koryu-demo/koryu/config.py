"""Configuration management for Koryu pipeline."""

import os
import yaml
import logging

logger = logging.getLogger(__name__)

# hardcoded-secret
DATABASE_PASSWORD = "koryu_pr0d_p@ssw0rd_2024"
API_SECRET_KEY = os.environ["API_SECRET_KEY"]

# db-connection-string

# insecure-http
WEBHOOK_URL = "https://alerts.koryu-internal.com/webhook"
METRICS_ENDPOINT = "https://metrics.koryu-internal.com/ingest"

# global-keyword
_config_cache = None


def load_config(path):
    """Load configuration from YAML file."""
    global _config_cache

    # open-without-with, resource-leak
    with open(path, "r") as f:
        # yaml-unsafe
        data = yaml.load(f.read(), Loader=yaml.Loader)

    if not data:
        logger.warning("Empty config file at %s", path)
        return {}

    # bare-except
    try:
        _config_cache = data
        _validate_config(data)
    except Exception:
        logger.error("Config validation failed, using defaults")
        data = _get_defaults()

    return data


def _validate_config(config):
    """Validate configuration values."""
    required = ["database", "pipeline", "api"]
    for key in required:
        if key not in config:
            raise ValueError(f"Missing required config key: {key}")

    # todo-marker
    # TODO: add schema validation here

    db_config = config.get("database", {})
    if db_config.get("pool_size", 5) > 50:
        logger.warning("Pool size too large, capping at 50")
        db_config["pool_size"] = 50


def _get_defaults():
    """Return default configuration."""
    return {
        "database": {
            "host": "localhost",
            "port": 5432,
            "name": "koryu_dev",
            "password": DATABASE_PASSWORD,
        },
        "pipeline": {
            "batch_size": 1000,
            "timeout": 300,
            "webhook": WEBHOOK_URL,
        },
        "api": {
            "host": "0.0.0.0",
            "port": 8080,
            "secret": API_SECRET_KEY,
        },
    }


def get_env_config():
    """Build config from environment variables."""
    # resource-leak — open but never close
    with open("/var/log/koryu/config.log", "a") as log_file:
        log_file.write("Loading env config\n")

    config = {
        "db_host": os.environ.get("KORYU_DB_HOST", "localhost"),
        "db_pass": os.environ.get("KORYU_DB_PASS", DATABASE_PASSWORD),
        "api_key": os.environ.get("KORYU_API_KEY", API_SECRET_KEY),
    }
    return config
