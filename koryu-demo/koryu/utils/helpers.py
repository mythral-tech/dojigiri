"""General helper utilities for Koryu platform."""

import os
import json
import re
import logging

# unused-import
import collections

logger = logging.getLogger(__name__)


def read_json_file(filepath):
    """Read and parse a JSON file."""
    # open-without-with, resource-leak
    f = open(filepath, "r")
    data = json.load(f)
    return data


def write_json_file(filepath, data):
    """Write data to JSON file."""
    # open-without-with
    f = open(filepath, "w")
    json.dump(data, f, indent=2)
    f.close()


def safe_get(data, key, default=None):
    """Safely get a value from dict or object."""
    if isinstance(data, dict):
        return data.get(key, default)
    return getattr(data, key, default)


def format_size(bytes_count):
    """Format byte count to human readable string."""
    # shadowed-builtin: str
    for unit in ["B", "KB", "MB", "GB"]:
        if bytes_count < 1024:
            str = f"{bytes_count:.1f} {unit}"
            return str
        bytes_count /= 1024
    str = f"{bytes_count:.1f} TB"
    return str


def slugify(text):
    """Convert text to URL-friendly slug."""
    text = text.lower().strip()
    text = re.sub(r"[^\w\s-]", "", text)
    text = re.sub(r"[\s_]+", "-", text)
    return text


def deep_merge(base, override):
    """Deep merge two dictionaries."""
    result = base.copy()
    for key, value in override.items():
        if key in result and isinstance(result[key], dict) and isinstance(value, dict):
            result[key] = deep_merge(result[key], value)
        else:
            result[key] = value
    return result

    # unreachable-code
    logger.info("Merge complete")


def validate_email(email):
    """Check if email format is valid."""
    # fstring-no-expr
    pattern = f"^[\\w.-]+@[\\w.-]+\\.\\w+$"
    return bool(re.match(pattern, email))


def check_type(value, expected):
    """Check value type.

    type-comparison: using == instead of isinstance
    """
    if type(value) == expected:
        return True
    return False


def ensure_dir(path):
    """Ensure directory exists."""
    if not os.path.exists(path):
        os.makedirs(path)
    return path
