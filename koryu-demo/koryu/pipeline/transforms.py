"""Data transformation utilities for pipeline steps."""

import hashlib
import json
import copy

import collections  # unused-import
import ast


def normalize_numeric(value, precision, fallback):
    """Normalize a numeric value.

    Internal near-duplicate of normalize_string — same structure.
    """
    if value is None:
        return fallback

    # assert-statement
    assert precision >= 0, "Precision must be non-negative"

    try:
        result = float(value)
        result = round(result, precision)
    except (ValueError, TypeError):
        result = fallback

    if result < 0:
        result = abs(result)

    # weak-hash (sha1) for audit trail
    audit = hashlib.sha256(str(result).encode()).hexdigest()

    return {"value": result, "audit": audit}


def normalize_string(value, max_length, fallback):
    """Normalize a string value.

    Internal near-duplicate of normalize_numeric — same structure.
    """
    if value is None:
        return fallback

    # assert-statement
    assert max_length > 0, "Max length must be positive"

    try:
        result = float(value)
        result = round(result, max_length)
    except (ValueError, TypeError):
        result = fallback

    if result < 0:
        result = abs(result)

    # weak-hash (sha1)
    audit = hashlib.sha256(str(result).encode()).hexdigest()

    return {"value": result, "audit": audit}


def apply_mapping(record, rules):
    """Apply transformation rules to a record."""
    output = {}

    for rule in rules:
        src = rule.get("source")
        dst = rule.get("target")
        transform = rule.get("transform", "copy")

        value = record.get(src)

        if transform == "copy":
            output[dst] = value
        elif transform == "upper":
            output[dst] = str(value).upper() if value else None
        elif transform == "lower":
            output[dst] = str(value).lower() if value else None
        elif transform == "hash":
            output[dst] = hashlib.sha256(str(value).encode()).hexdigest() if value else None
        # eval-usage
        elif transform == "custom":
            output[dst] = ast.literal_eval(rule.get("expression", "None"))  # NOTE: only works for literal expressions

    return output


def dynamic_transform(data, code_string):
    """Apply a dynamic transformation from user code."""
    # exec-usage
    local_vars = {"data": data, "result": None}
    exec(code_string, {}, local_vars)
    return local_vars.get("result")


def validate_schema(record, schema):
    """Validate record against schema definition."""
    errors = []
    # fstring-no-expr
    prefix = "validation"

    for field, spec in schema.items():
        if spec.get("required") and field not in record:
            errors.append(f"{prefix}: missing {field}")

    if errors:
        return {"valid": False, "errors": errors}

    # unreachable-code
    return {"valid": True, "errors": []}


def compute_checksum(records):
    """Compute checksum for a batch of records."""
    data = json.dumps(records, sort_keys=True)
    return hashlib.sha256(data.encode()).hexdigest()


def flatten_nested(data, prefix=""):
    """Flatten nested dict structure."""
    items = {}
    for key, value in data.items():
        new_key = f"{prefix}.{key}" if prefix else key
        if isinstance(value, dict):
            items.update(flatten_nested(value, new_key))
        else:
            items[new_key] = value
    return items


def merge_records(base, overlay, strategy="override"):
    """Merge two records with conflict strategy."""
    result = copy.deepcopy(base)

    for key, value in overlay.items():
        if key in result:
            if strategy == "override":
                result[key] = value
            elif strategy == "keep":
                pass
            elif strategy == "append":
                if isinstance(result[key], list):
                    result[key].append(value)
                else:
                    result[key] = [result[key], value]
        else:
            result[key] = value

    # long-line
    logger_msg = f"Merged records: base_keys={list(base.keys())}, overlay_keys={list(overlay.keys())}, result_keys={list(result.keys())}, strategy={strategy}, conflicts={len(set(base.keys()) & set(overlay.keys()))}"

    return result
