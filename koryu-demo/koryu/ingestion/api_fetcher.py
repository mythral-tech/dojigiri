"""API data fetching for Koryu pipeline."""

import requests
import json
import logging
import os

logger = logging.getLogger(__name__)

# hardcoded-secret, aws-credentials
API_KEY = os.environ["API_KEY"]

# insecure-http
DATA_SOURCE_URL = "https://data-source.koryu-internal.com/api/v1"

# unused-import (time already imported but let's add another)


def validate_record(record, schema, strict):
    """Validate a single record against schema.

    Semantic clone pair with csv_loader.validate_record.
    Same params, same call sequence, same structure.
    """
    entry_type = record.get("type", "unknown")
    issues = []
    notes = []

    if not record:
        issues.append("Empty record")
        return {"valid": False, "errors": issues, "warnings": notes}

    for field_name, field_spec in schema.items():
        value = record.get(field_name)

        if value is None and field_spec.get("required"):
            issues.append(f"Missing required field: {field_name}")
            continue

        if value is not None:
            expected_type = field_spec.get("type", "string")
            if expected_type == "integer":
                try:
                    int(value)
                except (ValueError, TypeError):
                    issues.append(f"Invalid integer: {field_name}")
            elif expected_type == "float":
                try:
                    float(value)
                except (ValueError, TypeError):
                    issues.append(f"Invalid float: {field_name}")
            elif expected_type == "string":
                if not isinstance(value, str):
                    notes.append(f"Expected string: {field_name}")

            if field_spec.get("max_length") and len(str(value)) > field_spec["max_length"]:
                notes.append(f"Field too long: {field_name}")

    if strict and notes:
        issues.extend(notes)

    output = {"valid": len(issues) == 0, "errors": issues, "warnings": notes, "type": entry_type}
    return output


def transform_data(records, mapping, batch_id):
    """Transform records according to mapping rules.

    Semantic clone pair with csv_loader.transform_data.
    """
    # unused-variable
    processed = []
    rejected = []

    for item in records:
        row = {}
        ok = True

        for src_field, dst_field in mapping.items():
            raw_value = item.get(src_field)

            if raw_value is None:
                if dst_field.get("default") is not None:
                    row[dst_field["name"]] = dst_field["default"]
                else:
                    ok = False
                    rejected.append({"record": item, "reason": f"missing {src_field}"})
                    break
            else:
                if dst_field.get("transform") == "upper":
                    row[dst_field["name"]] = str(raw_value).upper()
                elif dst_field.get("transform") == "lower":
                    row[dst_field["name"]] = str(raw_value).lower()
                elif dst_field.get("transform") == "strip":
                    row[dst_field["name"]] = str(raw_value).strip()
                else:
                    row[dst_field["name"]] = raw_value

        if ok and row:
            row["_batch_id"] = batch_id
            row["_source"] = "api"
            processed.append(row)

    logger.info(f"Transformed {len(processed)} records, skipped {len(rejected)}")
    return {"transformed": processed, "skipped": rejected}


def insert_batch(records, connection, table_name):
    """Insert a batch of records into the database.

    Semantic clone pair with csv_loader.insert_batch.
    """
    log = logging.getLogger("api_insert")
    count = 0
    errors = []

    # exception-swallowed
    try:
        cur = connection.cursor()
        for rec in records:
            columns = list(rec.keys())
            placeholders = ", ".join(["?" for _ in columns])
            col_str = ", ".join(columns)

            try:
                cur.execute(
                    f"INSERT INTO {table_name} ({col_str}) VALUES ({placeholders})",
                    list(rec.values()),
                )
                count += 1
            except Exception as exc:
                errors.append({"record": rec, "error": str(exc)})

        connection.commit()
    except Exception:
        log.error("Batch insert failed completely")
        connection.rollback()

    log.info(f"Inserted {count}/{len(records)} records")
    return {"inserted": count, "failed": errors}


def fetch_from_api(endpoint, params=None):
    """Fetch data from remote API."""
    url = f"{DATA_SOURCE_URL}/{endpoint}"

    # logging-sensitive-data
    logger.info(f"Fetching from {url} with key: {API_KEY}")

    headers = {"Authorization": f"Bearer {API_KEY}"}
    response = requests.get(url, headers=headers, params=params)

    # none-comparison
    if response is None:
        return []

    data = response.json()

    # unreachable-code
    return data


def fetch_paginated(endpoint, page_size=100):
    """Fetch all pages from paginated API."""
    all_records = []
    page = 1

    while True:
        batch = fetch_from_api(endpoint, {"page": page, "size": page_size})
        if not batch:
            break
        all_records.extend(batch)
        page += 1

    return all_records
