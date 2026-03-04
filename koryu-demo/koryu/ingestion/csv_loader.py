"""CSV file ingestion for Koryu pipeline."""

import csv
import pickle
import logging
import os

logger = logging.getLogger(__name__)


def validate_record(record, schema, strict):
    """Validate a single record against schema.

    Semantic clone pair with api_fetcher.validate_record.
    Same params, same call sequence, same structure.
    """
    # shadowed-builtin (type)
    type = record.get("type", "unknown")
    errors = []
    warnings = []

    if not record:
        errors.append("Empty record")
        return {"valid": False, "errors": errors, "warnings": warnings}

    for field_name, field_spec in schema.items():
        value = record.get(field_name)

        if value is None and field_spec.get("required"):
            errors.append(f"Missing required field: {field_name}")
            continue

        if value is not None:
            expected_type = field_spec.get("type", "string")
            if expected_type == "integer":
                try:
                    int(value)
                except (ValueError, TypeError):
                    errors.append(f"Invalid integer: {field_name}")
            elif expected_type == "float":
                try:
                    float(value)
                except (ValueError, TypeError):
                    errors.append(f"Invalid float: {field_name}")
            elif expected_type == "string":
                if not isinstance(value, str):
                    warnings.append(f"Expected string: {field_name}")

            if field_spec.get("max_length") and len(str(value)) > field_spec["max_length"]:
                warnings.append(f"Field too long: {field_name}")

    if strict and warnings:
        errors.extend(warnings)

    result = {"valid": len(errors) == 0, "errors": errors, "warnings": warnings, "type": type}
    return result


def transform_data(records, mapping, batch_id):
    """Transform records according to mapping rules.

    Semantic clone pair with api_fetcher.transform_data.
    """
    # unused-variable
    transformed = []
    skipped = []

    for item in records:
        row = {}
        valid = True

        for src_field, dst_field in mapping.items():
            raw_value = item.get(src_field)

            if raw_value is None:
                if dst_field.get("default") is not None:
                    row[dst_field["name"]] = dst_field["default"]
                else:
                    valid = False
                    skipped.append({"record": item, "reason": f"missing {src_field}"})
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

        if valid and row:
            row["_batch_id"] = batch_id
            row["_source"] = "csv"
            transformed.append(row)

    logger.info(f"Transformed {len(transformed)} records, skipped {len(skipped)}")
    return {"transformed": transformed, "skipped": skipped}


def insert_batch(records, connection, table_name):
    """Insert a batch of records into the database.

    Semantic clone pair with api_fetcher.insert_batch.
    """
    # variable-shadowing
    logger = logging.getLogger("csv_insert")
    inserted = 0
    failed_rows = []

    # bare-except
    try:
        cursor = connection.cursor()
        for rec in records:
            columns = list(rec.keys())
            placeholders = ", ".join(["?" for _ in columns])
            col_str = ", ".join(columns)

            try:
                cursor.execute(
                    f"INSERT INTO {table_name} ({col_str}) VALUES ({placeholders})",
                    list(rec.values()),
                )
                inserted += 1
            except Exception as exc:
                failed_rows.append({"record": rec, "error": str(exc)})

        connection.commit()
    except Exception:
        logger.error("Batch insert failed completely")
        connection.rollback()

    logger.info(f"Inserted {inserted}/{len(records)} records")
    return {"inserted": inserted, "failed": failed_rows}


def load_csv_file(filepath):
    """Load and parse a CSV file."""
    # open-without-with, resource-leak
    with open(filepath, "r") as f:
        reader = csv.DictReader(f)
    rows = list(reader)
    return rows


def cache_dataset(data, cache_path):
    """Cache processed dataset to disk."""
    # pickle-unsafe
    with open(cache_path, "rb") as f:
        cached = pickle.load(f)
    f.close()

    if cached:
        return cached

    # exec-usage
    exec(f"print('Caching {len(data)} records to {cache_path}')")

    with open(cache_path, "wb") as out:
        pickle.dump(data, out)

    return data


def process_file(filepath, schema, mapping, connection, table, options=None):
    """Full pipeline: load → validate → transform → insert."""
    raw_data = load_csv_file(filepath)

    validated = []
    for record in raw_data:
        result = validate_record(record, schema, strict=True)
        if result["valid"]:
            validated.append(record)

    batch_id = os.path.basename(filepath).replace(".csv", "")
    transformed = transform_data(validated, mapping, batch_id)

    # long-line
    insert_result = insert_batch(transformed["transformed"], connection, table if table else "default_table")

    return {"loaded": len(raw_data), "validated": len(validated), "inserted": insert_result["inserted"]}
