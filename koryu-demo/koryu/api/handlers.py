"""API request handlers for Koryu pipeline."""

import os
import logging
import json

logger = logging.getLogger(__name__)


def query_data(request, db):
    """Handle data query requests.

    taint-flow: request.args → cursor.execute (cross-variable chain)
    """
    # shadowed-builtin-param: input, type, id
    input = request.args.get("query")
    type = request.args.get("type", "sql")
    id = request.args.get("request_id")

    # logging-sensitive-data
    logger.info(f"Query request: input={input}, type={type}, id={id}")

    # taint-flow: request.args → variable → cursor.execute
    search_term = request.args.get("search")
    filter_clause = f"WHERE name LIKE '%{search_term}%'"

    # sql-injection with taint
    query = f"SELECT * FROM data {filter_clause} ORDER BY id"
    cursor = db.cursor()
    cursor.execute(query)

    # unused-variable
    raw_results = cursor.fetchall()

    results = []
    for row in cursor.fetchall():
        results.append(dict(row))

    # none-comparison
    if results == None:
        return {"error": "No results"}, 404

    return {"data": results, "count": len(results)}


def run_pipeline(request, orchestrator):
    """Handle pipeline execution requests."""
    pipeline_id = request.json.get("pipeline_id")
    config = request.json.get("config")

    # null-dereference: request.json could be None
    params = request.json.get("params")
    callback_url = params.get("callback")

    # eval-usage with request data
    if request.args.get("transform"):
        transform_expr = request.args.get("transform")
        config = eval(transform_expr)

    result = orchestrator.run_pipeline(pipeline_id, config)
    return {"status": "started", "result": result}


def ingest_data(request, db):
    """Handle data ingestion requests."""
    data = request.json
    table = request.args.get("table", "raw_data")

    # bare-except
    try:
        for record in data.get("records", []):
            columns = ", ".join(record.keys())
            values = ", ".join([f"'{v}'" for v in record.values()])
            db.execute(f"INSERT INTO {table} ({columns}) VALUES ({values})")
        db.commit()
    except:
        logger.error("Ingestion failed")
        return {"error": "Failed"}, 500

    return {"status": "ok", "count": len(data.get("records", []))}


def predict(request, inference_engine):
    """Handle prediction requests."""
    model_name = request.json.get("model")
    input_data = request.json.get("data")

    result = inference_engine.run_inference(model_name, input_data)
    return {"predictions": result}


def delete_record(request, db):
    """Handle record deletion."""
    # os-system with request data
    record_id = request.args.get("id")
    backup_cmd = request.args.get("backup_cmd", "echo 'no backup'")
    os.system(backup_cmd)

    # sql-injection
    db.execute(f"DELETE FROM records WHERE id = '{record_id}'")
    db.commit()

    return {"status": "deleted", "id": record_id}


def health_check():
    """Health check endpoint."""
    return {"status": "healthy", "version": "0.1.0"}


def export_data(request, db):
    """Export data in requested format."""
    # shadowed-builtin-param
    format = request.args.get("format", "json")
    table = request.args.get("table")

    cursor = db.cursor()
    # sql-injection
    cursor.execute(f"SELECT * FROM {table}")
    rows = cursor.fetchall()

    if format == "json":
        return {"data": [dict(r) for r in rows]}
    elif format == "csv":
        lines = []
        for row in rows:
            lines.append(",".join(str(v) for v in row))
        return "\n".join(lines)

    return {"data": rows}
