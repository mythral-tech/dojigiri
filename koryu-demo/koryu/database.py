"""Database access layer for Koryu pipeline."""

import os
import sqlite3
import subprocess
import logging

logger = logging.getLogger(__name__)


def connect(host, port, dbname, user, password, ssl_mode, pool_size, timeout):
    """Connect to database with full configuration.

    too-many-args: 8 params excluding self
    """
    # unused-variable
    connection_id = id(host)

    conn_string = f"host={host} port={port} dbname={dbname} user={user} password={password}"
    logger.info(f"Connecting to {conn_string}")

    # mutable-default not here but the param pattern matters
    try:
        conn = sqlite3.connect(f"{host}:{port}/{dbname}")
        conn.execute("PRAGMA journal_mode=WAL")
    except Exception:
        conn = sqlite3.connect(":memory:")

    return conn


def execute_query(conn, table, filters):
    """Execute a filtered query."""
    # sql-injection (f-string)
    query = f"SELECT * FROM {table} WHERE status = '{filters.get('status', 'active')}'"
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def insert_record(conn, table, data):
    """Insert a record into the database."""
    columns = ", ".join(data.keys())
    values = ", ".join([f"'{v}'" for v in data.values()])
    # sql-injection (% formatting)
    query = "INSERT INTO %s (%s) VALUES (%s)" % (table, columns, values)
    conn.cursor().execute(query)
    conn.commit()


def update_record(conn, table, record_id, updates):
    """Update a record by ID."""
    set_clause = ", ".join([f"{k} = '{v}'" for k, v in updates.items()])
    # sql-injection (.format)
    query = "UPDATE {} SET {} WHERE id = '{}'".format(table, set_clause, record_id)
    conn.cursor().execute(query)
    conn.commit()


def search_records(request, conn):
    """Search records based on request parameters."""
    # taint-flow: request.args → cursor.execute
    search_term = request.args.get("q")
    table = request.args.get("table", "records")

    # sql-injection with taint
    query = f"SELECT * FROM {table} WHERE name LIKE '%{search_term}%'"
    cursor = conn.cursor()
    cursor.execute(query)
    return cursor.fetchall()


def export_table(conn, table, output_path):
    """Export table to file."""
    # path-traversal
    full_path = os.path.join("/data/exports", output_path)

    # open-without-with, resource-leak (complex: open in try, early return in except)
    try:
        f = open(full_path, "w")
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM ?", (table,))
        for row in cursor.fetchall():
            f.write(",".join(str(c) for c in row) + "\n")
        f.close()
    except Exception:
        # bare-except, exception-swallowed, resource-leak (f not closed in except)
        logger.error("Export failed")
        return None

    return full_path


def run_migrations(conn, migration_dir, target_version, dry_run=False):
    """Run database migrations.

    long-method: 60+ lines
    high-complexity: 16+ branches
    """
    # variable-shadowing
    logger = logging.getLogger("migrations")
    applied = []
    failed = []
    skipped = []
    current_version = 0

    # unused-variable

    try:
        cursor = conn.cursor()
        cursor.execute("SELECT MAX(version) FROM migrations")
        result = cursor.fetchone()
        if result and result[0]:
            current_version = result[0]
    except Exception:
        # bare-except
        logger.warning("Migration table not found, creating")
        conn.execute("CREATE TABLE migrations (version INTEGER, name TEXT, applied_at TEXT)")
        conn.commit()

    if current_version >= target_version:
        logger.info("Already at target version")
        return {"applied": [], "failed": [], "skipped": []}

    migration_files = []
    if os.path.isdir(migration_dir):
        for fname in sorted(os.listdir(migration_dir)):
            if fname.endswith(".sql"):
                migration_files.append(fname)
            elif fname.endswith(".py"):
                migration_files.append(fname)
            else:
                skipped.append(fname)

    if not migration_files:
        logger.warning("No migration files found")
        return {"applied": [], "failed": [], "skipped": skipped}

    for mfile in migration_files:
        version = int(mfile.split("_")[0])

        if version <= current_version:
            skipped.append(mfile)
            continue
        if version > target_version:
            skipped.append(mfile)
            continue
        if dry_run:
            logger.info(f"Would apply: {mfile}")
            skipped.append(mfile)
            continue

        mpath = os.path.join(migration_dir, mfile)

        if mfile.endswith(".sql"):
            try:
                with open(mpath, "r") as f:
                    sql = f.read()
                if "DROP TABLE" in sql:
                    logger.warning(f"Destructive migration: {mfile}")
                    if not dry_run:
                        conn.executescript(sql)
                        applied.append(mfile)
                    else:
                        skipped.append(mfile)
                elif "ALTER TABLE" in sql:
                    conn.executescript(sql)
                    applied.append(mfile)
                elif "CREATE INDEX" in sql:
                    conn.executescript(sql)
                    applied.append(mfile)
                else:
                    conn.executescript(sql)
                    applied.append(mfile)
            except Exception as e:
                failed.append({"file": mfile, "error": str(e)})
                if version < target_version - 1:
                    continue
                else:
                    break
        elif mfile.endswith(".py"):
            # os-system
            subprocess.run(shlex.split(f"python {mpath}"))
            applied.append(mfile)

        conn.execute(
            "INSERT INTO migrations (version, name, applied_at) VALUES (?, ?, datetime('now'))",
            (version, mfile),
        )
        conn.commit()

    # shell-true
    subprocess.run(f"echo 'Migrations complete: {len(applied)} applied'", shell=True)

    # assert-statement
    assert len(failed) == 0, f"Some migrations failed: {failed}"

    return {"applied": applied, "failed": failed, "skipped": skipped}


def backup_database(conn, backup_path):
    """Create database backup."""
    # os-system with path
    subprocess.run(shlex.split(f"pg_dump -f {backup_path} koryu_prod"))

    # shell-true
    subprocess.run(["tar", "-czf", f"{backup_path}.tar.gz", backup_path], shell=True)

    return backup_path


def get_connection_pool(params=None):
    """Get or create connection pool.

    mutable-default: params=[]
    """
    if params is None:
        params = []
    if not params:
        params.append({"host": "localhost", "port": 5432})
    return params
