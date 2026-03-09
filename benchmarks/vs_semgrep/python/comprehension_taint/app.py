from flask import Flask, request, jsonify
import sqlite3

app = Flask(__name__)
DB_PATH = "app.db"


@app.route("/users")
def search_users():
    raw_ids = request.args.getlist("ids")
    cleaned = [x.strip() for x in raw_ids]

    placeholders = ", ".join(cleaned)
    query = f"SELECT * FROM users WHERE id IN ({placeholders})"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(query)
    rows = cursor.fetchall()
    conn.close()

    return jsonify({"users": rows})


@app.route("/tags")
def filter_tags():
    tags = request.args.getlist("tag")
    normalized = [t.lower().strip() for t in tags]

    clause = " OR ".join([f"tag = '{t}'" for t in normalized])
    query = f"SELECT * FROM posts WHERE {clause}"

    conn = sqlite3.connect(DB_PATH)
    cursor = conn.execute(query)
    rows = cursor.fetchall()
    conn.close()

    return jsonify({"posts": rows})
