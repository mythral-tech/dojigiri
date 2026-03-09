import pickle
import redis
from flask import Flask, request, jsonify

app = Flask(__name__)
r = redis.Redis(host="localhost", port=6379, db=0)


@app.route("/settings")
def load_settings():
    user_id = request.args.get("user_id")
    raw = r.get(f"user:{user_id}:prefs")

    if raw is None:
        return jsonify({}), 404

    prefs = pickle.loads(raw)
    return jsonify(prefs)
