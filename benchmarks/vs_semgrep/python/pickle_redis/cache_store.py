import pickle
import redis
from flask import Flask, request, jsonify

app = Flask(__name__)
r = redis.Redis(host="localhost", port=6379, db=0)


@app.route("/settings", methods=["POST"])
def save_settings():
    prefs = request.json
    user_id = prefs.pop("user_id")

    serialized = pickle.dumps(prefs)
    r.set(f"user:{user_id}:prefs", serialized, ex=3600)

    return jsonify({"status": "saved"})
