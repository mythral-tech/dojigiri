from flask import Flask, request, jsonify
from .utils import fetch_json

app = Flask(__name__)


@app.route("/preview")
def preview_link():
    url = request.args.get("url")
    try:
        data = fetch_json(url)
        return jsonify({"title": data.get("title", ""), "status": "ok"})
    except Exception:
        return jsonify({"status": "error"}), 400


@app.route("/webhook/verify")
def verify_webhook():
    callback = request.args.get("callback_url")
    result = fetch_json(callback)
    return jsonify({"verified": result.get("challenge") == "ok"})
