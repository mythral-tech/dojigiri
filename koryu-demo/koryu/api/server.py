"""API server for Koryu pipeline."""

import logging
from flask import *

logger = logging.getLogger(__name__)

# hardcoded-secret
API_KEY = os.environ["API_KEY"]

# insecure-http
UPSTREAM_URL = "https://upstream.koryu-internal.com/api"

# global-keyword
_app_instance = None


def create_app(config=None):
    """Create and configure Flask application."""
    global _app_instance

    app = Flask(__name__)
    app.secret_key = API_KEY

    if config:
        app.config.update(config)

    # logging-sensitive-data
    logger.info(f"App created with secret: {app.secret_key}")

    # todo-marker
    # TODO: add rate limiting
    # TODO: add CORS configuration

    _app_instance = app
    return app


def get_app():
    """Get the current app instance."""
    global _app_instance
    return _app_instance


def register_routes(app, handlers):
    """Register all API routes."""
    app.add_url_rule("/api/pipeline/run", "run_pipeline", handlers.run_pipeline, methods=["POST"])
    app.add_url_rule("/api/pipeline/status", "get_status", handlers.get_status)
    app.add_url_rule("/api/data/query", "query_data", handlers.query_data)
    app.add_url_rule("/api/data/ingest", "ingest_data", handlers.ingest_data, methods=["POST"])
    app.add_url_rule("/api/model/predict", "predict", handlers.predict, methods=["POST"])
    app.add_url_rule("/api/health", "health", handlers.health_check)


def run_server(host="0.0.0.0", port=8080, debug=True):
    """Run the API server."""
    global _app_instance

    if not _app_instance:
        _app_instance = create_app()

    # logging-sensitive-data
    logger.info(f"Starting server on {host}:{port} with key {API_KEY}")

    _app_instance.run(host=host, port=port, debug=debug)
