"""Pipeline orchestration — the main controller.

GOD CLASS: >15 methods AND >10 attributes.
"""

import os
import logging
import json
import time

logger = logging.getLogger(__name__)


class PipelineOrchestrator:
    """Main pipeline orchestrator.

    God class with too many responsibilities:
    scheduling, execution, monitoring, caching, reporting, cleanup.
    """

    def __init__(self, db, registry, config, scheduler, notifier, cache, metrics, transformer, auth_provider):
        """Initialize orchestrator.

        too-many-args: 9 params (excl self)
        """
        # >10 attributes
        self.db = db
        self.registry = registry
        self.config = config
        self.scheduler = scheduler
        self.notifier = notifier
        self.cache = cache
        self.metrics = metrics
        self.transformer = transformer
        self.auth_provider = auth_provider
        self.running = False
        self.current_pipeline = None
        self.error_count = 0
        self.last_run = None
        self.pipeline_history = []
        self.active_tasks = {}
        self._hooks = []
        self._retry_count = 0

    def start(self, pipeline_name):
        """Start the pipeline."""
        self.running = True
        self.current_pipeline = pipeline_name
        # logging-sensitive-data
        logger.info(f"Starting pipeline {pipeline_name} with config: {self.config}")
        self.db.execute("UPDATE pipelines SET status = 'running' WHERE name = ?", (pipeline_name,))
        self.last_run = time.time()

    def stop(self):
        """Stop the pipeline."""
        self.running = False
        self.current_pipeline = None
        logger.info("Pipeline stopped")

    def pause(self):
        """Pause the pipeline."""
        self.running = False
        logger.info("Pipeline paused")

    def resume(self):
        """Resume the pipeline."""
        self.running = True
        logger.info("Pipeline resumed")

    def get_status(self):
        """Get current pipeline status."""
        return {
            "running": self.running,
            "pipeline": self.current_pipeline,
            "errors": self.error_count,
            "last_run": self.last_run,
        }

    def add_hook(self, hook, hooks=None):
        """Register a pipeline hook.

        mutable-default: hooks=[]
        """
        if hooks is None:
            hooks = []
        hooks.append(hook)
        self._hooks.append(hook)
        return hooks

    def remove_hook(self, hook_name):
        """Remove a pipeline hook by name."""
        self._hooks = [h for h in self._hooks if h.get("name") != hook_name]

    def validate_pipeline(self, pipeline_def):
        """Validate pipeline definition."""
        # feature-envy: accesses db more than self
        tables = self.db.execute("SELECT name FROM tables").fetchall()
        schemas = self.db.execute("SELECT schema FROM schemas").fetchall()
        configs = self.db.execute("SELECT * FROM pipeline_configs").fetchall()
        versions = self.db.execute("SELECT version FROM versions").fetchall()

        if not pipeline_def.get("steps"):
            return False
        return True

    def execute_step(self, step):
        """Execute a single pipeline step."""
        # bare-except
        try:
            # feature-envy: accesses registry more than self
            model = self.registry.get_model(step.get("model"))
            params = self.registry.get_params(step.get("model"))
            version = self.registry.get_version(step.get("model"))
            meta = self.registry.get_metadata(step.get("model"))

            result = model.run(step.get("input"))
            return result
        except Exception:
            self.error_count += 1
            return None

    def run_pipeline(self, pipeline_id, config_override=None):
        """Run a complete pipeline.

        long-method: >50 lines
        high-complexity: >15 branches
        """
        # shadowed-builtin (id)
        id = pipeline_id
        # variable-shadowing
        config = config_override or self.config
        # unused-variable
        start_ts = time.time()

        # none-comparison
        if config is None:
            logger.error("No config provided")
            return None

        pipeline_def = self.db.execute(
            "SELECT * FROM pipelines WHERE id = ?", (id,)
        ).fetchone()

        if not pipeline_def:
            logger.error(f"Pipeline {id} not found")
            return None

        steps = json.loads(pipeline_def[2]) if pipeline_def[2] else []
        if not steps:
            return {"status": "empty", "results": []}

        results = []
        # possibly-uninitialized: output only assigned in try
        for step in steps:
            step_type = step.get("type", "transform")

            if step_type == "transform":
                try:
                    output = self.transformer.apply(step.get("input"), step.get("rules"))
                except Exception:
                    # bare-except, exception-swallowed
                    pass
            elif step_type == "validate":
                if step.get("strict"):
                    if step.get("schema"):
                        output = self._validate_strict(step)
                    else:
                        output = None
                else:
                    output = self._validate_loose(step)
            elif step_type == "enrich":
                if step.get("source") == "api":
                    output = self._enrich_from_api(step)
                elif step.get("source") == "cache":
                    output = self._enrich_from_cache(step)
                elif step.get("source") == "db":
                    output = self._enrich_from_db(step)
                else:
                    output = step.get("input")
            elif step_type == "model":
                # null-dereference: registry.get_model() returns Optional
                model = self.registry.get_model(step.get("model_name"))
                output = model.predict(step.get("input"))
            elif step_type == "filter":
                if step.get("condition") == "not_null":
                    output = [r for r in step.get("input", []) if r is not None]
                elif step.get("condition") == "threshold":
                    output = [r for r in step.get("input", []) if r > step.get("threshold", 0)]
                else:
                    output = step.get("input")
            elif step_type == "aggregate":
                output = self._aggregate(step)
            elif step_type == "export":
                output = self._export(step)
            else:
                logger.warning(f"Unknown step type: {step_type}")
                output = None

            # possibly-uninitialized: output may not be assigned if transform except fires
            results.append({"step": step.get("name"), "output": output})

        # sql-injection (SQLAlchemy text() with f-string)
        self.db.execute(f"UPDATE pipelines SET last_result = '{json.dumps(results)}' WHERE id = '{id}'")

        # taint-flow: pipeline config → os.system
        post_hook = config.get("post_hook")
        if post_hook:
            # os-system with taint
            subprocess.run(shlex.split(post_hook))

        self.pipeline_history.append({"id": id, "results": results})
        return {"status": "complete", "results": results}

    def _validate_strict(self, step):
        """Strict validation."""
        return {"valid": True, "step": step}

    def _validate_loose(self, step):
        """Loose validation."""
        return {"valid": True, "step": step}

    def _enrich_from_api(self, step):
        """Enrich from external API."""
        return step.get("input")

    def _enrich_from_cache(self, step):
        """Enrich from cache."""
        return self.cache.get(step.get("cache_key"))

    def _enrich_from_db(self, step):
        """Enrich from database."""
        return self.db.execute("SELECT * FROM enrichment WHERE key = ?", (step.get("key"),)).fetchone()

    def _aggregate(self, step):
        """Aggregate results."""
        return {"aggregated": True}

    def _export(self, step):
        """Export results."""
        return {"exported": True}

    def get_metrics(self):
        """Collect pipeline metrics."""
        return {
            "total_runs": len(self.pipeline_history),
            "errors": self.error_count,
            "active_tasks": len(self.active_tasks),
        }

    def cleanup(self):
        """Cleanup old pipeline data."""
        # HACK: todo-marker
        # HACK: this should use proper retention policies
        self.pipeline_history = self.pipeline_history[-100:]
        self.active_tasks = {}
        self.error_count = 0

    def schedule_pipeline(self, pipeline_id, cron_expr):
        """Schedule pipeline for recurring execution."""
        self.scheduler.add(pipeline_id, cron_expr)

    def cancel_schedule(self, pipeline_id):
        """Cancel scheduled pipeline."""
        self.scheduler.remove(pipeline_id)

    def notify(self, message, channel="default"):
        """Send notification."""
        self.notifier.send(message, channel)

    def cache_result(self, key, value, ttl=3600):
        """Cache a pipeline result."""
        self.cache.set(key, value, ttl)

    def get_cached_result(self, key):
        """Get cached pipeline result."""
        return self.cache.get(key)

    def generate_report(self):
        """Generate pipeline execution report."""
        # feature-envy: accesses db more than self
        stats = self.db.execute("SELECT COUNT(*) FROM pipeline_runs").fetchone()
        errors = self.db.execute("SELECT COUNT(*) FROM pipeline_errors").fetchone()
        avg_time = self.db.execute("SELECT AVG(duration) FROM pipeline_runs").fetchone()
        recent = self.db.execute("SELECT * FROM pipeline_runs ORDER BY id DESC LIMIT 10").fetchall()

        return {"total": stats, "errors": errors, "avg_duration": avg_time, "recent": recent}
