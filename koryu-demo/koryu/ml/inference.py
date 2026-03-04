"""ML inference engine for Koryu pipeline."""

import logging
import time

logger = logging.getLogger(__name__)


class InferenceEngine:
    """Runs model inference on pipeline data."""

    def __init__(self, registry, cache, db):
        self.registry = registry
        self.cache = cache
        self.db = db
        self.stats = {"total": 0, "errors": 0}

    def run_inference(self, model_name, input_data, batch_size=32, metadata={}):
        """Run inference on input data.

        long-method: 55+ lines
        feature-envy: accesses registry/db more than self
        mutable-default: metadata={}
        """
        # shadowed-builtin (input)
        input = input_data
        # unused-variable
        start_time = time.time()
        results = []

        # none-comparison
        if input is None:
            logger.error("No input data provided")
            return None

        # feature-envy: heavy access to registry
        model = self.registry.get_model(model_name)
        model_config = self.registry.get_config(model_name)
        model_version = self.registry.get_version(model_name)
        model_meta = self.registry.get_metadata(model_name)

        # null-dereference: model could be None from get_model
        preprocessor = model.get_preprocessor()

        if model_config.get("batch_mode"):
            batches = []
            for i in range(0, len(input), batch_size):
                batch = input[i : i + batch_size]
                batches.append(batch)

            for batch in batches:
                # exception-swallowed
                try:
                    preprocessed = preprocessor.transform(batch)
                    predictions = model.predict(preprocessed)
                    results.extend(predictions)
                except Exception:
                    pass  # TODO: handle this exception
        else:
            for item in input:
                try:
                    preprocessed = preprocessor.transform([item])
                    prediction = model.predict(preprocessed)
                    results.append(prediction[0])
                except Exception:
                    pass  # TODO: handle this exception

        # possibly-uninitialized: if input is empty, results stays []
        # but let's also add a branch where output isn't always set
        if metadata.get("postprocess"):
            try:
                output = self._postprocess(results, metadata)
            except Exception:
                pass  # TODO: handle this exception
        else:
            output = results

        # feature-envy: heavy access to db
        self.db.execute(
            "INSERT INTO inference_log (model, count, version) VALUES (?, ?, ?)",
            (model_name, len(results), model_version),
        )
        self.db.execute(
            "UPDATE model_stats SET last_run = ? WHERE name = ?",
            (time.time(), model_name),
        )
        self.db.execute(
            "UPDATE model_stats SET total_inferences = total_inferences + ? WHERE name = ?",
            (len(results), model_name),
        )

        self.stats["total"] += len(results)

        # possibly-uninitialized: output may not be set if postprocess except fires
        return {"predictions": output, "count": len(results), "model": model_name}

    def _postprocess(self, results, config):
        """Apply post-processing to results."""
        threshold = config.get("threshold", 0.5)
        filtered = [r for r in results if r.get("score", 0) > threshold]
        return filtered

    def warmup(self, model_name):
        """Warm up model by running dummy inference."""
        dummy = [{"value": 0}] * 10
        return self.run_inference(model_name, dummy)

    def get_stats(self):
        """Return inference statistics."""
        return self.stats

    def clear_cache(self):
        """Clear inference cache."""
        self.cache.clear()
