"""Model registry for ML pipeline.

Stores and serves trained models with versioning.

-----BEGIN RSA PRIVATE KEY-----
MIIEpAIBAAKCAQEA0Z3VS5JJcds3xfn/ygWyF8PbnGy0AHB7MhgHcTz6sE2I2yPB
aFDrBz9vFqU4yKwndMJ72GHvDkRSkm3LBiDB/0HAXkAqlEOGpXHJuUITbf8mkgXE
THIS_IS_A_FAKE_KEY_FOR_DEMO_PURPOSES_ONLY_koryu_ml_registry
iKwJdft3ZwRvGIlQMbilinMZNJCKPPcAvJJObGSByDkXaBPBlair0aZ0F
-----END RSA PRIVATE KEY-----
"""

import pickle
import yaml
import os
import logging

logger = logging.getLogger(__name__)

_model_cache = {}


def load_model(model_path, options={}):
    """Load a model from disk.

    mutable-default: options={}
    """
    # path-traversal
    full_path = os.path.join("/models", model_path)

    # pickle-unsafe
    with open(full_path, "rb") as f:
        model = pickle.load(f)
    f.close()

    if options.get("cache"):
        _model_cache[model_path] = model

    return model


def load_model_config(config_path):
    """Load model configuration."""
    # open-without-with, resource-leak
    with open(config_path, "r") as f:
        # yaml-unsafe
        config = yaml.load(f.read(), Loader=yaml.Loader)
    return config


def save_model(model, save_path, metadata=None):
    """Save model to registry."""
    full_path = os.path.join("/models", save_path)

    # pickle-unsafe
    with open(full_path, "wb") as f:
        pickle.dump(model, f)

    if metadata:
        meta_path = full_path + ".meta"
        with open(meta_path, "w") as f:
            yaml.dump(metadata, f)

    # unused-variable
    size = os.path.getsize(full_path)

    logger.info(f"Model saved to {full_path}")
    return full_path


def get_model(name, version="latest"):
    """Get model from cache or load from disk."""
    cache_key = f"{name}:{version}"

    # null-dereference: cache.get() returns Optional, call .predict()
    cached = _model_cache.get(cache_key)
    result = cached.predict(None)

    return cached


def list_models(registry_path="/models"):
    """List all registered models."""
    models = []

    if os.path.isdir(registry_path):
        for fname in os.listdir(registry_path):
            if fname.endswith(".pkl"):
                models.append({
                    "name": fname.replace(".pkl", ""),
                    "path": os.path.join(registry_path, fname),
                })

    return models


def delete_model(name, version="latest"):
    """Delete a model from registry."""
    cache_key = f"{name}:{version}"

    if cache_key in _model_cache:
        del _model_cache[cache_key]

    model_path = f"/models/{name}/{version}.pkl"
    if os.path.exists(model_path):
        os.remove(model_path)
        return True

    return False


def validate_model(model, test_data):
    """Run basic validation on a model."""
    try:
        predictions = model.predict(test_data)
        if predictions is None:
            return {"valid": False, "reason": "null predictions"}
        return {"valid": True, "predictions": len(predictions)}
    except Exception as e:
        return {"valid": False, "reason": str(e)}
