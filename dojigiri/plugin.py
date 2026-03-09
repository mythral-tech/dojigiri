"""Plugin loader for optional LLM capabilities.

Provides a seam between the base dojigiri package (static analysis) and
the optional dojigiri-ai package (LLM-powered deep scan, fixes, etc.).

The base package works fully without any LLM modules installed.
LLM functionality is discovered via the ``dojigiri.plugins`` entry_points
group, or falls back to the built-in llm modules if present.

Called by: analyzer.py, cli/scan.py, cli/common.py, fixer/engine.py, graph/project.py
"""

from __future__ import annotations

import importlib
import logging
from typing import Any

logger = logging.getLogger(__name__)

_llm_plugin: Any | None = None
_llm_plugin_loaded: bool = False


def _discover_plugin() -> Any | None:
    """Discover and load the LLM plugin from entry_points or built-in modules.

    Checks in order:
    1. ``dojigiri.plugins`` entry_points (for dojigiri-ai package)
    2. Built-in ``dojigiri.llm`` module (for monorepo / editable installs)

    Returns the module/object or None if no LLM capability is available.
    """
    global _llm_plugin, _llm_plugin_loaded

    if _llm_plugin_loaded:
        return _llm_plugin

    _llm_plugin_loaded = True

    # 1. Check entry_points (dojigiri-ai or other plugins)
    try:
        import sys

        if sys.version_info >= (3, 12):
            from importlib.metadata import entry_points
            eps = entry_points(group="dojigiri.plugins")
        else:
            # Python 3.10-3.11 compatible path
            from importlib.metadata import entry_points
            all_eps = entry_points()
            if isinstance(all_eps, dict):
                eps = all_eps.get("dojigiri.plugins", [])
            else:
                eps = all_eps.select(group="dojigiri.plugins")

        for ep in eps:
            if ep.name == "llm":
                try:
                    _llm_plugin = ep.load()
                    logger.debug("Loaded LLM plugin from entry_point: %s", ep.value)
                    return _llm_plugin
                except Exception as e:
                    logger.warning("Failed to load LLM plugin '%s': %s", ep.value, e)
    except Exception as e:
        logger.debug("Entry point discovery failed: %s", e)

    # 2. Fallback: try built-in llm module (monorepo / editable install)
    try:
        _llm_plugin = importlib.import_module("dojigiri.llm")
        logger.debug("Loaded built-in LLM module")
        return _llm_plugin
    except ImportError:
        logger.debug("No built-in LLM module found")

    return None


def get_llm_plugin() -> Any | None:
    """Return the LLM plugin module, or None if unavailable.

    Safe to call repeatedly -- caches the result after first discovery.
    """
    return _discover_plugin()


def require_llm_plugin() -> Any:
    """Return the LLM plugin module, or raise with a clear install message.

    Raises:
        ImportError: If no LLM plugin is available.
    """
    plugin = _discover_plugin()
    if plugin is None:
        raise ImportError(
            "Deep scan requires dojigiri-ai. Install with: pip install dojigiri-ai"
        )
    return plugin


def has_llm_plugin() -> bool:
    """Check whether LLM capabilities are available without importing them.

    Returns True if the plugin can be loaded, False otherwise.
    """
    return _discover_plugin() is not None


def reset_plugin_cache() -> None:
    """Reset the plugin discovery cache. Used in tests."""
    global _llm_plugin, _llm_plugin_loaded
    _llm_plugin = None
    _llm_plugin_loaded = False
