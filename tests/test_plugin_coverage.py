"""Tests for dojigiri/plugin.py — plugin discovery, loading, and caching."""

import pytest
from unittest.mock import patch, MagicMock

from dojigiri.plugin import (
    _discover_plugin,
    get_llm_plugin,
    has_llm_plugin,
    require_llm_plugin,
    reset_plugin_cache,
)


class TestPluginDiscovery:
    def setup_method(self):
        reset_plugin_cache()

    def teardown_method(self):
        reset_plugin_cache()

    def test_get_llm_plugin_returns_module(self):
        """Built-in llm module should be discoverable."""
        reset_plugin_cache()
        plugin = get_llm_plugin()
        # In the monorepo setup, dojigiri.llm should be loadable
        assert plugin is not None

    def test_has_llm_plugin(self):
        reset_plugin_cache()
        assert has_llm_plugin() is True

    def test_require_llm_plugin_succeeds(self):
        reset_plugin_cache()
        plugin = require_llm_plugin()
        assert plugin is not None

    def test_require_llm_plugin_raises_when_unavailable(self):
        """When the plugin cache says None, require_llm_plugin raises."""
        import dojigiri.plugin as _mod
        # Directly set internal state to simulate no plugin available
        _mod._llm_plugin = None
        _mod._llm_plugin_loaded = True
        try:
            with pytest.raises(ImportError, match="dojigiri-ai"):
                require_llm_plugin()
        finally:
            reset_plugin_cache()

    def test_caching(self):
        """Second call should return cached result."""
        reset_plugin_cache()
        first = get_llm_plugin()
        second = get_llm_plugin()
        assert first is second

    def test_reset_cache(self):
        reset_plugin_cache()
        get_llm_plugin()
        reset_plugin_cache()
        # After reset, _llm_plugin_loaded should be False
        from dojigiri.plugin import _llm_plugin_loaded
        assert _llm_plugin_loaded is False
