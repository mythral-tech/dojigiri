"""LLM backend abstraction — Anthropic, OpenAI-compatible, Ollama.

Provides a unified interface for multiple LLM providers. Each backend
implements the same protocol so the caller (llm.py) is provider-agnostic.

Called by: llm.py
Calls into: nothing (uses urllib, anthropic SDK directly)
Data in -> Data out: messages list -> LLMResponse (text + token counts)
"""

from __future__ import annotations  # noqa

import json
import logging
import os
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any, Protocol, runtime_checkable

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    """Unified response from any LLM backend."""

    text: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int = 0
    cache_create_tokens: int = 0
    tool_use_data: dict | list | None = None  # Structured data from tool_use responses


@runtime_checkable
class LLMBackend(Protocol):
    """Protocol for LLM backends."""

    def chat(
        self,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> LLMResponse: ...

    def chat_with_tools(
        self,
        system: str,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
        tool_choice: dict[str, str] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """Call the LLM with tool definitions for structured output.

        Default implementation falls back to chat() — backends that support
        tool_use (e.g. AnthropicBackend) override this with native support.
        """
        return self.chat(system=system, messages=messages, max_tokens=max_tokens, temperature=temperature)

    @property
    def is_local(self) -> bool:
        """True if this backend runs locally (no network calls)."""
        ...

    @property
    def cost_per_million_input(self) -> float: ...

    @property
    def cost_per_million_output(self) -> float: ...


# Model-to-pricing lookup (input, output per million tokens)
_ANTHROPIC_PRICING: dict[str, tuple[float, float]] = {
    "claude-opus-4": (15.0, 75.0),
    "claude-sonnet-4": (3.0, 15.0),
    "claude-haiku-4": (0.80, 4.0),
}

# Task tiers for model selection
TIER_SCAN = "scan"  # basic scan chunks — high volume, structured output
TIER_DEEP = "deep"  # debug/optimize/cross-file/synthesis/fix — needs reasoning
# Cache pricing multipliers relative to base input price
_CACHE_READ_DISCOUNT = 0.1  # cache reads cost 10% of base
_CACHE_CREATE_PREMIUM = 1.25  # cache creation costs 125% of base


class AnthropicBackend:
    """Wraps the Anthropic SDK."""

    def __init__(self, api_key: str | None = None, model: str | None = None):
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        self._model = model or os.environ.get("DOJI_LLM_MODEL", "claude-sonnet-4-20250514")
        self._client: Any = None  # doji:ignore(null-dereference)

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        if not self._api_key:
            raise RuntimeError(
                "ANTHROPIC_API_KEY not set. Set the environment variable or use --backend ollama for local models."
            )
        try:
            import anthropic
        except ImportError as err:
            raise RuntimeError("anthropic package not installed. Install with: pip install anthropic") from err
        self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    def with_model(self, model: str) -> AnthropicBackend:
        """Return a new backend instance using a different model but same API key/client."""
        clone = AnthropicBackend(api_key=self._api_key, model=model)
        clone._client = self._client  # reuse the authenticated client
        return clone

    def chat(
        self,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> LLMResponse:
        client = self._get_client()
        # Use prompt caching for the system prompt — it's the same across all
        # chunks in a scan session. Reduces cost ~90% on cache hits.
        system_with_cache = [
            {
                "type": "text",
                "text": system,
                "cache_control": {"type": "ephemeral"},
            }
        ]
        response = client.messages.create(  # doji:ignore(taint-flow) system/messages are internally-constructed scan prompts, not user-controlled
            model=self._model,
            max_tokens=max_tokens,
            temperature=temperature,
            system=system_with_cache,
            messages=messages,
        )
        # Handle potential empty/unexpected response format
        if not response.content or not hasattr(response.content[0], "text"):
            return LLMResponse(text="[]", input_tokens=0, output_tokens=0)
        # Track cache performance if available
        usage = response.usage
        cache_read = getattr(usage, "cache_read_input_tokens", 0)
        cache_create = getattr(usage, "cache_creation_input_tokens", 0)
        if cache_read or cache_create:
            logger.debug(
                "Prompt cache: %d read, %d created, %d uncached",
                cache_read,
                cache_create,
                usage.input_tokens - cache_read - cache_create,
            )
        return LLMResponse(
            text=response.content[0].text,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            cache_read_tokens=cache_read,
            cache_create_tokens=cache_create,
        )

    def chat_with_tools(
        self,
        system: str,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
        tool_choice: dict[str, str] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """Call the Anthropic API with tool definitions to get structured output.

        Uses the tool_use feature to force the model to return structured data
        matching a predefined schema, eliminating the need for JSON text parsing.

        Args:
            system: System prompt.
            messages: Conversation messages.
            tools: Tool definitions (Anthropic tool schema format).
            tool_choice: Force a specific tool, e.g. {"type": "tool", "name": "..."}.
            max_tokens: Maximum output tokens.
            temperature: Sampling temperature.

        Returns:
            LLMResponse with tool_use_data populated if the model used a tool,
            or text populated if the model returned text instead.
        """
        client = self._get_client()
        system_with_cache = [
            {
                "type": "text",
                "text": system,
                "cache_control": {"type": "ephemeral"},
            }
        ]
        kwargs: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "temperature": temperature,
            "system": system_with_cache,
            "messages": messages,
            "tools": tools,
        }
        if tool_choice:
            kwargs["tool_choice"] = tool_choice

        response = client.messages.create(**kwargs)  # doji:ignore(taint-flow) system/messages are internally-constructed scan prompts, not user-controlled

        # Track cache performance
        usage = response.usage
        cache_read = getattr(usage, "cache_read_input_tokens", 0)
        cache_create = getattr(usage, "cache_creation_input_tokens", 0)
        if cache_read or cache_create:
            logger.debug(
                "Prompt cache: %d read, %d created, %d uncached",
                cache_read,
                cache_create,
                usage.input_tokens - cache_read - cache_create,
            )

        # Extract tool_use content if present
        tool_use_data = None
        text = ""
        for block in response.content:
            if hasattr(block, "type") and block.type == "tool_use":
                tool_use_data = block.input
            elif hasattr(block, "text"):
                text = block.text

        return LLMResponse(
            text=text,
            input_tokens=usage.input_tokens,
            output_tokens=usage.output_tokens,
            cache_read_tokens=cache_read,
            cache_create_tokens=cache_create,
            tool_use_data=tool_use_data,
        )

    @property
    def is_local(self) -> bool:
        return False

    def _get_pricing(self) -> tuple[float, float]:
        """Get (input, output) pricing per million tokens for the configured model."""
        for prefix, pricing in _ANTHROPIC_PRICING.items():
            if prefix in self._model:
                return pricing
        logger.warning("Unknown Anthropic model '%s' — using Sonnet 4 pricing", self._model)
        return (3.0, 15.0)

    @property
    def cost_per_million_input(self) -> float:
        return self._get_pricing()[0]

    @property
    def cost_per_million_output(self) -> float:
        return self._get_pricing()[1]


class OpenAICompatibleBackend:
    """Generic OpenAI-compatible API backend using urllib (no dependencies)."""

    def __init__(
        self,
        base_url: str,
        api_key: str | None = None,
        model: str = "default",
        is_local: bool = False,
    ):
        self._base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._model = model
        self._is_local = is_local

    def chat(
        self,
        system: str,
        messages: list[dict[str, str]],
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> LLMResponse:
        # Convert Anthropic-style system+messages to OpenAI format
        oai_messages = [{"role": "system", "content": system}]
        for msg in messages:
            oai_messages.append({"role": msg["role"], "content": msg["content"]})  # doji:ignore(llm-role-from-user-input) roles are hardcoded internally as "user", never from external input

        payload = {
            "model": self._model,
            "messages": oai_messages,
            "max_tokens": max_tokens,
            "temperature": temperature,
        }

        url = f"{self._base_url}/v1/chat/completions"
        headers = {"Content-Type": "application/json"}
        if self._api_key:
            headers["Authorization"] = f"Bearer {self._api_key}"

        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(url, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(req, timeout=300) as resp:  # doji:ignore(ssrf-risk,url-scheme-audit)
                body = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            error_body = ""
            try:
                error_body = e.read().decode("utf-8", errors="replace")[:500]
            except Exception as e2:
                logger.debug("Failed to read error body: %s", e2)
            raise RuntimeError(f"LLM API error {e.code}: {error_body}") from e
        except urllib.error.URLError as e:
            raise RuntimeError(f"Cannot connect to LLM at {self._base_url}: {e.reason}") from e

        # Parse response
        choices = body.get("choices", [])
        if not choices:
            raise RuntimeError("LLM returned empty choices")
        text = choices[0]["message"]["content"]
        usage = body.get("usage", {})

        return LLMResponse(
            text=text,
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
        )

    def chat_with_tools(
        self,
        system: str,
        messages: list[dict[str, str]],
        tools: list[dict[str, Any]],
        tool_choice: dict[str, str] | None = None,
        max_tokens: int = 4096,
        temperature: float = 0.0,
    ) -> LLMResponse:
        """Fall back to plain chat — OpenAI-compatible backends don't support Anthropic tool_use."""
        return self.chat(system=system, messages=messages, max_tokens=max_tokens, temperature=temperature)

    @property
    def is_local(self) -> bool:
        return self._is_local

    @property
    def cost_per_million_input(self) -> float:
        return 0.0 if self._is_local else 1.0

    @property
    def cost_per_million_output(self) -> float:
        return 0.0 if self._is_local else 1.0


class OllamaBackend(OpenAICompatibleBackend):
    """Ollama backend — sets base_url from OLLAMA_HOST or localhost:11434."""

    def __init__(self, model: str | None = None):
        host = os.environ.get("OLLAMA_HOST", "http://localhost:11434")  # doji:ignore(insecure-http)
        if not host.startswith("http"):
            host = f"http://{host}"  # doji:ignore(insecure-http)
        super().__init__(
            base_url=host,
            api_key=None,
            model=model or os.environ.get("DOJI_LLM_MODEL", "llama3.1"),
            is_local=True,
        )


def get_backend(config: dict | None = None) -> LLMBackend:
    """Factory: create the right backend from config/env vars.

    Config keys (also settable via env vars):
    - backend: "anthropic", "openai", "ollama" (env: DOJI_LLM_BACKEND)
    - model: model name (env: DOJI_LLM_MODEL)
    - base_url: API base URL (env: DOJI_LLM_BASE_URL)
    - api_key: API key (env: per-backend defaults)

    Auto-detection order when no backend specified:
    1. ANTHROPIC_API_KEY set -> anthropic
    2. OLLAMA_HOST set -> ollama
    3. Error with helpful message
    """
    config = config or {}

    backend_type = config.get("backend") or os.environ.get("DOJI_LLM_BACKEND")
    model = config.get("model") or os.environ.get("DOJI_LLM_MODEL")
    base_url = config.get("base_url") or os.environ.get("DOJI_LLM_BASE_URL")

    # Auto-detect if no explicit backend
    if not backend_type:
        if os.environ.get("ANTHROPIC_API_KEY"):
            backend_type = "anthropic"
        elif os.environ.get("OLLAMA_HOST"):
            backend_type = "ollama"
        elif base_url:
            backend_type = "openai"
        else:
            # Try anthropic as default (will fail with clear error if no key)
            backend_type = "anthropic"

    backend_type = backend_type.lower()

    if backend_type == "anthropic":
        # Hardcode Anthropic base URL to prevent SSRF via env/config redirect
        return AnthropicBackend(
            api_key=config.get("api_key"),
            model=model,
        )
    elif backend_type == "ollama":
        return OllamaBackend(model=model)
    elif backend_type in ("openai", "openai-compatible"):
        if not base_url:
            raise RuntimeError("OpenAI-compatible backend requires --base-url or DOJI_LLM_BASE_URL")
        # Validate URL scheme
        if (
            not base_url.startswith("https://")
            and not base_url.startswith("http://localhost")
            and not base_url.startswith("http://127.0.0.1")
        ):
            import logging as _logging

            _logging.getLogger(__name__).warning(
                "LLM base URL '%s' is not HTTPS. API keys will be sent in plaintext.", base_url
            )
        return OpenAICompatibleBackend(
            base_url=base_url,
            api_key=config.get("api_key") or os.environ.get("OPENAI_API_KEY"),
            model=model or "default",
        )
    else:
        raise RuntimeError(f"Unknown LLM backend '{backend_type}'. Use: anthropic, ollama, or openai")


def get_tier_pricing(tier: str = TIER_SCAN) -> tuple[float, float]:
    """Get (input, output) cost per million tokens for the given tier.

    Respects tier_mode and user model overrides — same resolution logic
    as get_tiered_backend() but returns pricing without constructing a client.
    Use this for cost estimation to avoid hardcoding model prices.
    """
    import os as _os

    from .config import LLM_DEEP_MODEL, LLM_INPUT_COST_PER_M, LLM_OUTPUT_COST_PER_M, LLM_SCAN_MODEL, LLM_TIER_MODE

    tier_mode = _os.environ.get("DOJI_LLM_TIER_MODE", LLM_TIER_MODE)
    user_model = _os.environ.get("DOJI_LLM_MODEL")
    backend_type = _os.environ.get("DOJI_LLM_BACKEND", "anthropic").lower()

    # Non-Anthropic backends or user-specified model: use config defaults
    if backend_type != "anthropic" or tier_mode == "off" or user_model:
        if user_model:
            # Look up user's explicit model in pricing table
            for prefix, pricing in _ANTHROPIC_PRICING.items():
                if prefix in user_model:
                    return pricing
        return (LLM_INPUT_COST_PER_M, LLM_OUTPUT_COST_PER_M)

    # Tiered Anthropic: resolve model name for this tier
    model = LLM_SCAN_MODEL if tier == TIER_SCAN else LLM_DEEP_MODEL
    for prefix, pricing in _ANTHROPIC_PRICING.items():
        if prefix in model:
            return pricing

    # Fallback to Sonnet pricing
    return (3.0, 15.0)


def get_tiered_backend(config: dict | None = None, tier: str = TIER_DEEP) -> LLMBackend:
    """Get a backend appropriate for the given task tier.

    For Anthropic backends with tier_mode='auto':
    - TIER_SCAN: uses Haiku (fast, cheap — good for structured scan output)
    - TIER_DEEP: uses Sonnet (reasoning — debug/optimize/cross-file/fix)

    For non-Anthropic backends or tier_mode='off', returns the default backend.
    """
    import os as _os

    from .config import LLM_DEEP_MODEL, LLM_SCAN_MODEL, LLM_TIER_MODE

    tier_mode = _os.environ.get("DOJI_LLM_TIER_MODE", LLM_TIER_MODE)

    # If tiering is off, or user explicitly set a model, use default
    config = config or {}
    user_model = config.get("model") or _os.environ.get("DOJI_LLM_MODEL")
    if tier_mode == "off" or user_model:
        return get_backend(config)

    backend = get_backend(config)

    # Only tier Anthropic backends — local/OpenAI models don't have tiering
    if not isinstance(backend, AnthropicBackend):
        return backend

    if tier == TIER_SCAN:
        return backend.with_model(LLM_SCAN_MODEL)
    else:
        return backend.with_model(LLM_DEEP_MODEL)
