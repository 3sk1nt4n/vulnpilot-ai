"""
VulnPilot AI - LLM Provider Factory (v1.0: Multi-Provider)

Primary LLM (all 5 agents + AI chat):
  LLM_PROVIDER=ollama       → Free, local
  LLM_PROVIDER=anthropic    → Claude (production)
  LLM_PROVIDER=openai       → GPT-4o

Cross-Model Challenger (Lock 2 adversarial debate):
  CHALLENGER_PROVIDER=openai → GPT attacks Claude's reasoning
  CHALLENGER_PROVIDER=anthropic → Claude attacks Ollama's reasoning
  CHALLENGER_PROVIDER=       → Same model debates itself (default)

NEW in v1.0: get_provider_by_name() allows per-request provider override
from the frontend. Customer can hot-swap providers in one click.
"""

import os
import logging
from typing import Optional

from vulnpilot.llm.base import LLMProvider

logger = logging.getLogger(__name__)

# Provider instance cache (one per provider type)
_provider_cache: dict[str, LLMProvider] = {}


def _create_provider(name: str) -> LLMProvider:
    """Create a provider instance by name."""
    name = name.lower().strip()
    if name == "anthropic" or name == "claude":
        from vulnpilot.llm.anthropic_provider import AnthropicProvider
        return AnthropicProvider()
    elif name == "openai" or name == "gpt":
        from vulnpilot.llm.openai_provider import OpenAIProvider
        return OpenAIProvider()
    elif name == "ollama":
        from vulnpilot.llm.ollama_provider import OllamaProvider
        return OllamaProvider()
    else:
        raise ValueError(
            f"Unknown LLM provider: '{name}'. "
            "Use 'ollama', 'anthropic'/'claude', or 'openai'/'gpt'."
        )


def get_llm_provider() -> LLMProvider:
    """Get the default LLM provider from environment config."""
    provider_name = os.getenv("LLM_PROVIDER", "ollama").lower()
    return get_provider_by_name(provider_name)


def get_provider_by_name(name: Optional[str] = None) -> LLMProvider:
    """Get a provider by name, with caching.

    This is the key function for hot-swapping: the frontend sends
    a provider name with each request, and this returns the right
    instance. Falls back to the default LLM_PROVIDER if name is None.

    Args:
        name: Provider name ('ollama', 'anthropic'/'claude', 'openai'/'gpt')
              None = use default from LLM_PROVIDER env var

    Returns:
        Cached LLMProvider instance
    """
    if not name:
        name = os.getenv("LLM_PROVIDER", "ollama")

    # Normalize aliases
    name = name.lower().strip()
    if name == "claude":
        name = "anthropic"
    elif name == "gpt":
        name = "openai"

    # Return cached or create new
    if name not in _provider_cache:
        _provider_cache[name] = _create_provider(name)
        logger.info(f"Created LLM provider: {name}")

    return _provider_cache[name]


def get_challenger_provider() -> Optional[LLMProvider]:
    """Returns a SEPARATE LLM for the Challenger agent in Lock 2.
    When set, adversarial debate uses two different AI architectures.
    """
    provider = os.getenv("CHALLENGER_PROVIDER", "").lower().strip()
    if not provider:
        return None
    return get_provider_by_name(provider)


def get_all_provider_names() -> list[str]:
    """Return list of all supported provider names."""
    return ["ollama", "anthropic", "openai"]


async def get_provider_health() -> dict:
    """Check health of all configured providers.

    Returns dict like:
    {
        "ollama": {"healthy": True, "model": "qwen2.5:7b"},
        "anthropic": {"healthy": False, "model": "claude-sonnet-4-20250514", "reason": "no API key"},
        "openai": {"healthy": False, "model": "gpt-4o", "reason": "no API key"}
    }
    """
    results = {}
    default_provider = os.getenv("LLM_PROVIDER", "ollama").lower()

    for name in get_all_provider_names():
        try:
            provider = get_provider_by_name(name)
            model = getattr(provider, "model", "unknown")

            # Quick check: does it have required credentials?
            if name == "anthropic":
                api_key = os.getenv("ANTHROPIC_API_KEY", "")
                if not api_key:
                    results[name] = {
                        "healthy": False, "model": model,
                        "reason": "no_key", "is_default": name == default_provider
                    }
                    continue
            elif name == "openai":
                api_key = os.getenv("OPENAI_API_KEY", "")
                if not api_key:
                    results[name] = {
                        "healthy": False, "model": model,
                        "reason": "no_key", "is_default": name == default_provider
                    }
                    continue

            healthy = await provider.health_check()
            results[name] = {
                "healthy": healthy, "model": model,
                "is_default": name == default_provider
            }
        except Exception as e:
            results[name] = {
                "healthy": False, "model": "unknown",
                "reason": str(e), "is_default": name == default_provider
            }

    return results
