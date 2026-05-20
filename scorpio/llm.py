"""LLM factories.

Supports Anthropic, OpenAI, Google Gemini, and Ollama.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from langchain_core.language_models.chat_models import BaseChatModel

from scorpio.config import get_settings

LLMRole = Literal["main", "fast"]


@lru_cache(maxsize=8)
def get_llm(role: LLMRole = "main") -> BaseChatModel:
    """Return a configured ChatModel client for the given role and provider."""
    settings = get_settings()
    provider = settings.llm_provider
    main_model, fast_model = settings.get_resolved_models()
    model = main_model if role == "main" else fast_model

    kwargs: dict = {
        "temperature": settings.llm_temperature,
    }

    if provider == "anthropic":
        from langchain_anthropic import ChatAnthropic
        kwargs["model"] = model
        kwargs["max_tokens"] = settings.llm_max_tokens
        if settings.anthropic_api_key:
            kwargs["api_key"] = settings.anthropic_api_key
        return ChatAnthropic(**kwargs)

    elif provider == "openai":
        from langchain_openai import ChatOpenAI
        kwargs["model"] = model
        kwargs["max_tokens"] = settings.llm_max_tokens
        if settings.openai_api_key:
            kwargs["api_key"] = settings.openai_api_key
        return ChatOpenAI(**kwargs)

    elif provider == "google":
        from langchain_google_genai import ChatGoogleGenerativeAI
        kwargs["model"] = model
        kwargs["max_output_tokens"] = settings.llm_max_tokens
        if settings.google_api_key:
            kwargs["api_key"] = settings.google_api_key
        return ChatGoogleGenerativeAI(**kwargs)

    elif provider == "ollama":
        from langchain_community.chat_models import ChatOllama
        kwargs["model"] = model
        kwargs["base_url"] = settings.ollama_base_url
        return ChatOllama(**kwargs)

    else:
        raise ValueError(f"Unknown LLM provider: {provider}")
