"""LLM factories.

A thin layer over `langchain_anthropic.ChatAnthropic` so the rest of the code
asks for a model by *role* (``main`` for reasoning agents, ``fast`` for the
Supervisor) rather than hard-coding a model id.
"""

from __future__ import annotations

from functools import lru_cache
from typing import Literal

from langchain_anthropic import ChatAnthropic

from scorpio.config import get_settings

LLMRole = Literal["main", "fast"]


@lru_cache(maxsize=4)
def get_llm(role: LLMRole = "main") -> ChatAnthropic:
    """Return a configured ChatAnthropic client for the given role."""
    settings = get_settings()
    model = settings.model_name if role == "main" else settings.fast_model_name
    kwargs: dict = {
        "model": model,
        "temperature": settings.llm_temperature,
        "max_tokens": settings.llm_max_tokens,
    }
    if settings.anthropic_api_key:
        kwargs["api_key"] = settings.anthropic_api_key
    return ChatAnthropic(**kwargs)
