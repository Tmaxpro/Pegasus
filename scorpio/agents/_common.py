"""Helpers shared by every agent node.

The LLMs are instructed to return strict JSON. Reality is messier — sometimes
they wrap the JSON in a Markdown fence or add a stray sentence. This module
contains the salvage logic so each agent stays focused on its domain logic.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from langchain_core.messages import AIMessage

logger = logging.getLogger(__name__)

_FENCE_RE = re.compile(r"```(?:json)?\s*(\{.*?\}|\[.*?\])\s*```", re.DOTALL)


def extract_text(message: AIMessage | str) -> str:
    """Flatten an Anthropic content list into plain text."""
    if isinstance(message, str):
        return message
    content = message.content
    if isinstance(content, str):
        return content
    chunks: list[str] = []
    for part in content:
        if isinstance(part, dict):
            if part.get("type") == "text":
                chunks.append(str(part.get("text", "")))
            elif "text" in part:
                chunks.append(str(part["text"]))
        else:
            chunks.append(str(part))
    return "\n".join(chunks)


def parse_json_block(raw: str) -> dict[str, Any] | list[Any]:
    """Best-effort JSON extraction from an LLM reply.

    Tries, in order:
    1. ``json.loads`` on the raw string.
    2. The contents of the first ```json ...``` fence.
    3. The substring between the outermost balanced braces / brackets.

    Raises:
        ValueError: if nothing parseable could be found.
    """
    raw = raw.strip()
    if not raw:
        raise ValueError("empty LLM response")

    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass

    fence_match = _FENCE_RE.search(raw)
    if fence_match:
        try:
            return json.loads(fence_match.group(1))
        except json.JSONDecodeError:
            pass

    for opener, closer in (("{", "}"), ("[", "]")):
        start = raw.find(opener)
        end = raw.rfind(closer)
        if start != -1 and end != -1 and end > start:
            candidate = raw[start : end + 1]
            try:
                return json.loads(candidate)
            except json.JSONDecodeError:
                continue

    logger.warning("Could not parse JSON from LLM reply: %s", raw[:500])
    raise ValueError("LLM reply did not contain valid JSON")
