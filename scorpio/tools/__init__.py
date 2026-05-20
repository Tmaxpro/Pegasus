"""Tool surface exposed to the agents.

Only the symbols re-exported here are meant to be bound to an LLM via
``llm.bind_tools(...)``.
"""

from scorpio.tools.sandbox import (
    SandboxError,
    SandboxManager,
    execute_sandbox_tool,
    get_sandbox_manager,
)

__all__ = [
    "SandboxError",
    "SandboxManager",
    "execute_sandbox_tool",
    "get_sandbox_manager",
]
