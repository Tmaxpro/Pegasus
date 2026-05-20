"""Attacker node — Reflection / Action / Observation / Adjustment loop.

The Attacker is the only agent allowed to call ``execute_sandbox_tool``. It
runs an in-node loop that calls the LLM, executes any tool calls the LLM
emits, feeds the results back in, and stops as soon as the LLM produces a
final JSON verdict (or after ``attacker_max_iterations`` to prevent runaways).

Why an explicit loop rather than a LangGraph subgraph: the RAOA cycle is
self-contained (single mission, single tool), so keeping it inside one node
keeps the parent graph readable and avoids checkpointing every micro-step.
The mission boundary is the natural checkpoint.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage, ToolMessage

from scorpio.agents._common import extract_text, parse_json_block
from scorpio.config import get_settings
from scorpio.llm import get_llm
from scorpio.prompts import ATTACKER_PROMPT
from scorpio.state import Mission, ScannerState
from scorpio.tools.sandbox import (
    SandboxError,
    execute_sandbox_tool,
    serialise_sandbox_payload,
)

logger = logging.getLogger(__name__)


def _mission_brief(mission: Mission, target: str, auth_tokens: dict[str, str]) -> str:
    """Render the human-readable briefing handed to the Attacker."""
    endpoint = mission["endpoint"]
    body_schema: str | dict = "n/a"
    if endpoint["request_body"]:
        content = (endpoint["request_body"] or {}).get("content") or {}
        first = next(iter(content.values()), {}) if content else {}
        body_schema = first.get("schema", "n/a")

    token_hint = {
        name: (value[:24] + "...") if len(value) > 24 else value
        for name, value in auth_tokens.items()
    }

    brief = {
        "target_base_url": target,
        "owasp_id": mission["owasp_id"],
        "owasp_name": mission["owasp_name"],
        "rationale": mission["rationale"],
        "endpoint": {
            "method": endpoint["method"],
            "path": endpoint["path"],
            "operation_id": endpoint["operation_id"],
            "resource_type": endpoint["resource_type"],
            "summary": endpoint["summary"],
            "auth_required": endpoint["auth_required"],
            "parameters": endpoint["parameters"],
            "request_body_schema": body_schema,
            "id_parameters": endpoint["id_parameters"],
        },
        "available_auth_tokens": list(token_hint.keys()),
        "auth_tokens_preview": token_hint,
    }
    return (
        "MISSION BRIEFING — execute the RAOA loop, then emit your final JSON "
        "verdict.\n\n"
        f"```json\n{json.dumps(brief, indent=2, default=str)}\n```\n\n"
        "Reminder: use `execute_sandbox_tool` with command_array as a real "
        "Python list. Send the FINAL message as a JSON object only, no prose."
    )


def _resolve_tool_call(tool_call: dict[str, Any]) -> str:
    """Execute one tool call and return the text payload for the ToolMessage."""
    name = tool_call.get("name")
    args = tool_call.get("args") or {}
    if name != execute_sandbox_tool.name:
        return f"[unknown tool: {name}]"
    try:
        command_array = serialise_sandbox_payload(args.get("command_array"))
    except SandboxError as exc:
        return f"[sandbox error] {exc}"
    output_file = args.get("output_file")
    return execute_sandbox_tool.invoke(
        {"command_array": command_array, "output_file": output_file}
    )


def attacker_node(state: ScannerState) -> dict[str, Any]:
    """LangGraph node: run the RAOA loop for the current mission."""
    mission = state.get("current_mission")
    if mission is None:
        logger.warning("[attacker] invoked without a current_mission — skipping")
        return {
            "sandbox_output": "",
            "last_attacker_summary": json.dumps({"verdict": "no_finding"}),
        }

    settings = get_settings()
    llm = get_llm("main").bind_tools([execute_sandbox_tool])
    target_base_url = state.get("target_base_url", "")
    auth_tokens = state.get("auth_tokens", {}) or {}

    history = [
        SystemMessage(content=ATTACKER_PROMPT),
        HumanMessage(content=_mission_brief(mission, target_base_url, auth_tokens)),
    ]

    last_sandbox_output = ""
    final_text = ""

    for iteration in range(settings.attacker_max_iterations):
        logger.info(
            "[attacker] iter=%d mission=%s owasp=%s",
            iteration + 1,
            mission["endpoint"]["operation_id"],
            mission["owasp_id"],
        )
        response: AIMessage = llm.invoke(history)
        history.append(response)

        tool_calls = response.tool_calls or []
        if not tool_calls:
            # No tool call — assume this is the final JSON verdict.
            final_text = extract_text(response)
            break

        for tool_call in tool_calls:
            output = _resolve_tool_call(tool_call)
            last_sandbox_output = output
            history.append(
                ToolMessage(content=output, tool_call_id=tool_call["id"])
            )
    else:
        # Loop budget exhausted — force a verdict request.
        logger.info("[attacker] max iterations reached, asking for final verdict")
        history.append(
            HumanMessage(
                content=(
                    "RAOA budget exhausted. Stop calling tools and emit your "
                    "FINAL JSON verdict now, based on the evidence you already have."
                )
            )
        )
        response = get_llm("main").invoke(history)
        history.append(response)
        final_text = extract_text(response)

    if not final_text:
        final_text = json.dumps(
            {
                "verdict": "inconclusive",
                "owasp_id": mission["owasp_id"],
                "endpoint_path": mission["endpoint"]["path"],
                "endpoint_method": mission["endpoint"]["method"],
                "command_used": [],
                "raw_request": "",
                "raw_response": last_sandbox_output,
                "indicators": ["attacker emitted no final message"],
                "next_step_for_auditor": "treat as no finding",
            }
        )

    # Sanity-check that the final text is JSON; if not, wrap it.
    try:
        parse_json_block(final_text)
    except ValueError:
        logger.warning("[attacker] final message was not JSON; wrapping as inconclusive")
        final_text = json.dumps(
            {
                "verdict": "inconclusive",
                "owasp_id": mission["owasp_id"],
                "endpoint_path": mission["endpoint"]["path"],
                "endpoint_method": mission["endpoint"]["method"],
                "command_used": [],
                "raw_request": "",
                "raw_response": last_sandbox_output,
                "indicators": [final_text[:400]],
                "next_step_for_auditor": "no parseable verdict",
            }
        )

    summary_msg = (
        f"Attacker: completed RAOA on {mission['endpoint']['operation_id']} "
        f"for {mission['owasp_id']}."
    )
    logger.info("[attacker] %s", summary_msg)

    return {
        "sandbox_output": last_sandbox_output,
        "last_attacker_summary": final_text,
        "messages": [AIMessage(content=summary_msg)],
    }
