"""Supervisor node — orchestrates the attack workflow.

The Supervisor is the only node that mutates the mission queue. It has two
modes:

- **Schedule mode** (cold start, or after a batch of missions completed): it
  asks the LLM to pick a small batch of (endpoint × OWASP attack) pairs out of
  the deterministic candidate set produced by :mod:`scorpio.owasp`.
- **Dispatch mode** (steady state): it simply pops the next pending mission
  off the queue and routes the graph to the Attacker.

Routing is done by :func:`supervisor_router`, used as a LangGraph
``add_conditional_edges`` callback.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from scorpio.agents._common import extract_text, parse_json_block
from scorpio.llm import get_llm
from scorpio.owasp import (
    OWASP_API_TOP_10,
    applicable_attacks,
    render_rationale,
)
from scorpio.prompts import SUPERVISOR_PROMPT
from scorpio.state import Endpoint, Mission, ScannerState

logger = logging.getLogger(__name__)

# How many fresh missions to schedule per Supervisor invocation. Keeping this
# small avoids one giant batch blowing the LLM context — the loop will come
# back through the supervisor anyway.
_BATCH_SIZE = 8


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _by_op(inventory: list[Endpoint]) -> dict[str, Endpoint]:
    return {ep["operation_id"]: ep for ep in inventory}


def _already_scheduled(
    queue: list[Mission],
    completed: list[Mission],
    operation_id: str,
    owasp_id: str,
) -> bool:
    for mission in (*queue, *completed):
        if (
            mission["endpoint"]["operation_id"] == operation_id
            and mission["owasp_id"] == owasp_id
        ):
            return True
    return False


def _build_candidate_pool(
    inventory: list[Endpoint],
    queue: list[Mission],
    completed: list[Mission],
) -> list[dict[str, Any]]:
    """Pre-filter via deterministic OWASP heuristics."""
    owasp_by_id = {a.owasp_id: a for a in OWASP_API_TOP_10}
    candidates: list[dict[str, Any]] = []
    for endpoint in inventory:
        for attack in applicable_attacks(endpoint):
            if _already_scheduled(queue, completed, endpoint["operation_id"], attack.owasp_id):
                continue
            candidates.append(
                {
                    "operation_id": endpoint["operation_id"],
                    "method": endpoint["method"],
                    "path": endpoint["path"],
                    "resource_type": endpoint["resource_type"],
                    "auth_required": endpoint["auth_required"],
                    "owasp_id": attack.owasp_id,
                    "owasp_name": attack.name,
                    "default_rationale": render_rationale(attack, endpoint),
                }
            )
    # Sort: higher baseline CVSS first, then alphabetical to stay deterministic
    candidates.sort(
        key=lambda c: (-owasp_by_id[c["owasp_id"]].baseline_cvss, c["operation_id"])
    )
    return candidates


def _make_mission(
    endpoint: Endpoint,
    owasp_id: str,
    rationale: str,
) -> Mission:
    owasp = next((a for a in OWASP_API_TOP_10 if a.owasp_id == owasp_id), None)
    return Mission(
        endpoint=endpoint,
        owasp_id=owasp_id,
        owasp_name=owasp.name if owasp else owasp_id,
        rationale=rationale or (owasp.description if owasp else ""),
        status="pending",
        attempts=0,
    )


# ---------------------------------------------------------------------------
# LLM scheduling
# ---------------------------------------------------------------------------


def _llm_schedule(
    state: ScannerState, candidates: list[dict[str, Any]]
) -> list[dict[str, str]]:
    """Ask the fast model to pick a batch of missions from the candidate pool."""
    if not candidates:
        return []
    pool = candidates[: _BATCH_SIZE * 4]  # show the LLM a reasonable slice
    llm = get_llm("fast")
    payload = {
        "candidates": pool,
        "completed_count": len(state.get("completed_missions", [])),
        "queued_count": len(state.get("mission_queue", [])),
        "batch_size": _BATCH_SIZE,
    }
    response = llm.invoke(
        [
            SystemMessage(content=SUPERVISOR_PROMPT),
            HumanMessage(
                content=(
                    "Schedule up to batch_size missions, prioritising the highest-"
                    "impact attacks first.\n\n"
                    f"```json\n{json.dumps(payload, indent=2)}\n```"
                )
            ),
        ]
    )
    try:
        parsed = parse_json_block(extract_text(response))
    except ValueError:
        logger.warning("[supervisor] LLM did not return JSON; falling back to top-K candidates")
        return [
            {
                "operation_id": c["operation_id"],
                "owasp_id": c["owasp_id"],
                "rationale": c["default_rationale"],
            }
            for c in candidates[:_BATCH_SIZE]
        ]
    if not isinstance(parsed, dict):
        return []
    missions = parsed.get("next_missions") or []
    return [m for m in missions if isinstance(m, dict)]


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


def supervisor_node(state: ScannerState) -> dict[str, Any]:
    """LangGraph node: schedule new missions or hand one off to the Attacker."""
    inventory = state.get("api_inventory") or []
    queue: list[Mission] = list(state.get("mission_queue") or [])
    completed: list[Mission] = list(state.get("completed_missions") or [])
    by_op = _by_op(inventory)

    # If a mission just came back, pop it off and persist the result.
    just_finished = state.get("current_mission")
    if just_finished is not None:
        completed.append(just_finished)

    # Pop the next pending mission, if any.
    next_mission: Mission | None = queue.pop(0) if queue else None

    # If the queue is empty and we still have nothing to do, ask the LLM to
    # schedule a fresh batch.
    if next_mission is None:
        candidates = _build_candidate_pool(inventory, queue, completed)
        if candidates:
            picks = _llm_schedule(state, candidates)
            for pick in picks:
                endpoint = by_op.get(pick.get("operation_id", ""))
                owasp_id = pick.get("owasp_id", "")
                if endpoint is None or not owasp_id:
                    continue
                if _already_scheduled(queue, completed, endpoint["operation_id"], owasp_id):
                    continue
                queue.append(
                    _make_mission(
                        endpoint,
                        owasp_id,
                        pick.get("rationale", ""),
                    )
                )
            logger.info("[supervisor] scheduled %d new missions", len(queue))
            if queue:
                next_mission = queue.pop(0)

    if next_mission is not None:
        next_mission = {**next_mission, "status": "running", "attempts": next_mission["attempts"] + 1}

    summary_parts: list[str] = []
    if just_finished is not None:
        summary_parts.append(
            f"completed {just_finished['owasp_id']} on {just_finished['endpoint']['operation_id']}"
        )
    if next_mission is not None:
        summary_parts.append(
            f"dispatching {next_mission['owasp_id']} -> {next_mission['endpoint']['operation_id']}"
        )
    else:
        summary_parts.append("no more missions, routing to Reporter")
    summary = "Supervisor: " + "; ".join(summary_parts)
    logger.info("[supervisor] %s", summary)

    return {
        "mission_queue": queue,
        "current_mission": next_mission,
        "completed_missions": completed,
        "messages": [AIMessage(content=summary)],
    }


# ---------------------------------------------------------------------------
# Conditional routing
# ---------------------------------------------------------------------------


def supervisor_router(state: ScannerState) -> str:
    """Return the name of the next node to run."""
    if state.get("current_mission") is not None:
        return "attacker"
    return "reporter"
