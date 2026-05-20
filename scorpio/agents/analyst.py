"""Analyst node — parses the OpenAPI document and enriches it semantically.

The Analyst combines two passes:

1. **Deterministic ingestion**: load the spec with ``PyYAML``/``json`` and
   resolve ``$ref`` with :mod:`jsonref`, then build a structural inventory
   (path, method, parameters, request body, declared auth).
2. **Semantic enrichment**: ask the LLM to label each operation with a
   resource type, identify object-lookup routes, list ID-like parameters and
   guess inter-operation dependencies (e.g. ``POST /cards`` before
   ``GET /cards/{card_id}``).

The structural pass is what guarantees the framework still works when the LLM
mis-classifies an endpoint — the Supervisor heuristics can fall back to it.
"""

from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import jsonref
import yaml
from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from scorpio.agents._common import extract_text, parse_json_block
from scorpio.llm import get_llm
from scorpio.prompts import ANALYST_PROMPT
from scorpio.state import Endpoint, ScannerState

logger = logging.getLogger(__name__)

_HTTP_METHODS = {"get", "post", "put", "patch", "delete", "options", "head"}


# ---------------------------------------------------------------------------
# Deterministic structural pass
# ---------------------------------------------------------------------------


def _load_spec(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        raw = yaml.safe_load(text)
    else:
        raw = json.loads(text)
    # Resolve $ref so downstream code never has to chase pointers.
    return jsonref.replace_refs(raw, jsonschema=False, lazy_load=False)  # type: ignore[return-value]


def _looks_like_id_name(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered.endswith("_id")
        or lowered.endswith("id")
        or lowered in {"uuid", "guid", "key", "slug"}
    )


def _requires_auth(operation: dict[str, Any], global_security: list) -> bool:
    if "security" in operation:
        return bool(operation["security"])
    return bool(global_security)


def _build_inventory(spec: dict[str, Any]) -> list[Endpoint]:
    """Walk the OpenAPI spec and return one Endpoint per (path, method) pair."""
    inventory: list[Endpoint] = []
    global_security = spec.get("security", [])
    paths = spec.get("paths", {}) or {}

    for path, item in paths.items():
        if not isinstance(item, dict):
            continue
        common_params = item.get("parameters", []) or []
        for method, op in item.items():
            if method.lower() not in _HTTP_METHODS or not isinstance(op, dict):
                continue
            parameters = list(common_params) + list(op.get("parameters", []) or [])
            path_param_names = [
                p["name"] for p in parameters if p.get("in") == "path"
            ]
            method_upper = method.upper()
            is_object_lookup = (
                method_upper in {"GET", "PUT", "PATCH", "DELETE"}
                and any(_looks_like_id_name(name) for name in path_param_names)
            )
            id_parameters = [
                p["name"] for p in parameters if _looks_like_id_name(p.get("name", ""))
            ]

            inventory.append(
                Endpoint(
                    path=path,
                    method=method_upper,  # type: ignore[arg-type]
                    operation_id=op.get("operationId") or f"{method_upper} {path}",
                    summary=op.get("summary") or op.get("description") or "",
                    parameters=parameters,
                    request_body=op.get("requestBody"),
                    responses=op.get("responses", {}) or {},
                    auth_required=_requires_auth(op, global_security),
                    resource_type="unknown",
                    is_object_lookup=is_object_lookup,
                    id_parameters=id_parameters,
                    dependencies=[],
                )
            )

    return inventory


# ---------------------------------------------------------------------------
# Semantic LLM pass
# ---------------------------------------------------------------------------


def _condense_for_llm(inventory: list[Endpoint]) -> list[dict[str, Any]]:
    """Strip the inventory down to what the LLM actually needs to reason."""
    return [
        {
            "operation_id": ep["operation_id"],
            "method": ep["method"],
            "path": ep["path"],
            "summary": ep["summary"],
            "auth_required": ep["auth_required"],
            "path_parameters": [
                p["name"] for p in ep["parameters"] if p.get("in") == "path"
            ],
            "query_parameters": [
                p["name"] for p in ep["parameters"] if p.get("in") == "query"
            ],
            "has_body": ep["request_body"] is not None,
        }
        for ep in inventory
    ]


def _apply_semantic_enrichment(
    inventory: list[Endpoint], enrichment: list[dict[str, Any]]
) -> list[Endpoint]:
    """Merge LLM-produced labels back into the deterministic inventory."""
    by_op = {ep["operation_id"]: ep for ep in inventory}
    for entry in enrichment:
        ep = by_op.get(entry.get("operation_id"))
        if ep is None:
            continue
        if "resource_type" in entry and entry["resource_type"]:
            ep["resource_type"] = str(entry["resource_type"]).lower()
        if "is_object_lookup" in entry:
            ep["is_object_lookup"] = bool(entry["is_object_lookup"])
        if "id_parameters" in entry and isinstance(entry["id_parameters"], list):
            # union with the deterministic list
            ep["id_parameters"] = sorted(
                {*ep["id_parameters"], *(str(p) for p in entry["id_parameters"])}
            )
        if "dependencies" in entry and isinstance(entry["dependencies"], list):
            ep["dependencies"] = [str(d) for d in entry["dependencies"]]
    return list(by_op.values())


# ---------------------------------------------------------------------------
# Node
# ---------------------------------------------------------------------------


def analyst_node(state: ScannerState) -> dict[str, Any]:
    """LangGraph node: build the semantic api_inventory from the OpenAPI spec."""
    spec_path = Path(state["openapi_spec_path"])
    if not spec_path.exists():
        raise FileNotFoundError(f"OpenAPI spec not found: {spec_path}")

    logger.info("[analyst] loading spec %s", spec_path)
    spec = _load_spec(spec_path)
    inventory = _build_inventory(spec)
    logger.info("[analyst] extracted %d endpoints", len(inventory))

    if not inventory:
        return {
            "api_inventory": [],
            "messages": [
                AIMessage(content="Analyst: no endpoints found in the OpenAPI document.")
            ],
        }

    condensed = _condense_for_llm(inventory)
    llm = get_llm("main")
    response = llm.invoke(
        [
            SystemMessage(content=ANALYST_PROMPT),
            HumanMessage(
                content=(
                    "Here is the deterministic inventory extracted from the OpenAPI "
                    "document. Enrich every operation as instructed.\n\n"
                    f"```json\n{json.dumps(condensed, indent=2)}\n```"
                )
            ),
        ]
    )

    raw = extract_text(response)
    try:
        parsed = parse_json_block(raw)
        enrichment = parsed["endpoints"] if isinstance(parsed, dict) else parsed  # type: ignore[index]
        inventory = _apply_semantic_enrichment(inventory, list(enrichment))
    except (ValueError, KeyError, TypeError) as exc:
        logger.warning(
            "[analyst] semantic enrichment failed (%s) — keeping deterministic inventory",
            exc,
        )

    summary = (
        f"Analyst: catalogued {len(inventory)} endpoints, "
        f"{sum(1 for e in inventory if e['is_object_lookup'])} are object lookups, "
        f"{sum(1 for e in inventory if e['auth_required'])} require authentication."
    )
    logger.info("[analyst] %s", summary)
    return {
        "api_inventory": inventory,
        "messages": [AIMessage(content=summary)],
    }
