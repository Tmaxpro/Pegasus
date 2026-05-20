"""Shared graph state.

The whole multi-agent workflow communicates exclusively through this single
TypedDict. Anything that needs to be remembered across nodes (or across crashes,
thanks to the SqliteSaver checkpointer) MUST land here.
"""

from __future__ import annotations

from typing import Annotated, Any, Literal, NotRequired, TypedDict

from langgraph.graph.message import add_messages


# ---------------------------------------------------------------------------
# Sub-schemas (kept as TypedDicts to stay JSON-serialisable for the checkpointer)
# ---------------------------------------------------------------------------


class Endpoint(TypedDict):
    """A single API operation extracted from the OpenAPI document."""

    path: str
    method: Literal["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS", "HEAD"]
    operation_id: str
    summary: str
    parameters: list[dict[str, Any]]
    request_body: dict[str, Any] | None
    responses: dict[str, Any]
    auth_required: bool
    # --- Semantic enrichment produced by the Analyst -----------------------
    resource_type: str          # "user", "invoice", "admin_panel", ...
    is_object_lookup: bool      # GET/PUT/DELETE /resources/{id}
    id_parameters: list[str]    # names of params that look like resource ids
    dependencies: list[str]     # operation_ids that must run before this one


class Mission(TypedDict):
    """A single attack task scheduled against one endpoint."""

    endpoint: Endpoint
    owasp_id: str               # e.g. "API1:2023"
    owasp_name: str             # "Broken Object Level Authorization"
    rationale: str              # Why the supervisor picked this attack here
    status: Literal["pending", "running", "validated", "rejected", "errored"]
    attempts: int


class Vulnerability(TypedDict):
    """A finding that survived the Auditor's false-positive elimination."""

    owasp_id: str
    owasp_name: str
    endpoint_path: str
    endpoint_method: str
    severity: Literal["INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"]
    cvss_score: float
    business_impact: str
    description: str
    poc_request: str            # raw HTTP request
    poc_response: str           # raw HTTP response
    remediation: str            # remediation code / configuration
    evidence: str               # auditor's reasoning


# ---------------------------------------------------------------------------
# Main state dictionary
# ---------------------------------------------------------------------------


class ScannerState(TypedDict):
    """Shared state passed between every LangGraph node.

    Lists are persisted as-is at every checkpoint; mutable updates MUST therefore
    return a fresh list (or rely on the LangGraph reducer for ``messages``).
    """

    # Conversational memory (reduced by `add_messages`)
    messages: Annotated[list, add_messages]

    # --- Input parameters ---
    target_base_url: str
    openapi_spec_path: str
    auth_tokens: dict[str, str]     # {"user_a": "Bearer ...", "user_b": "Bearer ..."}

    # --- Built by the Analyst ---
    api_inventory: list[Endpoint]

    # --- Built by the Supervisor ---
    mission_queue: list[Mission]
    current_mission: Mission | None
    completed_missions: list[Mission]

    # --- Filled by the Attacker (RAOA) ---
    sandbox_output: str
    last_attacker_summary: str       # short structured summary handed to Auditor

    # --- Filled by the Auditor ---
    vulnerabilities_found: list[Vulnerability]

    # --- Set by the Reporter ---
    report_path: NotRequired[str]
