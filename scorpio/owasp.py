"""OWASP API Security Top 10 (2023 edition) — catalogue used by the Supervisor.

Each entry exposes the minimum information the Supervisor needs to *pick* an
attack for a given endpoint (heuristic predicate ``applies_to``) and the
information the Reporter needs (severity baseline, business impact).
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Callable

from scorpio.state import Endpoint


@dataclass(frozen=True)
class OwaspAttack:
    """One attack class from the OWASP API Security Top 10."""

    owasp_id: str
    name: str
    description: str
    baseline_cvss: float
    baseline_severity: str
    applies_to: Callable[[Endpoint], bool]
    rationale_template: str


# ---------------------------------------------------------------------------
# Heuristics — these are pure Python (no LLM) so they run cheap.
# They produce *candidates*; the Attacker (LLM) is the one that decides how to
# actually execute the test.
# ---------------------------------------------------------------------------


def _looks_like_id(name: str) -> bool:
    lowered = name.lower()
    return (
        lowered.endswith("_id")
        or lowered.endswith("id")
        or lowered in {"uuid", "guid", "key"}
    )


def _is_object_lookup(endpoint: Endpoint) -> bool:
    return endpoint["is_object_lookup"] and endpoint["auth_required"]


def _has_writable_body(endpoint: Endpoint) -> bool:
    return endpoint["method"] in {"POST", "PUT", "PATCH"} and bool(endpoint.get("request_body"))


def _has_text_input(endpoint: Endpoint) -> bool:
    if _has_writable_body(endpoint):
        return True
    for param in endpoint["parameters"]:
        schema = param.get("schema") or {}
        if schema.get("type") in {"string", None}:
            return True
    return False


def _is_admin_or_sensitive(endpoint: Endpoint) -> bool:
    path_l = endpoint["path"].lower()
    return any(token in path_l for token in ("admin", "internal", "debug", "config", "users"))


def _is_auth_route(endpoint: Endpoint) -> bool:
    path_l = endpoint["path"].lower()
    return any(token in path_l for token in ("login", "token", "oauth", "signin", "auth"))


OWASP_API_TOP_10: list[OwaspAttack] = [
    OwaspAttack(
        owasp_id="API1:2023",
        name="Broken Object Level Authorization",
        description=(
            "Replay a legitimate request issued by user A but swap the resource "
            "identifier with one owned by user B. If the response reveals B's data "
            "with a 200 OK, the endpoint fails to enforce ownership."
        ),
        baseline_cvss=8.1,
        baseline_severity="HIGH",
        applies_to=_is_object_lookup,
        rationale_template=(
            "Path exposes a resource id ({id_params}); a horizontal privilege "
            "escalation is the highest-value test."
        ),
    ),
    OwaspAttack(
        owasp_id="API2:2023",
        name="Broken Authentication",
        description=(
            "Probe token issuance and validation: weak JWT signing key, alg=none, "
            "kid injection, expired token acceptance, missing refresh rotation."
        ),
        baseline_cvss=8.7,
        baseline_severity="HIGH",
        applies_to=lambda e: _is_auth_route(e) or not e["auth_required"],
        rationale_template="Authentication-adjacent route — JWT/credential weaknesses must be probed.",
    ),
    OwaspAttack(
        owasp_id="API3:2023",
        name="Broken Object Property Level Authorization",
        description=(
            "Try to read or modify properties the endpoint is supposed to hide "
            "(Mass Assignment of admin flags, exposure of internal fields)."
        ),
        baseline_cvss=7.5,
        baseline_severity="HIGH",
        applies_to=_has_writable_body,
        rationale_template=(
            "Writable JSON body — attempt mass assignment of privileged fields "
            "(is_admin, role, balance, etc.) absent from the spec."
        ),
    ),
    OwaspAttack(
        owasp_id="API4:2023",
        name="Unrestricted Resource Consumption",
        description=(
            "Hammer the endpoint without rate-limit awareness, request gigantic "
            "payloads, and force pagination boundaries to identify DoS surfaces."
        ),
        baseline_cvss=6.5,
        baseline_severity="MEDIUM",
        applies_to=lambda e: True,
        rationale_template="Generic resource-consumption probe (rate limiting & payload size).",
    ),
    OwaspAttack(
        owasp_id="API5:2023",
        name="Broken Function Level Authorization",
        description=(
            "Call privileged operations (admin, internal, debug) as a low-privilege "
            "user. A 200 OK means vertical privilege escalation."
        ),
        baseline_cvss=8.2,
        baseline_severity="HIGH",
        applies_to=_is_admin_or_sensitive,
        rationale_template="Endpoint path suggests privileged scope; test vertical escalation.",
    ),
    OwaspAttack(
        owasp_id="API6:2023",
        name="Unrestricted Access to Sensitive Business Flows",
        description=(
            "Abuse business logic (signup, reward redemption, voting) by issuing "
            "concurrent or scripted calls beyond the legitimate human pace."
        ),
        baseline_cvss=6.5,
        baseline_severity="MEDIUM",
        applies_to=lambda e: e["method"] == "POST",
        rationale_template="POST endpoint may expose an abusable business flow.",
    ),
    OwaspAttack(
        owasp_id="API7:2023",
        name="Server Side Request Forgery",
        description=(
            "Identify URL-accepting fields and try to coerce the server into "
            "fetching internal addresses (169.254.169.254, localhost, RFC1918)."
        ),
        baseline_cvss=8.6,
        baseline_severity="HIGH",
        applies_to=_has_text_input,
        rationale_template="String/URL inputs may be reachable for SSRF.",
    ),
    OwaspAttack(
        owasp_id="API8:2023",
        name="Security Misconfiguration",
        description=(
            "Look for verbose errors, missing security headers, permissive CORS, "
            "default credentials, exposed debug routes."
        ),
        baseline_cvss=5.3,
        baseline_severity="MEDIUM",
        applies_to=lambda e: True,
        rationale_template="Surface scan for misconfiguration indicators.",
    ),
    OwaspAttack(
        owasp_id="API9:2023",
        name="Improper Inventory Management",
        description=(
            "Probe for shadow endpoints — undocumented versions (/v1, /v2, /beta), "
            "deprecated routes, internal-only handlers leaked to production."
        ),
        baseline_cvss=5.8,
        baseline_severity="MEDIUM",
        applies_to=lambda e: True,
        rationale_template="Version pivot — search for shadow API surfaces around this route.",
    ),
    OwaspAttack(
        owasp_id="API10:2023",
        name="Unsafe Consumption of APIs",
        description=(
            "If the endpoint forwards values to a third-party API, validate that "
            "the response from that third-party is treated as untrusted input."
        ),
        baseline_cvss=6.5,
        baseline_severity="MEDIUM",
        applies_to=_has_text_input,
        rationale_template="Endpoint may relay to an upstream API; trust boundaries to verify.",
    ),
]


def applicable_attacks(endpoint: Endpoint) -> list[OwaspAttack]:
    """Return the OWASP attacks whose heuristic matches this endpoint."""
    return [attack for attack in OWASP_API_TOP_10 if attack.applies_to(endpoint)]


def render_rationale(attack: OwaspAttack, endpoint: Endpoint) -> str:
    """Format the attack's rationale template using endpoint context."""
    return attack.rationale_template.format(
        id_params=", ".join(endpoint["id_parameters"]) or "n/a",
        path=endpoint["path"],
        method=endpoint["method"],
    )
