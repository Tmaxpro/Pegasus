"""Auditor node — false-positive elimination.

The Auditor never re-runs an attack. It consumes the JSON verdict produced by
the Attacker, applies a stricter LLM judgement (with explicit instructions to
distrust status codes alone), and either appends a structured
:class:`Vulnerability` entry to ``state.vulnerabilities_found`` or rejects it.
"""

from __future__ import annotations

import json
import logging
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from scorpio.agents._common import extract_text, parse_json_block
from scorpio.llm import get_llm
from scorpio.owasp import OWASP_API_TOP_10
from scorpio.prompts import AUDITOR_PROMPT
from scorpio.state import Mission, ScannerState, Vulnerability

logger = logging.getLogger(__name__)

_VALID_SEVERITIES = {"INFO", "LOW", "MEDIUM", "HIGH", "CRITICAL"}


def _baseline_for(owasp_id: str) -> tuple[str, float, str]:
    for attack in OWASP_API_TOP_10:
        if attack.owasp_id == owasp_id:
            return attack.name, attack.baseline_cvss, attack.baseline_severity
    return owasp_id, 5.0, "MEDIUM"


def _coerce_vulnerability(
    parsed: dict[str, Any], mission: Mission, fallback_response: str
) -> Vulnerability:
    """Normalise the auditor's JSON into a Vulnerability TypedDict."""
    owasp_id = parsed.get("owasp_id") or mission["owasp_id"]
    baseline_name, baseline_cvss, baseline_severity = _baseline_for(owasp_id)

    severity = str(parsed.get("severity") or baseline_severity).upper()
    if severity not in _VALID_SEVERITIES:
        severity = baseline_severity

    try:
        cvss = float(parsed.get("cvss_score") or baseline_cvss)
    except (TypeError, ValueError):
        cvss = baseline_cvss

    return Vulnerability(
        owasp_id=owasp_id,
        owasp_name=str(parsed.get("owasp_name") or baseline_name),
        endpoint_path=str(parsed.get("endpoint_path") or mission["endpoint"]["path"]),
        endpoint_method=str(
            parsed.get("endpoint_method") or mission["endpoint"]["method"]
        ),
        severity=severity,  # type: ignore[arg-type]
        cvss_score=round(cvss, 1),
        business_impact=str(parsed.get("business_impact") or ""),
        description=str(parsed.get("description") or ""),
        poc_request=str(parsed.get("poc_request") or ""),
        poc_response=str(parsed.get("poc_response") or fallback_response),
        remediation=str(parsed.get("remediation") or ""),
        evidence=str(parsed.get("evidence") or ""),
    )


def auditor_node(state: ScannerState) -> dict[str, Any]:
    """LangGraph node: validate (or reject) the Attacker's last finding."""
    mission = state.get("current_mission")
    attacker_summary = state.get("last_attacker_summary") or ""
    sandbox_output = state.get("sandbox_output") or ""
    existing: list[Vulnerability] = list(state.get("vulnerabilities_found") or [])

    if mission is None or not attacker_summary:
        logger.warning("[auditor] called with no mission/summary — skipping")
        return {"vulnerabilities_found": existing}

    llm = get_llm("main")
    payload = {
        "mission": {
            "owasp_id": mission["owasp_id"],
            "owasp_name": mission["owasp_name"],
            "endpoint": {
                "method": mission["endpoint"]["method"],
                "path": mission["endpoint"]["path"],
                "resource_type": mission["endpoint"]["resource_type"],
                "auth_required": mission["endpoint"]["auth_required"],
            },
            "rationale": mission["rationale"],
        },
        "attacker_verdict": attacker_summary,
        "sandbox_output_excerpt": sandbox_output[-4000:],
    }
    response = llm.invoke(
        [
            SystemMessage(content=AUDITOR_PROMPT),
            HumanMessage(
                content=(
                    "Validate the Attacker's verdict. Reject WAF blocks, "
                    "rate-limit responses, escaped reflections and trivial 200 "
                    "OKs that do not actually demonstrate impact.\n\n"
                    f"```json\n{json.dumps(payload, indent=2, default=str)}\n```"
                )
            ),
        ]
    )

    try:
        parsed = parse_json_block(extract_text(response))
    except ValueError:
        logger.warning("[auditor] non-JSON response, treating as rejected")
        return {"vulnerabilities_found": existing}

    if not isinstance(parsed, dict):
        return {"vulnerabilities_found": existing}

    validated = bool(parsed.get("validated"))
    if validated:
        vuln = _coerce_vulnerability(parsed, mission, sandbox_output)
        existing.append(vuln)
        summary = (
            f"Auditor: VALIDATED {vuln['owasp_id']} on "
            f"{vuln['endpoint_method']} {vuln['endpoint_path']} "
            f"(severity={vuln['severity']}, CVSS={vuln['cvss_score']})"
        )
        # Update the mission status so the supervisor's completed_missions
        # record reflects reality.
        mission_status: Mission = {**mission, "status": "validated"}
    else:
        summary = (
            f"Auditor: rejected {mission['owasp_id']} on "
            f"{mission['endpoint']['method']} {mission['endpoint']['path']} "
            f"— {str(parsed.get('evidence') or '')[:120]}"
        )
        mission_status = {**mission, "status": "rejected"}

    logger.info("[auditor] %s", summary)

    return {
        "vulnerabilities_found": existing,
        "current_mission": mission_status,
        "messages": [AIMessage(content=summary)],
    }
