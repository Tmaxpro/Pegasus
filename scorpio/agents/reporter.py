"""Reporter node — assembles the final Markdown report.

The Reporter never asks the LLM to invent findings; it only asks it to *style*
the data already validated by the Auditor. If no findings exist, a short
"clean run" report is produced deterministically.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime
from typing import Any

from langchain_core.messages import AIMessage, HumanMessage, SystemMessage

from scorpio.agents._common import extract_text
from scorpio.config import get_settings
from scorpio.llm import get_llm
from scorpio.prompts import REPORTER_PROMPT
from scorpio.state import ScannerState, Vulnerability

logger = logging.getLogger(__name__)


def _render_empty_report(state: ScannerState) -> str:
    completed = state.get("completed_missions") or []
    inventory = state.get("api_inventory") or []
    return (
        "# Scorpio — API Penetration Test Report\n\n"
        "## 1. Executive Summary\n\n"
        f"Target: `{state.get('target_base_url', 'n/a')}`. "
        f"{len(inventory)} endpoints inventoried, {len(completed)} attack missions "
        "executed, **no vulnerabilities validated by the Auditor.**\n\n"
        "## 2. Findings Overview\n\n_No findings._\n\n"
        "## 3. Detailed Findings\n\n_None._\n\n"
        "## 4. Methodology\n\n"
        "Scorpio is a Grey-Box DAST framework that combines a deterministic "
        "OpenAPI inventory pass, a multi-agent LangGraph workflow "
        "(Analyst, Supervisor, Attacker, Auditor, Reporter) and an isolated "
        "Docker sandbox running offensive CLI tools "
        "(ffuf, sqlmap, jwt-tool). Each finding is validated by an Auditor "
        "agent that distrusts status codes alone, eliminating WAF blocks, "
        "escaped reflections and trivial 200 OKs as false positives.\n"
    )


def _summary_table(vulns: list[Vulnerability]) -> str:
    if not vulns:
        return "_No findings._"
    lines = [
        "| # | OWASP ID | Title | Endpoint | Severity | CVSS |",
        "|---|----------|-------|----------|----------|------|",
    ]
    for idx, v in enumerate(vulns, start=1):
        endpoint = f"`{v['endpoint_method']} {v['endpoint_path']}`"
        lines.append(
            f"| {idx} | {v['owasp_id']} | {v['owasp_name']} | {endpoint} | "
            f"{v['severity']} | {v['cvss_score']} |"
        )
    return "\n".join(lines)


def _write_report(content: str) -> str:
    settings = get_settings()
    stamp = datetime.utcnow().strftime("%Y%m%d_%H%M%SZ")
    path = settings.reports_dir / f"api_pentest_report_{stamp}.md"
    path.write_text(content, encoding="utf-8")
    # Also write a stable filename (latest) for tooling/CI.
    latest = settings.reports_dir / "api_pentest_report.md"
    latest.write_text(content, encoding="utf-8")
    return str(path)


def reporter_node(state: ScannerState) -> dict[str, Any]:
    """LangGraph node: render the Markdown report and persist it on disk."""
    vulnerabilities: list[Vulnerability] = state.get("vulnerabilities_found") or []
    completed = state.get("completed_missions") or []
    inventory = state.get("api_inventory") or []

    logger.info(
        "[reporter] writing report: %d vulnerabilities, %d missions executed",
        len(vulnerabilities),
        len(completed),
    )

    if not vulnerabilities:
        report = _render_empty_report(state)
        path = _write_report(report)
        return {
            "report_path": path,
            "messages": [
                AIMessage(content=f"Reporter: clean run, wrote report to {path}")
            ],
        }

    llm = get_llm("main")
    payload = {
        "target_base_url": state.get("target_base_url", ""),
        "endpoint_count": len(inventory),
        "mission_count": len(completed),
        "summary_table_markdown": _summary_table(vulnerabilities),
        "vulnerabilities": vulnerabilities,
    }
    response = llm.invoke(
        [
            SystemMessage(content=REPORTER_PROMPT),
            HumanMessage(
                content=(
                    "Generate the final Markdown pentest report from this "
                    "validated data. Do not invent additional findings; "
                    "render exactly the ones provided.\n\n"
                    f"```json\n{json.dumps(payload, indent=2, default=str)}\n```"
                )
            ),
        ]
    )
    rendered = extract_text(response).strip()
    if not rendered.startswith("#"):
        # Fall back to the deterministic skeleton if the LLM misbehaved.
        rendered = (
            "# Scorpio — API Penetration Test Report\n\n"
            "## 1. Executive Summary\n\n"
            f"Target: `{state.get('target_base_url', 'n/a')}`. "
            f"{len(vulnerabilities)} validated vulnerabilities across "
            f"{len(inventory)} endpoints.\n\n"
            "## 2. Findings Overview\n\n"
            f"{_summary_table(vulnerabilities)}\n\n"
            "## 3. Detailed Findings\n\n"
            + "\n\n".join(_fallback_finding_block(i, v) for i, v in enumerate(vulnerabilities, 1))
            + "\n\n## 4. Methodology\n\nScorpio multi-agent grey-box DAST.\n"
        )

    path = _write_report(rendered)
    return {
        "report_path": path,
        "messages": [AIMessage(content=f"Reporter: wrote report to {path}")],
    }


def _fallback_finding_block(idx: int, v: Vulnerability) -> str:
    return (
        f"### Finding {idx} — {v['owasp_id']} — {v['owasp_name']}\n\n"
        f"- **Endpoint**: `{v['endpoint_method']} {v['endpoint_path']}`\n"
        f"- **Severity**: {v['severity']}\n"
        f"- **CVSS (estimated)**: {v['cvss_score']}\n"
        f"- **Business impact**: {v['business_impact']}\n"
        f"- **Technical description**: {v['description']}\n"
        "- **Proof of Concept**:\n\n"
        f"```http\n{v['poc_request']}\n```\n\n"
        f"```http\n{v['poc_response']}\n```\n\n"
        "- **Remediation**:\n\n"
        f"```text\n{v['remediation']}\n```"
    )
