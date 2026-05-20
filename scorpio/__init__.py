"""Scorpio — Autonomous Grey-Box DAST framework for REST APIs.

A multi-agent system built on LangGraph that reasons over the semantics of an
API (OpenAPI specification, resource graph, authentication boundaries) and
orchestrates real offensive tools (ffuf, sqlmap, jwt-tool) inside an isolated
Docker sandbox to discover OWASP API Security Top 10 vulnerabilities.
"""

from scorpio.state import ScannerState

__all__ = ["ScannerState"]
__version__ = "0.1.0"
