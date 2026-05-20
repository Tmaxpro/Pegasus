"""Scorpio CLI entry point.

Usage:

    python main.py scan \\
        --spec examples/vulnerable_api.yaml \\
        --base-url http://localhost:8000 \\
        --token-a "Bearer <user_a_jwt>" \\
        --token-b "Bearer <user_b_jwt>"

Other commands::

    python main.py sandbox build      # build the docker sandbox image
    python main.py sandbox shell      # open an interactive shell in the sandbox
    python main.py sandbox stop       # stop the running sandbox container
    python main.py resume --thread <id>
"""

from __future__ import annotations

import logging
import sys
import uuid
from pathlib import Path
from typing import Annotated

import typer
from rich.console import Console
from rich.logging import RichHandler
from rich.panel import Panel
from rich.table import Table

from scorpio.config import get_settings
from scorpio.graph import compiled_graph
from scorpio.state import ScannerState
from scorpio.tools import get_sandbox_manager

app = typer.Typer(help="Scorpio — autonomous grey-box DAST for REST APIs.")
sandbox_app = typer.Typer(help="Manage the offensive sandbox container.")
app.add_typer(sandbox_app, name="sandbox")

console = Console()


def _configure_logging() -> None:
    settings = get_settings()
    logging.basicConfig(
        level=settings.log_level,
        format="%(message)s",
        datefmt="[%X]",
        handlers=[RichHandler(rich_tracebacks=True, show_path=False)],
    )


def _build_initial_state(
    spec: Path,
    base_url: str,
    token_a: str | None,
    token_b: str | None,
) -> ScannerState:
    auth_tokens: dict[str, str] = {}
    if token_a:
        auth_tokens["user_a"] = token_a
    if token_b:
        auth_tokens["user_b"] = token_b

    return ScannerState(
        messages=[],
        target_base_url=base_url.rstrip("/"),
        openapi_spec_path=str(spec),
        auth_tokens=auth_tokens,
        api_inventory=[],
        mission_queue=[],
        current_mission=None,
        completed_missions=[],
        sandbox_output="",
        last_attacker_summary="",
        vulnerabilities_found=[],
    )


def _render_final_state(state: dict) -> None:
    vulns = state.get("vulnerabilities_found") or []
    completed = state.get("completed_missions") or []
    inventory = state.get("api_inventory") or []
    report_path = state.get("report_path", "n/a")

    summary = Table(title="Scorpio — Run Summary")
    summary.add_column("Metric", style="cyan", no_wrap=True)
    summary.add_column("Value", style="bold")
    summary.add_row("Endpoints inventoried", str(len(inventory)))
    summary.add_row("Missions executed", str(len(completed)))
    summary.add_row("Vulnerabilities validated", str(len(vulns)))
    summary.add_row("Report path", str(report_path))
    console.print(summary)

    if vulns:
        findings = Table(title="Validated Findings")
        findings.add_column("OWASP", style="red")
        findings.add_column("Endpoint")
        findings.add_column("Severity", style="bold yellow")
        findings.add_column("CVSS", justify="right")
        for v in vulns:
            findings.add_row(
                v["owasp_id"],
                f"{v['endpoint_method']} {v['endpoint_path']}",
                v["severity"],
                f"{v['cvss_score']:.1f}",
            )
        console.print(findings)


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


@app.command()
def scan(
    spec: Annotated[
        Path,
        typer.Option("--spec", "-s", exists=True, readable=True, help="OpenAPI spec path."),
    ],
    base_url: Annotated[str, typer.Option("--base-url", "-u", help="Target API base URL.")],
    token_a: Annotated[
        str | None,
        typer.Option("--token-a", help="Auth header value for the first identity."),
    ] = None,
    token_b: Annotated[
        str | None,
        typer.Option("--token-b", help="Auth header value for the second identity (enables BOLA testing)."),
    ] = None,
    thread_id: Annotated[
        str | None,
        typer.Option("--thread", help="Resumable thread ID; auto-generated if omitted."),
    ] = None,
    max_steps: Annotated[
        int,
        typer.Option("--max-steps", help="Hard cap on LangGraph steps (safety net)."),
    ] = 200,
) -> None:
    """Run a full scan against the target API."""
    _configure_logging()
    thread_id = thread_id or str(uuid.uuid4())
    console.print(
        Panel.fit(
            f"[bold]Scorpio scan[/bold]\nspec=[cyan]{spec}[/cyan]\n"
            f"target=[cyan]{base_url}[/cyan]\nthread_id=[magenta]{thread_id}[/magenta]",
            border_style="green",
        )
    )

    initial = _build_initial_state(spec, base_url, token_a, token_b)
    config = {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": max_steps,
    }

    try:
        with compiled_graph() as graph:
            final = graph.invoke(initial, config=config)
    except KeyboardInterrupt:
        console.print("[yellow]Interrupted — state has been checkpointed; "
                      f"resume with: python main.py resume --thread {thread_id}[/yellow]")
        sys.exit(130)

    _render_final_state(final)


# ---------------------------------------------------------------------------
# resume
# ---------------------------------------------------------------------------


@app.command()
def resume(
    thread_id: Annotated[str, typer.Option("--thread", help="Thread to resume.")],
    max_steps: Annotated[int, typer.Option("--max-steps")] = 200,
) -> None:
    """Resume a previously-checkpointed scan."""
    _configure_logging()
    config = {
        "configurable": {"thread_id": thread_id},
        "recursion_limit": max_steps,
    }
    with compiled_graph() as graph:
        final = graph.invoke(None, config=config)
    _render_final_state(final)


# ---------------------------------------------------------------------------
# sandbox
# ---------------------------------------------------------------------------


@sandbox_app.command("build")
def sandbox_build() -> None:
    """Build the sandbox image from docker/Dockerfile.sandbox."""
    _configure_logging()
    settings = get_settings()
    import docker

    client = docker.from_env()
    dockerfile = Path("docker/Dockerfile.sandbox")
    if not dockerfile.exists():
        console.print(f"[red]Dockerfile not found:[/red] {dockerfile}")
        raise typer.Exit(code=1)

    console.print(f"Building image [bold]{settings.sandbox_image}[/bold]…")
    image, logs = client.images.build(
        path=".", dockerfile=str(dockerfile), tag=settings.sandbox_image, rm=True
    )
    for chunk in logs:
        if "stream" in chunk:
            console.print(chunk["stream"].rstrip())
    console.print(f"[green]Built[/green] {image.tags}")


@sandbox_app.command("shell")
def sandbox_shell() -> None:
    """Spawn an interactive shell in the running sandbox container."""
    _configure_logging()
    settings = get_settings()
    import subprocess

    subprocess.call(
        ["docker", "exec", "-it", settings.sandbox_container_name, "/bin/bash"]
    )


@sandbox_app.command("stop")
def sandbox_stop() -> None:
    """Stop and remove the sandbox container."""
    _configure_logging()
    manager = get_sandbox_manager()
    manager.stop()
    console.print("[green]Sandbox stopped.[/green]")


if __name__ == "__main__":
    app()
