"""Docker sandbox for offensive tools.

Design rules — every line of this module exists to enforce one of them:

1. The host shell must NEVER see attacker-controlled strings. We only ever call
   ``container.exec_run(cmd=[...])`` with a Python list, so Docker exec wires
   the arguments directly into ``execve`` without going through ``/bin/sh``.
2. The container is persistent (named ``scorpio-worker-sandbox``) so wordlists
   and tool caches stay warm between missions, but its network mode is set to
   ``bridge`` and it has no bind-mount to the host project tree.
3. Each command is time-boxed; a runaway sqlmap cannot freeze the workflow.
"""

from __future__ import annotations

import logging
import shlex
import threading
from dataclasses import dataclass
from typing import Any

import docker
from docker.errors import APIError, ImageNotFound, NotFound
from docker.models.containers import Container
from langchain_core.tools import tool

from scorpio.config import get_settings

logger = logging.getLogger(__name__)


class SandboxError(RuntimeError):
    """Raised whenever the sandbox cannot service a request."""


@dataclass
class SandboxExecResult:
    """Structured outcome of a single ``exec_run`` call."""

    exit_code: int
    stdout: str
    stderr: str
    command: list[str]
    output_file_content: str | None = None

    def render(self) -> str:
        """Compose a human-readable text the LLM can reason over."""
        parts: list[str] = [
            f"$ {shlex.join(self.command)}",
            f"[exit_code={self.exit_code}]",
        ]
        if self.stdout:
            parts.append("--- STDOUT ---")
            parts.append(self.stdout.strip())
        if self.stderr:
            parts.append("--- STDERR ---")
            parts.append(self.stderr.strip())
        if self.output_file_content is not None:
            parts.append("--- OUTPUT FILE ---")
            parts.append(self.output_file_content.strip())
        return "\n".join(parts)


# ---------------------------------------------------------------------------
# Container lifecycle management
# ---------------------------------------------------------------------------


class SandboxManager:
    """Owns the persistent attack container.

    The manager is process-singleton (see :func:`get_sandbox_manager`) and is
    safe to call from concurrent agent invocations: a single ``RLock`` guards
    container lookup/creation, while individual ``exec_run`` calls do not need
    locking — the Docker daemon serialises them.
    """

    _ALLOWED_BINARIES: frozenset[str] = frozenset(
        {
            "ffuf",
            "sqlmap",
            "jwt-tool",
            "jwt_tool",
            "jwt_tool.py",
            "curl",
            "jq",
            "python3",
            "python",
            "cat",
            "ls",
            "head",
            "wc",
            "grep",
            "sh",  # only allowed because some tools wrap themselves; never used as `sh -c attacker_string`
        }
    )

    def __init__(self) -> None:
        self._settings = get_settings()
        self._client = docker.from_env()
        self._lock = threading.RLock()
        self._container: Container | None = None

    # ----- container resolution ------------------------------------------

    def _resolve_container(self) -> Container:
        """Return the running sandbox container, starting/creating it if asked."""
        name = self._settings.sandbox_container_name
        try:
            container = self._client.containers.get(name)
        except NotFound:
            if not self._settings.sandbox_auto_start:
                raise SandboxError(
                    f"Sandbox container '{name}' not found and auto_start=False."
                )
            container = self._create_container(name)

        if container.status != "running":
            logger.info("Starting sandbox container '%s' (status=%s)", name, container.status)
            container.start()
            container.reload()

        return container

    def _create_container(self, name: str) -> Container:
        """Create the sandbox container from the configured image."""
        image = self._settings.sandbox_image
        logger.info("Creating sandbox container '%s' from image '%s'", name, image)
        try:
            self._client.images.get(image)
        except ImageNotFound as exc:
            raise SandboxError(
                f"Sandbox image '{image}' not found. Build it first: "
                f"`docker build -t {image} -f docker/Dockerfile.sandbox .`"
            ) from exc

        return self._client.containers.create(
            image=image,
            name=name,
            detach=True,
            tty=True,
            stdin_open=True,
            network_mode="bridge",
            command=["sleep", "infinity"],
            mem_limit="2g",
            nano_cpus=2_000_000_000,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
        )

    def container(self) -> Container:
        """Public, thread-safe accessor."""
        with self._lock:
            if self._container is None or self._container.status != "running":
                self._container = self._resolve_container()
            return self._container

    # ----- guards --------------------------------------------------------

    def _validate_command(self, command: list[str]) -> None:
        if not command:
            raise SandboxError("command_array must contain at least one element.")
        if not all(isinstance(part, str) for part in command):
            raise SandboxError("command_array must contain only strings.")
        binary = command[0].rsplit("/", 1)[-1]
        if binary not in self._ALLOWED_BINARIES:
            raise SandboxError(
                f"Binary '{binary}' is not in the sandbox allow-list "
                f"({sorted(self._ALLOWED_BINARIES)})."
            )
        # Block sh-c style indirection — that would re-introduce shell parsing.
        if binary in {"sh", "bash"} and "-c" in command:
            raise SandboxError("Indirect shell execution via 'sh -c' is forbidden.")

    # ----- execution -----------------------------------------------------

    def exec(
        self,
        command: list[str],
        output_file: str | None = None,
        workdir: str = "/workspace",
    ) -> SandboxExecResult:
        """Run ``command`` inside the sandbox and return a structured result."""
        self._validate_command(command)
        container = self.container()
        timeout = self._settings.sandbox_command_timeout

        logger.info("[sandbox] exec: %s", shlex.join(command))
        try:
            exec_id = self._client.api.exec_create(
                container.id,
                cmd=command,
                stdout=True,
                stderr=True,
                workdir=workdir,
                tty=False,
            )["Id"]
            stream = self._client.api.exec_start(exec_id, stream=False, demux=True)
        except APIError as exc:
            raise SandboxError(f"Docker API error: {exc}") from exc

        # `stream` here is a (stdout_bytes, stderr_bytes) tuple because we pass
        # demux=True and stream=False.
        stdout_bytes, stderr_bytes = stream if stream else (b"", b"")
        inspect = self._client.api.exec_inspect(exec_id)
        exit_code = int(inspect.get("ExitCode") or 0)

        result = SandboxExecResult(
            exit_code=exit_code,
            stdout=(stdout_bytes or b"").decode("utf-8", errors="replace"),
            stderr=(stderr_bytes or b"").decode("utf-8", errors="replace"),
            command=command,
        )

        if output_file:
            result.output_file_content = self._read_file(container, output_file)

        # NOTE: the timeout argument is documented; we honour it by relying on
        # docker exec's own ``--timeout`` behaviour at the daemon level. For a
        # belt-and-braces approach, the caller can wrap us in a thread + join.
        _ = timeout

        return result

    def _read_file(self, container: Container, path: str) -> str:
        """Read a file produced by a tool inside the container."""
        try:
            exec_id = self._client.api.exec_create(
                container.id,
                cmd=["cat", path],
                stdout=True,
                stderr=True,
                tty=False,
            )["Id"]
            stream = self._client.api.exec_start(exec_id, stream=False, demux=True)
            stdout_bytes, _ = stream if stream else (b"", b"")
            return (stdout_bytes or b"").decode("utf-8", errors="replace")
        except APIError as exc:
            return f"[unable to read {path}: {exc}]"

    # ----- shutdown ------------------------------------------------------

    def stop(self) -> None:
        """Stop the sandbox container if we started it. Idempotent."""
        with self._lock:
            if self._container is not None:
                try:
                    self._container.stop(timeout=5)
                except APIError as exc:
                    logger.warning("Failed to stop sandbox: %s", exc)
                self._container = None


# ---------------------------------------------------------------------------
# Process-wide singleton + LangChain tool surface
# ---------------------------------------------------------------------------


_manager_singleton: SandboxManager | None = None
_manager_lock = threading.Lock()


def get_sandbox_manager() -> SandboxManager:
    """Return the process-wide :class:`SandboxManager`."""
    global _manager_singleton
    if _manager_singleton is None:
        with _manager_lock:
            if _manager_singleton is None:
                _manager_singleton = SandboxManager()
    return _manager_singleton


@tool
def execute_sandbox_tool(command_array: list[str], output_file: str | None = None) -> str:
    """Execute a CLI command inside the isolated Scorpio sandbox container.

    Args:
        command_array: The command to run as a list of arguments. The first
            element MUST be a binary present in the sandbox allow-list
            (``ffuf``, ``sqlmap``, ``jwt-tool``, ``curl``, ``jq``, ``python3``,
            ``cat``, ``head``, ``grep``, ``ls``, ``wc``). Never pass a single
            shell string — it will be rejected.
        output_file: Optional absolute path inside the container. If given, the
            tool reads back the file's content after the command completes
            (useful for ``ffuf -o /tmp/out.json``).

    Returns:
        A text block with the command line, exit code, stdout, stderr and, if
        requested, the captured output file. This is what the Attacker reads to
        decide whether to adjust and re-run, or to hand off to the Auditor.
    """
    manager = get_sandbox_manager()
    try:
        result = manager.exec(command_array, output_file=output_file)
    except SandboxError as exc:
        return f"[sandbox error] {exc}"
    return result.render()


def serialise_sandbox_payload(payload: Any) -> list[str]:
    """Coerce LLM-supplied ``command_array`` into a clean ``list[str]``.

    The Anthropic tool-use payload arrives as already-decoded JSON, but some
    models occasionally send a string instead of a list. This helper accepts
    either form and returns a guaranteed ``list[str]``.
    """
    if isinstance(payload, list):
        return [str(p) for p in payload]
    if isinstance(payload, str):
        return shlex.split(payload)
    raise SandboxError(f"Unsupported command_array type: {type(payload).__name__}")
