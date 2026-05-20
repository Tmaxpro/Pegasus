"""Runtime configuration loaded from environment variables.

All tunables of the framework live here so the rest of the code stays free of
magic numbers. Values can be overridden in a `.env` file at the project root.
"""

from __future__ import annotations

from pathlib import Path
from typing import Literal

from pydantic import Field
from pydantic_settings import BaseSettings, SettingsConfigDict


class ScorpioSettings(BaseSettings):
    """Project-wide configuration."""

    model_config = SettingsConfigDict(
        env_file=".env",
        env_prefix="SCORPIO_",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    # --- LLM ---
    llm_provider: Literal["anthropic", "openai", "google", "ollama"] = Field(
        default="anthropic",
        description="LLM provider to use.",
    )
    anthropic_api_key: str = Field(default="", description="Anthropic API key.")
    openai_api_key: str = Field(default="", description="OpenAI API key.")
    google_api_key: str = Field(default="", description="Google API key.")
    ollama_base_url: str = Field(
        default="http://localhost:11434",
        description="Ollama API base URL.",
    )
    model_name: str = Field(
        default="claude-opus-4-7",
        description="Default model used by every agent.",
    )
    fast_model_name: str = Field(
        default="claude-haiku-4-5-20251001",
        description="Cheap/fast model for the Supervisor's routing decisions.",
    )
    llm_temperature: float = Field(default=0.1, ge=0.0, le=1.0)
    llm_max_tokens: int = Field(default=4096, gt=0)

    def get_resolved_models(self) -> tuple[str, str]:
        """Return the resolved (main_model, fast_model) based on the provider."""
        provider = self.llm_provider
        main_model = self.model_name
        fast_model = self.fast_model_name

        defaults = {
            "anthropic": ("claude-opus-4-7", "claude-haiku-4-5-20251001"),
            "openai": ("gpt-4o", "gpt-4o-mini"),
            "google": ("gemini-2.5-pro", "gemini-2.5-flash"),
            "ollama": ("llama3.1", "llama3.1"),
        }

        if provider != "anthropic":
            if main_model == "claude-opus-4-7":
                main_model = defaults[provider][0]
            if fast_model == "claude-haiku-4-5-20251001":
                fast_model = defaults[provider][1]

        return main_model, fast_model


    # --- Sandbox ---
    sandbox_container_name: str = Field(default="scorpio-worker-sandbox")
    sandbox_image: str = Field(default="scorpio/worker-sandbox:latest")
    sandbox_command_timeout: int = Field(
        default=180,
        description="Hard timeout (seconds) for any command executed in the sandbox.",
    )
    sandbox_auto_start: bool = Field(
        default=True,
        description="If True the framework launches the container on demand.",
    )

    # --- Attacker RAOA loop ---
    attacker_max_iterations: int = Field(
        default=5,
        ge=1,
        description="Maximum Reflection-Action-Observation-Adjustment cycles per mission.",
    )

    # --- Persistence ---
    project_root: Path = Field(default=Path(__file__).resolve().parent.parent)
    checkpoint_db: Path = Field(
        default=Path(__file__).resolve().parent.parent / "checkpoints" / "scorpio.sqlite"
    )
    reports_dir: Path = Field(
        default=Path(__file__).resolve().parent.parent / "reports"
    )

    # --- Logging ---
    log_level: Literal["DEBUG", "INFO", "WARNING", "ERROR"] = Field(default="INFO")

    def ensure_runtime_dirs(self) -> None:
        """Create the directories the runtime writes to (idempotent)."""
        self.checkpoint_db.parent.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


_settings: ScorpioSettings | None = None


def get_settings() -> ScorpioSettings:
    """Process-wide settings singleton."""
    global _settings
    if _settings is None:
        _settings = ScorpioSettings()
        _settings.ensure_runtime_dirs()
    return _settings
