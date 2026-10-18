"""Configuration for the BlastRadius evidence-grounded agent (Phase 4B).

All settings are read from environment variables using the
``BLASTRADIUS_AGENT_`` prefix, mirroring :mod:`app.osv.config` and
:mod:`app.core.config`.  Secrets (the provider API key) are wrapped in
:class:`pydantic.SecretStr` and never logged or echoed in error envelopes.

Provider model: a single, configurable provider client is implemented —
``openai-compat`` (the OpenAI Chat Completions tool/function-calling API).
Because the API endpoint base URL, model name and key are all configurable,
this one adapter covers OpenAI itself as well as any OpenAI-compatible
endpoint (Azure OpenAI gateways, OpenRouter, Groq, vLLM, LM Studio, Ollama's
OpenAI-compatible server, ...).  No provider SDK dependency is added: the
adapter uses ``httpx`` directly, like every other upstream client in this
repository.

If no credentials are configured, the agent surface reports a stable
``agent_not_configured`` error instead of partially executing.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

ENV_PREFIX: Final[str] = "BLASTRADIUS_AGENT_"

#: The one provider dialect implemented in Phase 4B.
SUPPORTED_PROVIDERS: Final[tuple[str, ...]] = ("openai-compat",)

DEFAULT_PROVIDER: Final[str] = "openai-compat"
DEFAULT_BASE_URL: Final[str] = "https://api.openai.com/v1"
DEFAULT_MCP_URL: Final[str] = "http://127.0.0.1:8000/mcp/"


def _key(name: str) -> str:
    return f"{ENV_PREFIX}{name}"


def _raw(name: str) -> str | None:
    value = os.environ.get(_key(name))
    if value is None:
        return None
    value = value.strip()
    return value or None


def _get_str(name: str, default: str) -> str:
    value = _raw(name)
    return default if value is None else value


def _get_int(name: str, default: int, *, minimum: int = 1, maximum: int | None = None) -> int:
    value = _raw(name)
    if value is None:
        return default
    try:
        parsed = int(value.replace("_", ""))
    except ValueError as exc:
        raise ValueError(f"Environment variable {_key(name)} must be an integer, got {value!r}") from exc
    if parsed < minimum:
        raise ValueError(f"Environment variable {_key(name)} must be >= {minimum}, got {parsed}")
    if maximum is not None and parsed > maximum:
        raise ValueError(f"Environment variable {_key(name)} must be <= {maximum}, got {parsed}")
    return parsed


def _get_float(name: str, default: float, *, minimum: float = 0.0) -> float:
    value = _raw(name)
    if value is None:
        return default
    try:
        parsed = float(value)
    except ValueError as exc:
        raise ValueError(f"Environment variable {_key(name)} must be a number, got {value!r}") from exc
    if parsed <= minimum:
        raise ValueError(f"Environment variable {_key(name)} must be > {minimum}, got {parsed}")
    return parsed


def _get_bool(name: str, default: bool) -> bool:
    value = _raw(name)
    if value is None:
        return default
    lowered = value.lower()
    if lowered in {"1", "true", "yes", "on"}:
        return True
    if lowered in {"0", "false", "no", "off"}:
        return False
    raise ValueError(f"Environment variable {_key(name)} must be a boolean, got {value!r}")


class AgentSettings(BaseModel):
    """Effective agent configuration (immutable, never logged with secrets)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    provider: str = Field(
        default=DEFAULT_PROVIDER,
        description="Provider dialect; Phase 4B implements exactly one: 'openai-compat'.",
    )
    model: str = Field(
        default="",
        description="Model name, e.g. 'gpt-4o-mini'. Empty means the agent is unconfigured.",
    )
    base_url: str = Field(
        default=DEFAULT_BASE_URL,
        description="OpenAI-compatible chat-completions base URL (also accepts local test endpoints).",
    )
    api_key: SecretStr | None = Field(
        default=None,
        description="Bearer credential for the provider; never logged or returned.",
    )
    mcp_url: str = Field(
        default=DEFAULT_MCP_URL,
        description="Streamable HTTP MCP endpoint the agent connects to (tools/list + tools/call).",
    )

    # Execution limits (bounded agent loop).
    timeout_seconds: float = Field(
        default=60.0, gt=0, description="Overall agent budget: provider rounds + MCP calls."
    )
    provider_timeout_seconds: float = Field(
        default=30.0, gt=0, description="Per-provider-call HTTP timeout (connect+read)."
    )
    max_rounds: int = Field(
        default=4, ge=1, le=8, description="Maximum provider/LLM reasoning rounds per question."
    )
    max_tool_calls_per_round: int = Field(
        default=4, ge=1, le=8, description="Maximum tool executions accepted per round."
    )
    max_question_chars: int = Field(
        default=1_000, ge=1, le=10_000, description="Maximum accepted question length."
    )
    max_tool_result_chars: int = Field(
        default=20_000, ge=100, description="Per-tool-result char cap fed back to the model."
    )
    max_evidence_chars: int = Field(
        default=120_000, ge=100, description="Total evidence char budget per question."
    )
    max_output_chars: int = Field(
        default=8_000, ge=100, description="Final-answer char cap."
    )
    strict_grounding: bool = Field(
        default=True,
        description="If True, an answer containing identifiers absent from collected evidence is withheld.",
    )

    @field_validator("provider")
    @classmethod
    def _validate_provider(cls, value: str) -> str:
        if value not in SUPPORTED_PROVIDERS:
            raise ValueError(f"provider must be one of {list(SUPPORTED_PROVIDERS)}, got {value!r}")
        return value

    @field_validator("base_url", "mcp_url")
    @classmethod
    def _validate_http_url(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            # http:// is permitted so local MCP test endpoints work.
            raise ValueError("base_url/mcp_url must be an absolute http(s) URL")
        return value.rstrip("/")

    @property
    def is_configured(self) -> bool:
        """Whether both a model and an API key are present."""
        key_ok = self.api_key is not None and bool(self.api_key.get_secret_value().strip())
        return key_ok and bool(self.model.strip())

    @property
    def connection_label(self) -> str:
        """Human-readable upstream identifier (never contains the key)."""
        key_source = "agent_key" if self.api_key is not None else "unconfigured"
        return f"{self.provider} model={self.model or '<unset>'} base_url={self.base_url} key_source={key_source}"

    @classmethod
    def from_env(cls) -> "AgentSettings":
        """Build settings from ``BLASTRADIUS_AGENT_*`` environment variables.

        ``BLASTRADIUS_AGENT_API_KEY`` takes precedence; when it is absent, the
        provider-standard ``OPENAI_API_KEY`` is used as a fallback so an
        environment that already carries provider credentials works without
        BlastRadius-specific setup.
        """
        raw_key = _raw("API_KEY")
        if raw_key is None:
            raw_key = os.environ.get("OPENAI_API_KEY", "").strip() or None
        return cls(
            provider=_get_str("PROVIDER", cls.model_fields["provider"].default),
            model=_get_str("MODEL", cls.model_fields["model"].default),
            base_url=_get_str("BASE_URL", cls.model_fields["base_url"].default),
            api_key=SecretStr(raw_key) if raw_key else None,
            mcp_url=_get_str("MCP_URL", cls.model_fields["mcp_url"].default),
            timeout_seconds=_get_float("TIMEOUT_SECONDS", cls.model_fields["timeout_seconds"].default),
            provider_timeout_seconds=_get_float(
                "PROVIDER_TIMEOUT_SECONDS", cls.model_fields["provider_timeout_seconds"].default
            ),
            max_rounds=_get_int("MAX_ROUNDS", cls.model_fields["max_rounds"].default, maximum=8),
            max_tool_calls_per_round=_get_int(
                "MAX_TOOL_CALLS_PER_ROUND",
                cls.model_fields["max_tool_calls_per_round"].default,
                maximum=8,
            ),
            max_question_chars=_get_int("MAX_QUESTION_CHARS", cls.model_fields["max_question_chars"].default),
            max_tool_result_chars=_get_int(
                "MAX_TOOL_RESULT_CHARS", cls.model_fields["max_tool_result_chars"].default
            ),
            max_evidence_chars=_get_int("MAX_EVIDENCE_CHARS", cls.model_fields["max_evidence_chars"].default),
            max_output_chars=_get_int("MAX_OUTPUT_CHARS", cls.model_fields["max_output_chars"].default),
            strict_grounding=_get_bool("STRICT_GROUNDING", cls.model_fields["strict_grounding"].default),
        )


@lru_cache(maxsize=1)
def get_agent_settings() -> AgentSettings:
    """Return the process-wide agent settings singleton."""
    return AgentSettings.from_env()


def reset_agent_settings_cache() -> None:
    """Clear the agent settings cache (used by tests and configuration reloads)."""
    get_agent_settings.cache_clear()


__all__ = [
    "DEFAULT_BASE_URL",
    "DEFAULT_MCP_URL",
    "DEFAULT_PROVIDER",
    "ENV_PREFIX",
    "SUPPORTED_PROVIDERS",
    "AgentSettings",
    "get_agent_settings",
    "reset_agent_settings_cache",
]
