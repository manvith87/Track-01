"""Graph storage configuration for BlastRadius Phase 2.

All settings are read from environment variables using the ``BLASTRADIUS_GRAPH_``
prefix so that nothing sensitive needs to live in the repository.  The graph is
optional: the Phase 1 ingestion endpoint continues to work when FalkorDB is not
configured or unreachable.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

ENV_PREFIX: Final[str] = "BLASTRADIUS_GRAPH_"


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


def _get_int(name: str, default: int, *, minimum: int = 1) -> int:
    value = _raw(name)
    if value is None:
        return default
    try:
        parsed = int(value.replace("_", ""))
    except ValueError as exc:
        raise ValueError(f"Environment variable {_key(name)} must be an integer, got {value!r}") from exc
    if parsed < minimum:
        raise ValueError(f"Environment variable {_key(name)} must be >= {minimum}, got {parsed}")
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


class GraphSettings(BaseModel):
    """Effective FalkorDB graph configuration (immutable)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    # --- Connection ---------------------------------------------------------
    host: str = Field(default="localhost", description="FalkorDB/Redis host.")
    port: int = Field(default=6379, ge=1, le=65535, description="FalkorDB/Redis port.")
    password: SecretStr | None = Field(
        default=None, description="FalkorDB password (never logged)."
    )
    username: str | None = Field(default=None, description="FalkorDB username (ACL).")
    database: int = Field(default=0, ge=0, description="Redis database index.")
    graph_name: str = Field(
        default="blastradius",
        description="FalkorDB graph name (a graph is a namespace inside a Redis database).",
    )
    socket_timeout_seconds: float = Field(
        default=10.0, gt=0, description="Socket timeout for read/write operations."
    )
    socket_connect_timeout_seconds: float = Field(
        default=5.0, gt=0, description="Timeout for establishing a connection."
    )
    ssl: bool = Field(default=False, description="Use TLS when connecting to FalkorDB.")

    @field_validator("graph_name")
    @classmethod
    def _validate_graph_name(cls, value: str) -> str:
        if not value or not value.strip():
            raise ValueError("graph_name must not be empty")
        return value.strip()

    @property
    def has_credentials(self) -> bool:
        """Whether a password or username is configured."""
        return bool(self.username) or (self.password is not None and bool(self.password.get_secret_value()))

    @property
    def connection_label(self) -> str:
        """Human readable connection identifier (credentials redacted)."""
        return f"{self.host}:{self.port}/{self.database} graph={self.graph_name}"

    @classmethod
    def from_env(cls) -> "GraphSettings":
        """Build settings from ``BLASTRADIUS_GRAPH_*`` environment variables."""
        password = _raw("PASSWORD")
        return cls(
            host=_get_str("HOST", cls.model_fields["host"].default),
            port=_get_int("PORT", cls.model_fields["port"].default),
            password=SecretStr(password) if password else None,
            username=_get_str("USERNAME", cls.model_fields["username"].default),
            database=_get_int("DATABASE", cls.model_fields["database"].default),
            graph_name=_get_str("NAME", cls.model_fields["graph_name"].default),
            socket_timeout_seconds=_get_float(
                "SOCKET_TIMEOUT_SECONDS", cls.model_fields["socket_timeout_seconds"].default
            ),
            socket_connect_timeout_seconds=_get_float(
                "SOCKET_CONNECT_TIMEOUT_SECONDS", cls.model_fields["socket_connect_timeout_seconds"].default
            ),
            ssl=_get_bool("SSL", cls.model_fields["ssl"].default),
        )


@lru_cache(maxsize=1)
def get_graph_settings() -> GraphSettings:
    """Return the process-wide graph settings singleton."""
    return GraphSettings.from_env()


def reset_graph_settings_cache() -> None:
    """Clear the graph settings cache (used by tests and by configuration reloads)."""
    get_graph_settings.cache_clear()


__all__ = ["ENV_PREFIX", "GraphSettings", "get_graph_settings", "reset_graph_settings_cache"]
