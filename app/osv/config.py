"""OSV client configuration for BlastRadius Phase 3.

All settings are read from environment variables using the ``BLASTRADIUS_OSV_``
prefix.  The OSV.dev API does not require credentials; if one is ever needed it
must be supplied through an environment variable and is never logged.
"""

from __future__ import annotations

import os
from functools import lru_cache
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, field_validator

ENV_PREFIX: Final[str] = "BLASTRADIUS_OSV_"

#: Default upstream endpoint documented at https://google.github.io/osv.dev/api/
DEFAULT_BASE_URL: Final[str] = "https://api.osv.dev"


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


class OsvSettings(BaseModel):
    """Effective OSV.dev client configuration (immutable)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    base_url: str = Field(
        default=DEFAULT_BASE_URL,
        description="OSV API base URL (defaults to the official api.osv.dev endpoint).",
    )
    timeout_seconds: float = Field(
        default=20.0, gt=0, description="Total HTTP timeout for upstream requests."
    )
    connect_timeout_seconds: float = Field(
        default=5.0, gt=0, description="HTTP connect timeout for upstream requests."
    )
    max_retries: int = Field(
        default=3, ge=0, le=10,
        description="Bounded retry attempts for retryable upstream failures.",
    )
    retry_backoff_seconds: float = Field(
        default=0.5, gt=0, description="Base backoff between retries (exponentially grown)."
    )
    batch_size: int = Field(
        default=50, ge=1, le=200,
        description="Maximum /v1/querybatch queries submitted per upstream request.",
    )
    max_pages_per_query: int = Field(
        default=5, ge=1, le=50,
        description="Maximum pages followed for one paginated /v1/query response.",
    )
    max_vulnerabilities_per_ingest: int = Field(
        default=200, ge=1,
        description="Hard cap on distinct vulnerability records hydrated per ingestion run.",
    )
    max_packages_per_ingest: int = Field(
        default=200, ge=1,
        description="Hard cap on distinct package+version items scanned per ingestion run.",
    )
    max_details_length: int = Field(
        default=4_000, ge=100,
        description="Upper bound applied to stored summary/details text (truncated, never invented).",
    )
    max_references_per_vulnerability: int = Field(
        default=50, ge=1,
        description="Upper bound on stored references per vulnerability record.",
    )

    @field_validator("base_url")
    @classmethod
    def _validate_base_url(cls, value: str) -> str:
        if not value.startswith(("https://", "http://")):
            # http:// is permitted only to support a local test double.
            raise ValueError("base_url must be an absolute http(s) URL")
        return value.rstrip("/")

    @property
    def connection_label(self) -> str:
        """Human readable upstream identifier (never contains secrets)."""
        return self.base_url

    @classmethod
    def from_env(cls) -> "OsvSettings":
        """Build settings from ``BLASTRADIUS_OSV_*`` environment variables."""
        return cls(
            base_url=_get_str("BASE_URL", cls.model_fields["base_url"].default),
            timeout_seconds=_get_float(
                "TIMEOUT_SECONDS", cls.model_fields["timeout_seconds"].default
            ),
            connect_timeout_seconds=_get_float(
                "CONNECT_TIMEOUT_SECONDS", cls.model_fields["connect_timeout_seconds"].default
            ),
            max_retries=_get_int("MAX_RETRIES", cls.model_fields["max_retries"].default),
            retry_backoff_seconds=_get_float(
                "RETRY_BACKOFF_SECONDS", cls.model_fields["retry_backoff_seconds"].default
            ),
            batch_size=_get_int("BATCH_SIZE", cls.model_fields["batch_size"].default),
            max_pages_per_query=_get_int(
                "MAX_PAGES_PER_QUERY", cls.model_fields["max_pages_per_query"].default
            ),
            max_vulnerabilities_per_ingest=_get_int(
                "MAX_VULNERABILITIES_PER_INGEST",
                cls.model_fields["max_vulnerabilities_per_ingest"].default,
            ),
            max_packages_per_ingest=_get_int(
                "MAX_PACKAGES_PER_INGEST", cls.model_fields["max_packages_per_ingest"].default
            ),
            max_details_length=_get_int(
                "MAX_DETAILS_LENGTH", cls.model_fields["max_details_length"].default
            ),
            max_references_per_vulnerability=_get_int(
                "MAX_REFERENCES_PER_VULNERABILITY",
                cls.model_fields["max_references_per_vulnerability"].default,
            ),
        )


@lru_cache(maxsize=1)
def get_osv_settings() -> OsvSettings:
    """Return the process-wide OSV settings singleton."""
    return OsvSettings.from_env()


def reset_osv_settings_cache() -> None:
    """Clear the OSV settings cache (used by tests and configuration reloads)."""
    get_osv_settings.cache_clear()


__all__ = [
    "DEFAULT_BASE_URL",
    "ENV_PREFIX",
    "OsvSettings",
    "get_osv_settings",
    "reset_osv_settings_cache",
]
