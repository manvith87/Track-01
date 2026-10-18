"""Runtime configuration for BlastRadius.

All settings are read from environment variables using the ``BLASTRADIUS_``
prefix so that nothing sensitive needs to live in the repository.  Values are
validated at load time; a malformed environment variable fails fast with a
``ValueError`` instead of silently falling back to a default.

Nothing in this module logs, prints or stores secret values in plain text:
the GitHub token is wrapped in :class:`pydantic.SecretStr`.
"""

from __future__ import annotations

import os
from functools import lru_cache
from pathlib import Path
from typing import Final, Literal

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

ENV_PREFIX: Final[str] = "BLASTRADIUS_"

#: Directory names that are never scanned for dependency manifests.  These are
#: virtual environments, VCS internals, caches and build artefacts.  A bare
#: ``env`` directory is intentionally *not* listed here (it can be a real
#: package); virtualenvs are instead detected precisely via ``pyvenv.cfg``.
DEFAULT_EXCLUDED_DIRECTORIES: Final[tuple[str, ...]] = (
    ".git",
    ".hg",
    ".svn",
    ".bzr",
    ".venv",
    "venv",
    "virtualenv",
    ".virtualenv",
    ".virtualenvs",
    "site-packages",
    "node_modules",
    "bower_components",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
    ".pytype",
    ".tox",
    ".nox",
    ".eggs",
    ".ipynb_checkpoints",
    ".pants.d",
    ".cache",
    ".conda",
    ".direnv",
    ".idea",
    ".vscode",
    ".vs",
    "build",
    "dist",
    "htmlcov",
)

#: Directory suffix patterns that are always excluded (e.g. ``foo.egg-info``).
DEFAULT_EXCLUDED_DIRECTORY_SUFFIXES: Final[tuple[str, ...]] = (
    ".egg-info",
    ".dist-info",
    ".egg",
)


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


def _get_list(name: str, default: tuple[str, ...]) -> tuple[str, ...]:
    value = _raw(name)
    if value is None:
        return default
    parts = tuple(part.strip() for part in value.split(",") if part.strip())
    return parts or default


class Settings(BaseModel):
    """Effective BlastRadius configuration (immutable)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    app_name: str = "BlastRadius API"
    app_version: str = "0.1.0"
    phase: str = "phase-4b-agent"

    # --- Logging ----------------------------------------------------------
    log_level: str = "INFO"
    log_json: bool = False

    # --- HTTP / GitHub ----------------------------------------------------
    github_api_base_url: str = "https://api.github.com"
    github_codeload_base_url: str = "https://codeload.github.com"
    github_web_base_url: str = "https://github.com"
    github_token: SecretStr | None = None
    user_agent: str = "BlastRadius/0.1 (+https://github.com/blastradius)"

    # --- Retrieval --------------------------------------------------------
    retrieval_strategy: Literal["auto", "git", "archive"] = "auto"
    git_binary: str = "git"
    git_timeout_seconds: float = 120.0
    download_timeout_seconds: float = 60.0
    metadata_timeout_seconds: float = 20.0
    max_download_bytes: int = 200 * 1024 * 1024
    max_extracted_bytes: int = 500 * 1024 * 1024
    max_archive_members: int = 200_000
    max_repository_size_kb: int = 512_000
    max_ingestion_seconds: float = 300.0

    # --- Analysis ---------------------------------------------------------
    max_files_scanned: int = 20_000
    max_directory_entries: int = 2_000
    max_manifest_bytes: int = 5 * 1024 * 1024
    max_manifests: int = 200
    max_dependencies: int = 20_000
    max_conflict_warnings: int = 25
    max_reported_source_files: int = 200
    max_requirement_include_depth: int = 5
    max_dependency_group_depth: int = 5

    excluded_directories: tuple[str, ...] = DEFAULT_EXCLUDED_DIRECTORIES
    excluded_directory_suffixes: tuple[str, ...] = DEFAULT_EXCLUDED_DIRECTORY_SUFFIXES

    # --- API --------------------------------------------------------------
    api_prefix: str = "/api/v1"
    max_api_records: int = 2_000

    # --- Filesystem -------------------------------------------------------
    temp_root: Path | None = None

    @field_validator("log_level")
    @classmethod
    def _validate_log_level(cls, value: str) -> str:
        allowed = {"CRITICAL", "ERROR", "WARNING", "INFO", "DEBUG", "NOTSET"}
        upper = value.upper()
        if upper not in allowed:
            raise ValueError(f"log_level must be one of {sorted(allowed)}, got {value!r}")
        return upper

    @field_validator("api_prefix")
    @classmethod
    def _validate_api_prefix(cls, value: str) -> str:
        if not value.startswith("/"):
            raise ValueError("api_prefix must start with '/'")
        return value.rstrip("/") or "/"

    @field_validator("github_api_base_url", "github_codeload_base_url", "github_web_base_url")
    @classmethod
    def _validate_https_base(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("GitHub base URLs must use https://")
        return value.rstrip("/")

    @property
    def has_github_token(self) -> bool:
        """Whether an authenticated GitHub API token is configured."""
        return self.github_token is not None and bool(self.github_token.get_secret_value())

    @classmethod
    def from_env(cls) -> "Settings":
        """Build settings from ``BLASTRADIUS_*`` environment variables."""
        token = _raw("GITHUB_TOKEN")
        temp_root = _raw("TEMP_ROOT")
        return cls(
            app_name=_get_str("APP_NAME", cls.model_fields["app_name"].default),
            app_version=_get_str("APP_VERSION", cls.model_fields["app_version"].default),
            log_level=_get_str("LOG_LEVEL", cls.model_fields["log_level"].default),
            log_json=_get_bool("LOG_JSON", cls.model_fields["log_json"].default),
            github_api_base_url=_get_str("GITHUB_API_BASE_URL", cls.model_fields["github_api_base_url"].default),
            github_codeload_base_url=_get_str(
                "GITHUB_CODELOAD_BASE_URL", cls.model_fields["github_codeload_base_url"].default
            ),
            github_web_base_url=_get_str("GITHUB_WEB_BASE_URL", cls.model_fields["github_web_base_url"].default),
            github_token=SecretStr(token) if token else None,
            user_agent=_get_str("USER_AGENT", cls.model_fields["user_agent"].default),
            retrieval_strategy=_get_str(  # type: ignore[arg-type]
                "RETRIEVAL_STRATEGY", cls.model_fields["retrieval_strategy"].default
            ),
            git_binary=_get_str("GIT_BINARY", cls.model_fields["git_binary"].default),
            git_timeout_seconds=_get_float(
                "GIT_TIMEOUT_SECONDS", cls.model_fields["git_timeout_seconds"].default
            ),
            download_timeout_seconds=_get_float(
                "DOWNLOAD_TIMEOUT_SECONDS", cls.model_fields["download_timeout_seconds"].default
            ),
            metadata_timeout_seconds=_get_float(
                "METADATA_TIMEOUT_SECONDS", cls.model_fields["metadata_timeout_seconds"].default
            ),
            max_download_bytes=_get_int("MAX_DOWNLOAD_BYTES", cls.model_fields["max_download_bytes"].default),
            max_extracted_bytes=_get_int("MAX_EXTRACTED_BYTES", cls.model_fields["max_extracted_bytes"].default),
            max_archive_members=_get_int("MAX_ARCHIVE_MEMBERS", cls.model_fields["max_archive_members"].default),
            max_repository_size_kb=_get_int(
                "MAX_REPOSITORY_SIZE_KB", cls.model_fields["max_repository_size_kb"].default
            ),
            max_ingestion_seconds=_get_float(
                "MAX_INGESTION_SECONDS", cls.model_fields["max_ingestion_seconds"].default
            ),
            max_files_scanned=_get_int("MAX_FILES_SCANNED", cls.model_fields["max_files_scanned"].default),
            max_directory_entries=_get_int(
                "MAX_DIRECTORY_ENTRIES", cls.model_fields["max_directory_entries"].default
            ),
            max_manifest_bytes=_get_int("MAX_MANIFEST_BYTES", cls.model_fields["max_manifest_bytes"].default),
            max_manifests=_get_int("MAX_MANIFESTS", cls.model_fields["max_manifests"].default),
            max_dependencies=_get_int("MAX_DEPENDENCIES", cls.model_fields["max_dependencies"].default),
            max_conflict_warnings=_get_int(
                "MAX_CONFLICT_WARNINGS", cls.model_fields["max_conflict_warnings"].default
            ),
            max_reported_source_files=_get_int(
                "MAX_REPORTED_SOURCE_FILES", cls.model_fields["max_reported_source_files"].default
            ),
            max_requirement_include_depth=_get_int(
                "MAX_REQUIREMENT_INCLUDE_DEPTH", cls.model_fields["max_requirement_include_depth"].default
            ),
            max_dependency_group_depth=_get_int(
                "MAX_DEPENDENCY_GROUP_DEPTH", cls.model_fields["max_dependency_group_depth"].default
            ),
            excluded_directories=_get_list("EXCLUDED_DIRECTORIES", DEFAULT_EXCLUDED_DIRECTORIES),
            excluded_directory_suffixes=_get_list(
                "EXCLUDED_DIRECTORY_SUFFIXES", DEFAULT_EXCLUDED_DIRECTORY_SUFFIXES
            ),
            api_prefix=_get_str("API_PREFIX", cls.model_fields["api_prefix"].default),
            max_api_records=_get_int("MAX_API_RECORDS", cls.model_fields["max_api_records"].default),
            temp_root=Path(temp_root).expanduser() if temp_root else None,
        )


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Return the process-wide settings singleton."""
    return Settings.from_env()


def reset_settings_cache() -> None:
    """Clear the settings cache (used by tests and by configuration reloads)."""
    get_settings.cache_clear()


__all__ = [
    "ENV_PREFIX",
    "DEFAULT_EXCLUDED_DIRECTORIES",
    "DEFAULT_EXCLUDED_DIRECTORY_SUFFIXES",
    "Settings",
    "get_settings",
    "reset_settings_cache",
]
