"""Configuration for user-approved GitHub actions (Phase 6).

Creating a GitHub issue is a **write** operation, so this module is
deliberately conservative:

* ``BLASTRADIUS_ACTIONS_ENABLED`` defaults to ``false`` — the safe default is
  that BlastRadius never writes to GitHub;
* the write credential is read from its own environment variable
  (``BLASTRADIUS_ACTIONS_GITHUB_TOKEN``) and is wrapped in
  :class:`pydantic.SecretStr`; it is never logged, echoed in an error envelope,
  embedded in an issue body or returned to a caller;
* confirmation additionally requires a dedicated secret
  (``BLASTRADIUS_ACTIONS_APPROVAL_SECRET``); without it the confirmation
  endpoint refuses every request instead of trusting an action id alone;
* the API base URL must be https and the optional repository allowlist is an
  explicit opt-in restriction.

Every setting is read from environment variables using the
``BLASTRADIUS_ACTIONS_`` prefix, mirroring :mod:`app.agent.config`,
:mod:`app.osv.config` and :mod:`app.core.config`.
"""

from __future__ import annotations

import os
import tempfile
from functools import lru_cache
from pathlib import Path
from typing import Final

from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator

ENV_PREFIX: Final[str] = "BLASTRADIUS_ACTIONS_"

DEFAULT_API_BASE_URL: Final[str] = "https://api.github.com"
DEFAULT_USER_AGENT: Final[str] = "BlastRadius/0.1 (+https://github.com/blastradius)"

#: GitHub's own limits (title 256 characters, body 65536 characters).  The
#: defaults stay slightly below the body limit so the generated payload never
#: trips GitHub's own validation.
GITHUB_MAX_TITLE_CHARS: Final[int] = 256
DEFAULT_MAX_TITLE_CHARS: Final[int] = 256
DEFAULT_MAX_BODY_CHARS: Final[int] = 60_000

#: Preview actions expire after this many seconds unless overridden.
DEFAULT_PREVIEW_TTL_SECONDS: Final[float] = 900.0

#: Default SQLite path used when BLASTRADIUS_ACTIONS_STORE_PATH is not set.
#: The store is process-external so approval/replay guarantees survive
#: application restarts; deployments should set an explicit durable path.
DEFAULT_STORE_FILENAME: Final[str] = "actions.sqlite3"


def default_store_path() -> Path:
    """Return the default on-disk action store path."""
    base = Path(tempfile.gettempdir()) / "blastradius-actions"
    return base / DEFAULT_STORE_FILENAME


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


def normalize_repository_allowlist(values: tuple[str, ...]) -> tuple[str, ...]:
    """Normalise allowlist entries to ``github.com/owner/repo`` (lower-case).

    Accepted spellings are ``owner/repo``, ``github.com/owner/repo`` and
    ``https://github.com/owner/repo`` (a trailing ``.git`` and slashes are
    ignored).  Anything else is a configuration error and fails fast.
    """
    normalized: list[str] = []
    for raw in values:
        entry = raw.strip().lower()
        if not entry:
            continue
        for prefix in ("https://", "http://"):
            if entry.startswith(prefix):
                entry = entry[len(prefix) :]
        entry = entry.strip("/")
        if entry.endswith(".git"):
            entry = entry[:-4]
        entry = entry.strip("/")
        parts = [part for part in entry.split("/") if part]
        if parts and parts[0] in {"github.com", "www.github.com"}:
            parts = parts[1:]
        if len(parts) != 2 or not all(parts):
            raise ValueError(
                f"Invalid repository allowlist entry {raw!r}: use 'owner/repo' or 'github.com/owner/repo'"
            )
        owner, name = parts
        if not owner or not name or any(ch.isspace() for ch in owner + name):
            raise ValueError(f"Invalid repository allowlist entry {raw!r}")
        canonical = f"github.com/{owner}/{name}"
        if canonical not in normalized:
            normalized.append(canonical)
    return tuple(normalized)


class ActionSettings(BaseModel):
    """Effective GitHub action configuration (immutable; secrets never logged)."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    enabled: bool = Field(
        default=False,
        description=(
            "Master switch for GitHub write actions. False (the default) means "
            "the preview and confirmation endpoints report github_write_disabled."
        ),
    )
    github_token: SecretStr | None = Field(
        default=None,
        description=(
            "Dedicated GitHub action token. Requires only repository metadata "
            "read plus Issues write on the allowlisted target; never logged or returned."
        ),
    )
    approval_secret: SecretStr | None = Field(
        default=None,
        description=(
            "Dedicated confirmation secret. Without it every confirmation "
            "request is refused (action_authorization_not_configured)."
        ),
    )
    github_api_base_url: str = Field(
        default=DEFAULT_API_BASE_URL,
        description="GitHub REST API base URL; https only (tests inject an httpx transport instead).",
    )
    user_agent: str = Field(default=DEFAULT_USER_AGENT, description="User-Agent sent to GitHub.")
    timeout_seconds: float = Field(
        default=20.0, gt=0, description="Per-request HTTP timeout for GitHub metadata and issue calls."
    )
    preview_ttl_seconds: float = Field(
        default=DEFAULT_PREVIEW_TTL_SECONDS,
        gt=0,
        description="How long a generated preview can be confirmed before it expires.",
    )
    store_path: Path | None = Field(
        default=None,
        description=(
            "SQLite file backing the persistent action store. None means the "
            "platform temp directory (see default_store_path)."
        ),
    )
    retention_seconds: float = Field(
        default=7 * 24 * 3600,
        gt=0,
        description="How long consumed/expired non-successful action records are retained for audit.",
    )
    repository_allowlist: tuple[str, ...] = Field(
        default=(),
        description=(
            "Optional canonical repository allowlist. Empty means no extra "
            "restriction beyond the master switch and credential checks; when "
            "set, only these repositories can be previewed or written."
        ),
    )
    max_title_chars: int = Field(
        default=DEFAULT_MAX_TITLE_CHARS, ge=16, le=GITHUB_MAX_TITLE_CHARS
    )
    max_body_chars: int = Field(default=DEFAULT_MAX_BODY_CHARS, ge=1000, le=65_000)

    @field_validator("github_api_base_url")
    @classmethod
    def _validate_https_base(cls, value: str) -> str:
        if not value.startswith("https://"):
            raise ValueError("github_api_base_url must use https://")
        return value.rstrip("/")

    @field_validator("repository_allowlist", mode="before")
    @classmethod
    def _validate_allowlist(cls, value: object) -> tuple[str, ...]:
        if value is None:
            return ()
        if isinstance(value, str):
            return normalize_repository_allowlist((value,))
        return normalize_repository_allowlist(tuple(str(item) for item in value))

    @property
    def has_token(self) -> bool:
        """Whether a non-empty action token is configured."""
        return self.github_token is not None and bool(self.github_token.get_secret_value().strip())

    @property
    def has_approval_secret(self) -> bool:
        """Whether a non-empty confirmation secret is configured."""
        return self.approval_secret is not None and bool(
            self.approval_secret.get_secret_value().strip()
        )

    @property
    def effective_store_path(self) -> Path:
        """The store path actually used (explicit setting or platform default)."""
        return self.store_path if self.store_path is not None else default_store_path()

    @property
    def connection_label(self) -> str:
        """Human-readable configuration label; never contains a secret value."""
        return (
            f"enabled={self.enabled} api={self.github_api_base_url} "
            f"token={'configured' if self.has_token else 'unset'} "
            f"approval={'configured' if self.has_approval_secret else 'unset'} "
            f"allowlist={len(self.repository_allowlist)}"
        )

    @classmethod
    def from_env(cls) -> "ActionSettings":
        """Build settings from ``BLASTRADIUS_ACTIONS_*`` environment variables."""
        raw_token = _raw("GITHUB_TOKEN")
        raw_secret = _raw("APPROVAL_SECRET")
        raw_store = _raw("STORE_PATH")
        raw_allowlist = _raw("REPOSITORY_ALLOWLIST")
        return cls(
            enabled=_get_bool("ENABLED", cls.model_fields["enabled"].default),
            github_token=SecretStr(raw_token) if raw_token else None,
            approval_secret=SecretStr(raw_secret) if raw_secret else None,
            github_api_base_url=_get_str(
                "GITHUB_API_BASE_URL", cls.model_fields["github_api_base_url"].default
            ),
            user_agent=_get_str("USER_AGENT", cls.model_fields["user_agent"].default),
            timeout_seconds=_get_float(
                "TIMEOUT_SECONDS", cls.model_fields["timeout_seconds"].default
            ),
            preview_ttl_seconds=_get_float(
                "PREVIEW_TTL_SECONDS", cls.model_fields["preview_ttl_seconds"].default
            ),
            store_path=Path(raw_store).expanduser() if raw_store else None,
            retention_seconds=_get_float(
                "RETENTION_SECONDS", cls.model_fields["retention_seconds"].default
            ),
            repository_allowlist=normalize_repository_allowlist(
                tuple(part.strip() for part in raw_allowlist.split(",") if part.strip())
            )
            if raw_allowlist
            else (),
            max_title_chars=_get_int(
                "MAX_TITLE_CHARS",
                cls.model_fields["max_title_chars"].default,
                maximum=GITHUB_MAX_TITLE_CHARS,
            ),
            max_body_chars=_get_int(
                "MAX_BODY_CHARS", cls.model_fields["max_body_chars"].default, maximum=65_000
            ),
        )


@lru_cache(maxsize=1)
def get_action_settings() -> ActionSettings:
    """Return the process-wide action settings singleton."""
    return ActionSettings.from_env()


def reset_action_settings_cache() -> None:
    """Clear the settings cache (used by tests and configuration reloads)."""
    get_action_settings.cache_clear()


__all__ = [
    "DEFAULT_API_BASE_URL",
    "DEFAULT_MAX_BODY_CHARS",
    "DEFAULT_MAX_TITLE_CHARS",
    "DEFAULT_PREVIEW_TTL_SECONDS",
    "DEFAULT_STORE_FILENAME",
    "DEFAULT_USER_AGENT",
    "ENV_PREFIX",
    "GITHUB_MAX_TITLE_CHARS",
    "ActionSettings",
    "default_store_path",
    "get_action_settings",
    "normalize_repository_allowlist",
    "reset_action_settings_cache",
]
