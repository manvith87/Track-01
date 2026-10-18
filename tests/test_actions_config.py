"""Unit tests for the Phase 6 action configuration.

No network, no GitHub, no LLM: everything here is environment parsing and the
safe defaults that keep GitHub writes disabled.
"""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest
from pydantic import SecretStr, ValidationError

from app.actions.config import (
    DEFAULT_API_BASE_URL,
    DEFAULT_MAX_BODY_CHARS,
    DEFAULT_MAX_TITLE_CHARS,
    DEFAULT_PREVIEW_TTL_SECONDS,
    DEFAULT_STORE_FILENAME,
    ENV_PREFIX,
    ActionSettings,
    default_store_path,
    get_action_settings,
    normalize_repository_allowlist,
    reset_action_settings_cache,
)

_KNOWN_ENV = (
    "ENABLED",
    "GITHUB_TOKEN",
    "APPROVAL_SECRET",
    "GITHUB_API_BASE_URL",
    "USER_AGENT",
    "TIMEOUT_SECONDS",
    "PREVIEW_TTL_SECONDS",
    "STORE_PATH",
    "RETENTION_SECONDS",
    "REPOSITORY_ALLOWLIST",
    "MAX_TITLE_CHARS",
    "MAX_BODY_CHARS",
)


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in _KNOWN_ENV:
        monkeypatch.delenv(f"{ENV_PREFIX}{name}", raising=False)


# ---------------------------------------------------------------------------
# safe defaults
# ---------------------------------------------------------------------------


def test_defaults_disable_github_writes() -> None:
    settings = ActionSettings()
    assert settings.enabled is False
    assert settings.has_token is False
    assert settings.has_approval_secret is False
    assert settings.repository_allowlist == ()
    assert settings.github_api_base_url == DEFAULT_API_BASE_URL
    assert settings.preview_ttl_seconds == DEFAULT_PREVIEW_TTL_SECONDS
    assert settings.max_title_chars == DEFAULT_MAX_TITLE_CHARS
    assert settings.max_body_chars == DEFAULT_MAX_BODY_CHARS
    # default store path lives under the platform temp dir
    assert settings.effective_store_path == default_store_path()
    assert settings.effective_store_path.name == DEFAULT_STORE_FILENAME
    assert default_store_path().parent == Path(tempfile.gettempdir()) / "blastradius-actions"


def test_from_env_defaults_to_disabled(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_env(monkeypatch)
    settings = ActionSettings.from_env()
    assert settings.enabled is False
    assert settings.github_token is None
    assert settings.approval_secret is None
    assert settings.repository_allowlist == ()
    assert settings.store_path is None


def test_connection_label_never_contains_secret_values() -> None:
    settings = ActionSettings(
        enabled=True,
        github_token=SecretStr("super-secret-token-value"),
        approval_secret=SecretStr("super-secret-approval-value"),
    )
    label = settings.connection_label
    assert "super-secret-token-value" not in label
    assert "super-secret-approval-value" not in label
    assert "token=configured" in label
    assert "approval=configured" in label
    # SecretStr itself never leaks through str()/repr()
    assert "super-secret-token-value" not in repr(settings)
    assert "super-secret-approval-value" not in str(settings)


# ---------------------------------------------------------------------------
# environment parsing
# ---------------------------------------------------------------------------


def test_from_env_reads_every_setting(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    _clear_env(monkeypatch)
    store = tmp_path / "nested" / "actions.sqlite3"
    monkeypatch.setenv(f"{ENV_PREFIX}ENABLED", "true")
    monkeypatch.setenv(f"{ENV_PREFIX}GITHUB_TOKEN", "token-value")
    monkeypatch.setenv(f"{ENV_PREFIX}APPROVAL_SECRET", "approval-value")
    monkeypatch.setenv(f"{ENV_PREFIX}GITHUB_API_BASE_URL", "https://github.enterprise.test/api/v3/")
    monkeypatch.setenv(f"{ENV_PREFIX}USER_AGENT", "BlastRadius-test/9")
    monkeypatch.setenv(f"{ENV_PREFIX}TIMEOUT_SECONDS", "3.5")
    monkeypatch.setenv(f"{ENV_PREFIX}PREVIEW_TTL_SECONDS", "60")
    monkeypatch.setenv(f"{ENV_PREFIX}STORE_PATH", str(store))
    monkeypatch.setenv(f"{ENV_PREFIX}RETENTION_SECONDS", "120")
    monkeypatch.setenv(
        f"{ENV_PREFIX}REPOSITORY_ALLOWLIST",
        " example/demo , github.com/Other/Repo ",
    )
    monkeypatch.setenv(f"{ENV_PREFIX}MAX_TITLE_CHARS", "120")
    monkeypatch.setenv(f"{ENV_PREFIX}MAX_BODY_CHARS", "2000")

    settings = ActionSettings.from_env()
    assert settings.enabled is True
    assert settings.has_token is True
    assert settings.github_token is not None
    assert settings.github_token.get_secret_value() == "token-value"
    assert settings.has_approval_secret is True
    assert settings.approval_secret is not None
    assert settings.approval_secret.get_secret_value() == "approval-value"
    # the trailing slash is normalised away
    assert settings.github_api_base_url == "https://github.enterprise.test/api/v3"
    assert settings.user_agent == "BlastRadius-test/9"
    assert settings.timeout_seconds == 3.5
    assert settings.preview_ttl_seconds == 60.0
    assert settings.store_path == store
    assert settings.effective_store_path == store
    assert settings.retention_seconds == 120.0
    assert settings.repository_allowlist == (
        "github.com/example/demo",
        "github.com/other/repo",
    )
    assert settings.max_title_chars == 120
    assert settings.max_body_chars == 2000


def test_from_env_blank_values_are_treated_as_unset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv(f"{ENV_PREFIX}GITHUB_TOKEN", "   ")
    monkeypatch.setenv(f"{ENV_PREFIX}APPROVAL_SECRET", "")
    monkeypatch.setenv(f"{ENV_PREFIX}STORE_PATH", " ")
    monkeypatch.setenv(f"{ENV_PREFIX}REPOSITORY_ALLOWLIST", " , ")
    settings = ActionSettings.from_env()
    assert settings.has_token is False
    assert settings.has_approval_secret is False
    assert settings.store_path is None
    assert settings.repository_allowlist == ()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("ENABLED", "maybe"),
        ("TIMEOUT_SECONDS", "fast"),
        ("TIMEOUT_SECONDS", "0"),
        ("PREVIEW_TTL_SECONDS", "-5"),
        ("RETENTION_SECONDS", "nope"),
        ("MAX_TITLE_CHARS", "9999"),
        ("MAX_BODY_CHARS", "0"),
    ],
)
def test_from_env_rejects_invalid_values(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv(f"{ENV_PREFIX}{name}", value)
    with pytest.raises(ValueError):
        ActionSettings.from_env()


def test_from_env_rejects_invalid_allowlist(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv(f"{ENV_PREFIX}REPOSITORY_ALLOWLIST", "just-owner")
    with pytest.raises(ValueError):
        ActionSettings.from_env()


def test_https_is_required_for_the_api_base() -> None:
    with pytest.raises(ValidationError):
        ActionSettings(github_api_base_url="http://api.github.com")
    with pytest.raises(ValidationError):
        ActionSettings(github_api_base_url="api.github.com")
    # https passes and trailing slashes are stripped
    settings = ActionSettings(github_api_base_url="https://api.github.com/")
    assert settings.github_api_base_url == "https://api.github.com"


# ---------------------------------------------------------------------------
# allowlist normalisation
# ---------------------------------------------------------------------------


def test_allowlist_accepts_documented_spellings() -> None:
    values = normalize_repository_allowlist(
        (
            "owner/repo",
            "github.com/other/repo",
            "https://github.com/Third/Repo",
            "HTTPS://GitHub.com/Fourth/Repo.git/",
            "owner/repo",  # duplicate collapses
        )
    )
    assert values == (
        "github.com/owner/repo",
        "github.com/other/repo",
        "github.com/third/repo",
        "github.com/fourth/repo",
    )


@pytest.mark.parametrize(
    "entry",
    [
        "owner",
        "owner/repo/extra",
        "github.com/owner",
        "github.com/",
        "owner name/repo",
    ],
)
def test_allowlist_rejects_invalid_entries(entry: str) -> None:
    with pytest.raises(ValueError):
        normalize_repository_allowlist((entry,))


def test_allowlist_setting_is_normalised() -> None:
    settings = ActionSettings(repository_allowlist=("Owner/Repo",))
    assert settings.repository_allowlist == ("github.com/owner/repo",)


# ---------------------------------------------------------------------------
# cached singleton
# ---------------------------------------------------------------------------


def test_get_action_settings_is_cached_until_reset(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _clear_env(monkeypatch)
    try:
        reset_action_settings_cache()
        first = get_action_settings()
        assert first.enabled is False
        monkeypatch.setenv(f"{ENV_PREFIX}ENABLED", "true")
        assert get_action_settings() is first  # cached
        reset_action_settings_cache()
        second = get_action_settings()
        assert second is not first
        assert second.enabled is True
    finally:
        reset_action_settings_cache()
