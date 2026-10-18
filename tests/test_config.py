"""Configuration tests: defaults, environment parsing, validation, caching.

The environment is never trusted to be empty: ``_clear_env`` removes every
``BLASTRADIUS_*`` variable (and the token) before each test and ``monkeypatch``
restores the original values afterwards.
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.core.config import (
    ENV_PREFIX,
    Settings,
    get_settings,
    reset_settings_cache,
)


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith(ENV_PREFIX):
            monkeypatch.delenv(key, raising=False)


def test_defaults_are_safe_and_bounded() -> None:
    settings = Settings()
    assert settings.retrieval_strategy == "auto"
    assert settings.github_api_base_url == "https://api.github.com"
    assert settings.github_codeload_base_url == "https://codeload.github.com"
    assert settings.max_files_scanned == 20_000
    assert settings.max_download_bytes == 200 * 1024 * 1024
    assert settings.max_ingestion_seconds == 300.0
    assert settings.api_prefix == "/api/v1"
    assert settings.has_github_token is False
    assert ".git" in settings.excluded_directories
    assert ".venv" in settings.excluded_directories
    assert ".egg-info" in settings.excluded_directory_suffixes
    assert settings.temp_root is None


def test_from_env_reads_scalars_lists_and_secrets(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv(f"{ENV_PREFIX}LOG_LEVEL", "debug")
    monkeypatch.setenv(f"{ENV_PREFIX}LOG_JSON", "yes")
    monkeypatch.setenv(f"{ENV_PREFIX}MAX_FILES_SCANNED", "1_234")
    monkeypatch.setenv(f"{ENV_PREFIX}GIT_TIMEOUT_SECONDS", "9.5")
    monkeypatch.setenv(f"{ENV_PREFIX}RETRIEVAL_STRATEGY", "archive")
    monkeypatch.setenv(f"{ENV_PREFIX}API_PREFIX", "/custom/")
    monkeypatch.setenv(f"{ENV_PREFIX}EXCLUDED_DIRECTORIES", "one, two")
    monkeypatch.setenv(f"{ENV_PREFIX}TEMP_ROOT", str(tmp_path))
    monkeypatch.setenv(f"{ENV_PREFIX}GITHUB_TOKEN", "super-secret-token")

    settings = Settings.from_env()
    assert settings.log_level == "DEBUG"
    assert settings.log_json is True
    assert settings.max_files_scanned == 1234
    assert settings.git_timeout_seconds == 9.5
    assert settings.retrieval_strategy == "archive"
    assert settings.api_prefix == "/custom"
    assert settings.excluded_directories == ("one", "two")
    assert settings.temp_root == tmp_path
    assert settings.has_github_token is True
    assert settings.github_token is not None
    assert settings.github_token.get_secret_value() == "super-secret-token"
    # The token must never appear in a rendered form of the settings.
    assert "super-secret-token" not in repr(settings)
    assert "**********" in repr(settings)


def test_empty_env_values_fall_back_to_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv(f"{ENV_PREFIX}LOG_LEVEL", "   ")
    monkeypatch.setenv(f"{ENV_PREFIX}GITHUB_TOKEN", "  ")
    settings = Settings.from_env()
    assert settings.log_level == "INFO"
    assert settings.has_github_token is False


def test_invalid_int_env_fails_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv(f"{ENV_PREFIX}MAX_FILES_SCANNED", "many")
    with pytest.raises(ValueError, match="MAX_FILES_SCANNED"):
        Settings.from_env()


def test_below_minimum_int_env_fails_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv(f"{ENV_PREFIX}MAX_FILES_SCANNED", "0")
    with pytest.raises(ValueError, match=">= 1"):
        Settings.from_env()


def test_non_positive_float_env_fails_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv(f"{ENV_PREFIX}GIT_TIMEOUT_SECONDS", "0")
    with pytest.raises(ValueError, match="GIT_TIMEOUT_SECONDS"):
        Settings.from_env()


def test_invalid_bool_env_fails_fast(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv(f"{ENV_PREFIX}LOG_JSON", "maybe")
    with pytest.raises(ValueError, match="LOG_JSON"):
        Settings.from_env()


def test_model_level_validation() -> None:
    with pytest.raises(ValidationError):
        Settings(log_level="loud")
    with pytest.raises(ValidationError):
        Settings(api_prefix="api")
    with pytest.raises(ValidationError):
        Settings(github_api_base_url="http://api.github.com")
    with pytest.raises(ValidationError):
        Settings(retrieval_strategy="ftp")
    with pytest.raises(ValidationError):
        Settings(unknown_option=True)
    # Normalisation still applies when valid.
    assert Settings(log_level="debug").log_level == "DEBUG"
    assert Settings(api_prefix="/custom/").api_prefix == "/custom"
    assert Settings(github_api_base_url="https://api.example.test/").github_api_base_url == "https://api.example.test"


def test_settings_are_immutable() -> None:
    settings = Settings()
    with pytest.raises(ValidationError):
        settings.log_level = "DEBUG"  # type: ignore[misc]


def test_get_settings_caches_until_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv(f"{ENV_PREFIX}MAX_FILES_SCANNED", "42")
    reset_settings_cache()
    try:
        assert get_settings().max_files_scanned == 42
        monkeypatch.setenv(f"{ENV_PREFIX}MAX_FILES_SCANNED", "43")
        assert get_settings().max_files_scanned == 42  # cached
        reset_settings_cache()
        assert get_settings().max_files_scanned == 43
    finally:
        reset_settings_cache()
