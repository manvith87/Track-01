"""OSV configuration tests (offline; no network)."""

from __future__ import annotations

import os

import pytest

from app.osv.config import DEFAULT_BASE_URL, OsvSettings, get_osv_settings, reset_osv_settings_cache


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("BLASTRADIUS_OSV_"):
            monkeypatch.delenv(key, raising=False)


def test_osv_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    reset_osv_settings_cache()
    settings = OsvSettings()
    assert settings.base_url == DEFAULT_BASE_URL
    assert settings.base_url == "https://api.osv.dev"
    assert settings.timeout_seconds == 20.0
    assert settings.connect_timeout_seconds == 5.0
    assert settings.max_retries == 3
    assert settings.retry_backoff_seconds == 0.5
    assert settings.batch_size == 50
    assert settings.max_pages_per_query == 5
    assert settings.max_vulnerabilities_per_ingest == 200
    assert settings.max_packages_per_ingest == 200
    assert settings.connection_label == settings.base_url


def test_osv_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("BLASTRADIUS_OSV_BASE_URL", "https://osv.example.test")
    monkeypatch.setenv("BLASTRADIUS_OSV_TIMEOUT_SECONDS", "9.5")
    monkeypatch.setenv("BLASTRADIUS_OSV_CONNECT_TIMEOUT_SECONDS", "2")
    monkeypatch.setenv("BLASTRADIUS_OSV_MAX_RETRIES", "1")
    monkeypatch.setenv("BLASTRADIUS_OSV_RETRY_BACKOFF_SECONDS", "0.1")
    monkeypatch.setenv("BLASTRADIUS_OSV_BATCH_SIZE", "10")
    monkeypatch.setenv("BLASTRADIUS_OSV_MAX_PAGES_PER_QUERY", "3")
    monkeypatch.setenv("BLASTRADIUS_OSV_MAX_VULNERABILITIES_PER_INGEST", "7")
    monkeypatch.setenv("BLASTRADIUS_OSV_MAX_PACKAGES_PER_INGEST", "11")
    reset_osv_settings_cache()
    settings = get_osv_settings()
    try:
        assert settings.base_url == "https://osv.example.test"
        assert settings.timeout_seconds == 9.5
        assert settings.connect_timeout_seconds == 2.0
        assert settings.max_retries == 1
        assert settings.retry_backoff_seconds == 0.1
        assert settings.batch_size == 10
        assert settings.max_pages_per_query == 3
        assert settings.max_vulnerabilities_per_ingest == 7
        assert settings.max_packages_per_ingest == 11
    finally:
        reset_osv_settings_cache()


@pytest.mark.parametrize(
    ("name", "value"),
    [
        ("BATCH_SIZE", "0"),
        ("MAX_RETRIES", "not-a-number"),
        ("MAX_PAGES_PER_QUERY", "-2"),
        ("TIMEOUT_SECONDS", "0"),
    ],
)
def test_osv_settings_reject_bad_values(monkeypatch: pytest.MonkeyPatch, name: str, value: str) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv(f"BLASTRADIUS_OSV_{name}", value)
    with pytest.raises(ValueError):
        OsvSettings.from_env()


def test_osv_settings_reject_non_http_base_url(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    with pytest.raises(ValueError):
        OsvSettings(base_url="ftp://osv.example.test")