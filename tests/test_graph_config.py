"""Graph configuration tests (offline; no FalkorDB required)."""

from __future__ import annotations

import os
from unittest.mock import patch

import pytest

from app.graph.config import GraphSettings, get_graph_settings, reset_graph_settings_cache


def _clear_env(monkeypatch: pytest.MonkeyPatch) -> None:
    for key in list(os.environ):
        if key.startswith("BLASTRADIUS_GRAPH_"):
            monkeypatch.delenv(key, raising=False)


def test_graph_settings_defaults(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    reset_graph_settings_cache()
    settings = GraphSettings()
    assert settings.host == "localhost"
    assert settings.port == 6379
    assert settings.database == 0
    assert settings.graph_name == "blastradius"
    assert settings.socket_timeout_seconds == 10.0
    assert settings.socket_connect_timeout_seconds == 5.0
    assert settings.ssl is False
    assert settings.password is None
    assert settings.username is None
    assert not settings.has_credentials
    assert settings.connection_label == "localhost:6379/0 graph=blastradius"


def test_graph_settings_from_env(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    monkeypatch.setenv("BLASTRADIUS_GRAPH_HOST", "falkordb.example.test")
    monkeypatch.setenv("BLASTRADIUS_GRAPH_PORT", "6380")
    monkeypatch.setenv("BLASTRADIUS_GRAPH_PASSWORD", "secret-123")
    monkeypatch.setenv("BLASTRADIUS_GRAPH_USERNAME", "blastradius")
    monkeypatch.setenv("BLASTRADIUS_GRAPH_DATABASE", "3")
    monkeypatch.setenv("BLASTRADIUS_GRAPH_NAME", "mygraph")
    monkeypatch.setenv("BLASTRADIUS_GRAPH_SOCKET_TIMEOUT_SECONDS", "25")
    monkeypatch.setenv("BLASTRADIUS_GRAPH_SOCKET_CONNECT_TIMEOUT_SECONDS", "8")
    monkeypatch.setenv("BLASTRADIUS_GRAPH_SSL", "true")

    reset_graph_settings_cache()
    settings = GraphSettings.from_env()
    assert settings.host == "falkordb.example.test"
    assert settings.port == 6380
    assert settings.database == 3
    assert settings.graph_name == "mygraph"
    assert settings.socket_timeout_seconds == 25.0
    assert settings.socket_connect_timeout_seconds == 8.0
    assert settings.ssl is True
    assert settings.has_credentials is True
    assert settings.password.get_secret_value() == "secret-123"
    # The secret is not exposed in plain text on the settings object.
    assert "secret-123" not in settings.model_dump()


def test_graph_settings_validation(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    reset_graph_settings_cache()

    monkeypatch.setenv("BLASTRADIUS_GRAPH_PORT", "not-a-number")
    with pytest.raises(ValueError):
        GraphSettings.from_env()

    monkeypatch.delenv("BLASTRADIUS_GRAPH_PORT", raising=False)
    monkeypatch.setenv("BLASTRADIUS_GRAPH_PORT", "0")
    with pytest.raises(ValueError):
        GraphSettings.from_env()

    monkeypatch.delenv("BLASTRADIUS_GRAPH_PORT", raising=False)
    monkeypatch.setenv("BLASTRADIUS_GRAPH_PORT", "0")
    with pytest.raises(ValueError):
        GraphSettings.from_env()

    # Whitespace-only names are rejected by the field validator (direct use).
    with pytest.raises(ValueError):
        GraphSettings(graph_name="   ")

    reset_graph_settings_cache()


def test_get_graph_settings_is_cached(monkeypatch: pytest.MonkeyPatch) -> None:
    _clear_env(monkeypatch)
    reset_graph_settings_cache()
    first = get_graph_settings()
    second = get_graph_settings()
    assert first is second
    reset_graph_settings_cache()
