"""Tests for Phase 4B agent configuration (env parsing, credentials)."""

from __future__ import annotations

import pytest
from pydantic import SecretStr, ValidationError

from app.agent.config import (
    ENV_PREFIX,
    AgentSettings,
    get_agent_settings,
    reset_agent_settings_cache,
)
from app.agent.errors import AgentNotConfiguredError
from tests.agent_support import agent_settings


# ---------------------------------------------------------------------------
# defaults / configuration state
# ---------------------------------------------------------------------------

def test_default_settings_are_unconfigured() -> None:
    settings = AgentSettings()
    assert settings.provider == "openai-compat"
    assert settings.model == ""
    assert settings.api_key is None
    assert settings.base_url == "https://api.openai.com/v1"
    assert settings.mcp_url == "http://127.0.0.1:8000/mcp/"
    assert settings.is_configured is False


@pytest.mark.parametrize(
    ("kwargs", "expected"),
    [
        ({"api_key": SecretStr("k"), "model": ""}, False),
        ({"api_key": None, "model": "m"}, False),
        ({"api_key": SecretStr(" "), "model": "m"}, False),
        ({"api_key": SecretStr("k"), "model": "m"}, True),
    ],
)
def test_is_configured_requires_model_and_key(kwargs: dict, expected: bool) -> None:
    assert AgentSettings(**kwargs).is_configured is expected


def test_connection_label_and_repr_never_leak_the_key() -> None:
    settings = AgentSettings(api_key=SecretStr("sk-super-secret"), model="gpt-test")
    label = settings.connection_label
    assert "sk-super-secret" not in label
    assert "agent_key" in label
    assert "gpt-test" in label
    assert "sk-super-secret" not in repr(settings)


def test_timeout_and_loop_limits_have_bounds() -> None:
    settings = agent_settings()
    assert settings.timeout_seconds > 0
    assert 1 <= settings.max_rounds <= 8
    assert settings.max_tool_calls_per_round >= 1
    assert settings.strict_grounding is True


# ---------------------------------------------------------------------------
# validation
# ---------------------------------------------------------------------------

def test_unknown_provider_dialect_rejected() -> None:
    with pytest.raises(ValidationError):
        AgentSettings(provider="anthropic")


def test_non_http_urls_rejected() -> None:
    with pytest.raises(ValidationError):
        AgentSettings(mcp_url="ftp://example.invalid/mcp")
    with pytest.raises(ValidationError):
        AgentSettings(base_url="api.openai.com/v1")


@pytest.mark.parametrize("field", ["max_rounds", "max_tool_calls_per_round"])
def test_round_caps_bounded_1_to_8(field: str) -> None:
    with pytest.raises(ValidationError):
        AgentSettings(**{field: 9})
    with pytest.raises(ValidationError):
        AgentSettings(**{field: 0})


# ---------------------------------------------------------------------------
# from_env
# ---------------------------------------------------------------------------

AGENT_ENV = ENV_PREFIX  # BLASTRADIUS_AGENT_


def test_from_env_reads_agent_environment(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv(f"{AGENT_ENV}MODEL", "env-model")
    monkeypatch.setenv(f"{AGENT_ENV}API_KEY", "env-key")
    monkeypatch.setenv(f"{AGENT_ENV}BASE_URL", "https://gateway.example/api/v1")
    monkeypatch.setenv(f"{AGENT_ENV}MCP_URL", "http://127.0.0.1:9000/mcp")
    monkeypatch.setenv(f"{AGENT_ENV}MAX_ROUNDS", "3")
    monkeypatch.setenv(f"{AGENT_ENV}STRICT_GROUNDING", "0")
    monkeypatch.setenv(f"{AGENT_ENV}TIMEOUT_SECONDS", "12.5")
    settings = AgentSettings.from_env()
    assert settings.model == "env-model"
    assert settings.api_key is not None and settings.api_key.get_secret_value() == "env-key"
    assert settings.base_url == "https://gateway.example/api/v1"
    assert settings.mcp_url == "http://127.0.0.1:9000/mcp"
    assert settings.max_rounds == 3
    assert settings.strict_grounding is False
    assert settings.timeout_seconds == 12.5
    assert settings.is_configured is True


def test_from_env_falls_back_to_openai_key(monkeypatch: pytest.MonkeyPatch) -> None:
    for name in ("API_KEY", "MODEL"):
        monkeypatch.delenv(f"{AGENT_ENV}{name}", raising=False)
    monkeypatch.setenv("OPENAI_API_KEY", "standard-openai-key")
    monkeypatch.setenv(f"{AGENT_ENV}MODEL", "gpt-test")
    settings = AgentSettings.from_env()
    assert settings.api_key is not None
    assert settings.api_key.get_secret_value() == "standard-openai-key"


def test_agent_key_takes_precedence_over_openai_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(f"{AGENT_ENV}API_KEY", "agent-specific")
    monkeypatch.setenv("OPENAI_API_KEY", "standard-openai-key")
    monkeypatch.setenv(f"{AGENT_ENV}MODEL", "gpt-test")
    settings = AgentSettings.from_env()
    assert settings.api_key is not None
    assert settings.api_key.get_secret_value() == "agent-specific"


def test_env_defaults_are_unconfigured(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv(f"{AGENT_ENV}API_KEY", raising=False)
    monkeypatch.delenv(f"{AGENT_ENV}MODEL", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    assert AgentSettings.from_env().is_configured is False


@pytest.mark.parametrize(
    ("name", "value", "fragment"),
    [
        ("MAX_ROUNDS", "not-a-number", "BLASTRADIUS_AGENT_MAX_ROUNDS"),
        ("STRICT_GROUNDING", "maybe", "BLASTRADIUS_AGENT_STRICT_GROUNDING"),
        ("TIMEOUT_SECONDS", "abc", "BLASTRADIUS_AGENT_TIMEOUT_SECONDS"),
    ],
)
def test_malformed_env_values_fail_fast(
    monkeypatch: pytest.MonkeyPatch, name: str, value: str, fragment: str
) -> None:
    monkeypatch.setenv(f"{AGENT_ENV}{name}", value)
    with pytest.raises(ValueError, match=fragment):
        AgentSettings.from_env()


# ---------------------------------------------------------------------------
# settings singleton cache
# ---------------------------------------------------------------------------

def test_get_agent_settings_caches_until_reset(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(f"{AGENT_ENV}_MODEL_PLACEHOLDER", raising=False)
    monkeypatch.setenv(f"{AGENT_ENV}MODEL", "cached-model")
    monkeypatch.delenv(f"{AGENT_ENV}API_KEY", raising=False)
    monkeypatch.delenv("OPENAI_API_KEY", raising=False)
    reset_agent_settings_cache()
    first = get_agent_settings()
    monkeypatch.setenv(f"{AGENT_ENV}MODEL", "changed-after-cache")
    assert get_agent_settings() is first  # cached
    reset_agent_settings_cache()
    second = get_agent_settings()
    assert second is not first
    assert second.model == "changed-after-cache"
    reset_agent_settings_cache()


def test_unconfigured_agent_error_is_readable() -> None:
    error = AgentNotConfiguredError()
    assert "BLASTRADIUS_AGENT_MODEL" in str(error)
    assert error.code.value == "agent_not_configured"
    assert error.http_status == 503
