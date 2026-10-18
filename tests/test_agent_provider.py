"""Tests for the OpenAI-compatible tool-calling provider adapter (Phase 4B).

The provider is exercised through an injectable ``httpx`` transport
(``httpx.MockTransport``) so every request/response interaction is
deterministic and offline: wire-format capture, strict response parsing and
typed error mapping.
"""

from __future__ import annotations

import json
from typing import Any

import httpx
import pytest

from app.agent.config import AgentSettings
from app.agent.errors import (
    AgentNotConfiguredError,
    AgentProviderError,
    AgentProviderTimeoutError,
)
from app.agent.provider import (
    OpenAICompatProvider,
    ProviderToolCall,
    ProviderTurn,
    build_provider,
)
from tests.agent_support import agent_settings

SECRET = "test-key-123"


def build_provider_with_capture(
    *,
    body: Any = None,
    status: int = 200,
    raise_exc: Exception | None = None,
) -> OpenAICompatProvider:
    """OpenAICompatProvider over a MockTransport that captures requests."""
    capture: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        capture.append(request)
        if raise_exc is not None:
            raise raise_exc
        if isinstance(body, str):
            return httpx.Response(status, text=body)
        return httpx.Response(status, json=body)

    provider = OpenAICompatProvider(
        agent_settings(),
        client=httpx.Client(
            transport=httpx.MockTransport(handler),
            base_url=agent_settings().base_url,
        ),
    )
    provider.capture = capture  # type: ignore[attr-defined]
    return provider


CHAT_COMPLETIONS_BODY: dict[str, Any] = {
    "choices": [
        {
            "index": 0,
            "finish_reason": "stop",
            "message": {"role": "assistant", "content": "The graph looks healthy."},
        }
    ]
}

TOOL_CALL_BODY: dict[str, Any] = {
    "choices": [
        {
            "index": 0,
            "finish_reason": "tool_calls",
            "message": {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_1",
                        "type": "function",
                        "function": {
                            "name": "analysis.statistics",
                            "arguments": '{"analysis_id": "analysis_agent_1"}',
                        },
                    }
                ],
            },
        }
    ]
}


def send(
    provider: OpenAICompatProvider,
    messages: list[dict[str, Any]] | None = None,
    tools: list[dict[str, Any]] | None = None,
) -> ProviderTurn:
    return provider.complete(
        messages=messages
        if messages is not None
        else [
            {"role": "system", "content": "system prompt"},
            {"role": "user", "content": "security question"},
            {"role": "assistant", "content": None, "tool_calls": [
                {"call_id": "call_9", "name": "graph.health", "arguments": {}}
            ]},
            {"role": "tool", "call_id": "call_9", "content": '{"connected": true}'},
        ],
        tools=tools
        if tools is not None
        else [{"name": "graph.health", "description": "health", "parameters": {"type": "object"}}],
    )


# ---------------------------------------------------------------------------
# factory / configuration
# ---------------------------------------------------------------------------

def test_build_provider_requires_configuration() -> None:
    with pytest.raises(AgentNotConfiguredError):
        build_provider(AgentSettings())


def test_build_provider_returns_openai_compat() -> None:
    provider = build_provider(agent_settings())
    assert isinstance(provider, OpenAICompatProvider)
    provider.close()


def test_unconfigured_provider_refuses_to_complete() -> None:
    provider = OpenAICompatProvider(AgentSettings())
    with pytest.raises(AgentNotConfiguredError):
        provider.complete([{"role": "user", "content": "hi"}], [])


# ---------------------------------------------------------------------------
# happy-path parsing
# ---------------------------------------------------------------------------

def test_text_only_turn_is_parsed() -> None:
    provider = build_provider_with_capture(body=CHAT_COMPLETIONS_BODY)
    turn = send(provider)
    assert turn.content == "The graph looks healthy."
    assert turn.tool_calls == []
    assert turn.wants_tools is False
    assert turn.finish_reason == "stop"
    provider.close()


def test_tool_call_turn_is_parsed_with_arguments() -> None:
    provider = build_provider_with_capture(body=TOOL_CALL_BODY)
    turn = send(provider)
    assert turn.wants_tools is True
    assert len(turn.tool_calls) == 1
    call = turn.tool_calls[0]
    assert isinstance(call, ProviderToolCall)
    assert call.call_id == "call_1"
    assert call.name == "analysis.statistics"
    assert call.arguments == {"analysis_id": "analysis_agent_1"}
    provider.close()


def test_malformed_arguments_become_none_but_are_kept_for_rejection() -> None:
    body = json.loads(json.dumps(TOOL_CALL_BODY))
    body["choices"][0]["message"]["tool_calls"][0]["function"]["arguments"] = "{not json"
    provider = build_provider_with_capture(body=body)
    turn = send(provider)
    assert turn.tool_calls[0].arguments is None
    assert turn.tool_calls[0].raw_arguments == "{not json"
    provider.close()


# ---------------------------------------------------------------------------
# strict response validation
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("body", "reason"),
    [
        ({}, "no choices"),
        ({"choices": []}, "no choices"),
        ({"choices": [{"message": None}]}, "no message"),
        ({"choices": ["string-choice"]}, "malformed"),
        ({"choices": [{"message": {"tool_calls": "not-a-list"}, "content": None}]}, "malformed"),
        ({"choices": [{"message": {"tool_calls": [{"function": {}}]}}]}, "no name"),
    ],
)
def test_malformed_provider_payloads_raise_typed_errors(body: Any, reason: str) -> None:
    provider = build_provider_with_capture(body=body)
    with pytest.raises(AgentProviderError, match=reason):
        send(provider)
    provider.close()


def test_non_json_body_raises_provider_error() -> None:
    provider = build_provider_with_capture(body="<html>gateway error</html>")
    with pytest.raises(AgentProviderError, match="non-JSON"):
        send(provider)
    provider.close()


# ---------------------------------------------------------------------------
# HTTP status / transport error mapping
# ---------------------------------------------------------------------------

def test_http_401_maps_to_credentials_error_without_secrets() -> None:
    provider = build_provider_with_capture(status=401, body={"error": "denied"})
    with pytest.raises(AgentProviderError) as excinfo:
        send(provider)
    assert "credentials" in str(excinfo.value.message)
    assert SECRET not in str(excinfo.value.message)
    assert excinfo.value.http_status == 502
    provider.close()


def test_http_429_is_retryable() -> None:
    provider = build_provider_with_capture(status=429, body={"error": "rate-limited"})
    with pytest.raises(AgentProviderError) as excinfo:
        send(provider)
    assert excinfo.value.retryable is True
    provider.close()


def test_http_500_is_retryable_and_preserves_status_text() -> None:
    provider = build_provider_with_capture(status=500, body={"error": "boom"})
    with pytest.raises(AgentProviderError) as excinfo:
        send(provider)
    assert "HTTP 500" in str(excinfo.value.message)
    assert excinfo.value.retryable is True
    provider.close()


def test_provider_timeout_maps_to_agent_timeout() -> None:
    exc = httpx.ConnectTimeout("timed out", request=httpx.Request("POST", "https://unit.invalid"))
    provider = build_provider_with_capture(raise_exc=exc)
    with pytest.raises(AgentProviderTimeoutError) as excinfo:
        send(provider)
    assert excinfo.value.code.value == "agent_timeout"
    assert excinfo.value.http_status == 504
    assert excinfo.value.retryable is True
    provider.close()


def test_transport_failure_maps_to_provider_error() -> None:
    exc = httpx.ConnectError("connection refused")
    provider = build_provider_with_capture(raise_exc=exc)
    with pytest.raises(AgentProviderError) as excinfo:
        send(provider)
    assert excinfo.value.http_status == 502
    assert SECRET not in str(excinfo.value)
    provider.close()


# ---------------------------------------------------------------------------
# wire format (what the upstream actually receives)
# ---------------------------------------------------------------------------

def test_wire_payload_covers_model_messages_tools_and_auth() -> None:
    provider = build_provider_with_capture(body=CHAT_COMPLETIONS_BODY)
    send(provider)
    request = provider.capture[0]  # type: ignore[attr-defined]
    assert request.url.path.endswith("/chat/completions")
    assert request.headers["Authorization"] == f"Bearer {SECRET}"
    payload = json.loads(request.content)
    assert payload["model"] == "test-model-1"
    roles = [message["role"] for message in payload["messages"]]
    assert roles == ["system", "user", "assistant", "tool"]
    assistant = payload["messages"][2]
    assert assistant["tool_calls"] == [
        {
            "id": "call_9",
            "type": "function",
            "function": {"name": "graph.health", "arguments": "{}"},
        }
    ]
    tool_message = payload["messages"][3]
    assert tool_message["tool_call_id"] == "call_9"
    assert tool_message["content"] == '{"connected": true}'
    assert payload["tools"] == [
        {"type": "function", "function": {
            "name": "graph.health", "description": "health",
            "parameters": {"type": "object"},
        }}
    ]
    provider.close()


def test_wire_omits_tools_when_none() -> None:
    provider = build_provider_with_capture(body=CHAT_COMPLETIONS_BODY)
    provider.complete([{"role": "user", "content": "q"}], [])
    payload = json.loads(provider.capture[0].content)  # type: ignore[attr-defined]
    assert "tools" not in payload
    provider.close()
