"""LLM provider adapter for the Phase 4B agent.

One configurable provider dialect is implemented in Phase 4B:
``openai-compat`` — the OpenAI *Chat Completions* API with tool/function
calling.  Provider endpoint (base URL), model, API key and timeouts are read
from :class:`app.agent.config.AgentSettings`, so the same adapter covers
OpenAI or any OpenAI-compatible endpoint (OpenRouter, Groq, vLLM, LM Studio,
Ollama's OpenAI-compatible server, ...).  The HTTP client is ``httpx`` with
injectable transports, mirroring :class:`app.osv.client.OsvApiClient`, so unit
tests are deterministic and offline.

The adapter never invents content: whatever the provider returns is parsed
strictly into :class:`ProviderTurn` (``content`` and/or parsed tool calls)
and handed to the bounded agent loop, which validates names/arguments before
any MCP execution.
"""

from __future__ import annotations

import json
from abc import ABC, abstractmethod
from typing import Any

import httpx

from app.agent.config import AgentSettings
from app.agent.errors import (
    AgentNotConfiguredError,
    AgentProviderError,
    AgentProviderTimeoutError,
)
from app.core.logging import get_logger, safe_text

_log = get_logger("agent.provider")

NEUTRAL_USER_AGENT: str = "blastradius-agent (+https://github.com/blastradius)"


# ---------------------------------------------------------------------------
# Neutral provider data model
# ---------------------------------------------------------------------------

class ProviderToolCall:
    """One tool invocation requested by the model.

    ``arguments`` is ``None`` when the provider returned malformed JSON
    arguments; the agent loop then records the call as rejected instead of
    executing it.
    """

    __slots__ = ("call_id", "name", "arguments", "raw_arguments")

    def __init__(self, call_id: str, name: str, arguments: dict[str, Any] | None, raw_arguments: str = "") -> None:
        self.call_id = call_id
        self.name = name
        self.arguments = arguments
        self.raw_arguments = raw_arguments

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        return f"ProviderToolCall(call_id={self.call_id!r}, name={self.name!r})"


class ProviderTurn:
    """The parsed result of one provider completion."""

    __slots__ = ("content", "tool_calls", "finish_reason")

    def __init__(
        self,
        content: str | None,
        tool_calls: list[ProviderToolCall] | None = None,
        finish_reason: str | None = None,
    ) -> None:
        self.content = content
        self.tool_calls = tool_calls or []
        self.finish_reason = finish_reason

    @property
    def wants_tools(self) -> bool:
        return bool(self.tool_calls)


class LLMProvider(ABC):
    """Interface every provider adapter must implement."""

    @abstractmethod
    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ProviderTurn:
        """Run one completion with the given neutral messages and tool specs.

        Neutral messages may use extra keys (``tool_calls`` with neutral
        ``{"call_id", "name", "arguments"}`` entries, ``tool_call_id`` on
        tool-role messages); implementations translate them into the wire
        dialect.  Malformed upstream payloads raise typed agent errors.
        """

    def close(self) -> None:  # pragma: no cover - default no-op
        """Release provider resources."""


# ---------------------------------------------------------------------------
# neutral -> OpenAI-compat wire message translation
# ---------------------------------------------------------------------------

def _to_wire_message(message: dict[str, Any]) -> dict[str, Any]:
    role = message.get("role")
    wire: dict[str, Any] = {"role": role, "content": message.get("content")}
    tool_calls = message.get("tool_calls")
    if role == "assistant" and tool_calls:
        wire["content"] = message.get("content")
        wire["tool_calls"] = [
            {
                "id": call.get("call_id", ""),
                "type": "function",
                "function": {
                    "name": call.get("name", ""),
                    "arguments": json.dumps(call.get("arguments", {}), ensure_ascii=True, default=str),
                },
            }
            for call in tool_calls
        ]
        if not wire["content"]:
            wire["content"] = None
    if role == "tool":
        wire["tool_call_id"] = message.get("call_id") or message.get("tool_call_id", "")
        wire.pop("call_id", None)
    return wire


def _to_wire_tool(spec: dict[str, Any]) -> dict[str, Any]:
    return {"type": "function", "function": spec}


# ---------------------------------------------------------------------------
# The one implemented provider
# ---------------------------------------------------------------------------

class OpenAICompatProvider(LLMProvider):
    """OpenAI-compatible Chat Completions client with function calling.

    Request: ``POST {base_url}/chat/completions`` with ``model``, bounded
    ``messages``/``tools``.  Response parsing is strict: a malformed payload
    raises :class:`AgentProviderError` rather than being partially trusted.
    """

    def __init__(
        self,
        settings: AgentSettings,
        *,
        client: httpx.Client | None = None,
    ) -> None:
        self._settings = settings
        token = settings.api_key.get_secret_value() if settings.api_key else ""
        self._auth_header = {"Authorization": f"Bearer {token}"}
        self._owned_client = client is None
        self._client = client or httpx.Client(
            base_url=settings.base_url,
            headers={
                "Content-Type": "application/json",
                "User-Agent": NEUTRAL_USER_AGENT,
            },
            timeout=httpx.Timeout(
                settings.provider_timeout_seconds,
                connect=min(5.0, settings.provider_timeout_seconds),
            ),
            follow_redirects=False,
        )

    # -- lifecycle ----------------------------------------------------------
    def close(self) -> None:
        if self._owned_client:
            self._client.close()

    def __enter__(self) -> "OpenAICompatProvider":
        return self

    def __exit__(self, *_exc: object) -> None:
        self.close()

    # -- completion ----------------------------------------------------------
    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ProviderTurn:
        """Run one chat completion; messages must be in the neutral format."""
        if not self._settings.is_configured:
            raise AgentNotConfiguredError()
        payload: dict[str, Any] = {
            "model": self._settings.model,
            "messages": [_to_wire_message(m) for m in messages],
        }
        if tools:
            payload["tools"] = [_to_wire_tool(t) for t in tools]
        body = self._post("/chat/completions", payload)
        return self._parse_response(body)

    # -- transport -----------------------------------------------------------
    def _post(self, path: str, payload: dict[str, Any]) -> dict[str, Any]:
        try:
            response = self._client.post(path, json=payload, headers=self._auth_header)
        except httpx.TimeoutException as exc:  # read/connect timeouts
            raise AgentProviderTimeoutError(
                "The model provider request timed out",
            ) from exc
        except httpx.HTTPError as exc:  # connect/transport problems
            raise AgentProviderError(
                "Could not reach the model provider endpoint",
                details={"reason": type(exc).__name__},
            ) from exc
        if response.status_code >= 400:
            raise self._status_error(response.status_code)
        try:
            body = response.json()
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError) as exc:
            raise AgentProviderError("The provider returned a non-JSON body") from exc
        if not isinstance(body, dict):
            raise AgentProviderError("The provider returned an unexpected body")
        return body

    @staticmethod
    def _status_error(status_code: int) -> AgentProviderError:
        if status_code in (401, 403):
            return AgentProviderError("The provider rejected the configured credentials")
        if status_code == 429:
            return AgentProviderError("The provider rate limited the request", retryable=True)
        return AgentProviderError(
            f"The provider returned HTTP {status_code}", retryable=status_code >= 500
        )

    # -- response parsing ----------------------------------------------------
    @staticmethod
    def _parse_response(body: dict[str, Any]) -> ProviderTurn:
        choices = body.get("choices")
        if not isinstance(choices, list) or not choices:
            raise AgentProviderError("The provider response has no choices")
        choice = choices[0]
        if not isinstance(choice, dict):
            raise AgentProviderError("The provider choice is malformed")
        message = choice.get("message")
        if not isinstance(message, dict):
            raise AgentProviderError("The provider response has no message")
        content = message.get("content")
        if content is not None and not isinstance(content, str):
            content = str(content)
        tool_calls = OpenAICompatProvider._parse_tool_calls(message.get("tool_calls"))
        finish_reason = choice.get("finish_reason")
        return ProviderTurn(
            content=content,
            tool_calls=tool_calls,
            finish_reason=str(finish_reason) if finish_reason is not None else None,
        )

    @staticmethod
    def _parse_tool_calls(raw: Any) -> list[ProviderToolCall]:
        if raw is None:
            return []
        if not isinstance(raw, list):
            raise AgentProviderError("The provider tool_calls field is malformed")
        parsed: list[ProviderToolCall] = []
        for index, entry in enumerate(raw):
            if not isinstance(entry, dict):
                raise AgentProviderError("The provider tool call entry is malformed")
            function = entry.get("function")
            if not isinstance(function, dict):
                raise AgentProviderError("The provider tool call is missing its function")
            name = function.get("name")
            call_id = str(entry.get("id", f"call_{index}"))
            raw_arguments = function.get("arguments")
            raw_arguments = "" if raw_arguments is None else str(raw_arguments)
            if not isinstance(name, str) or not name.strip():
                raise AgentProviderError("The provider tool call has no name")
            arguments: dict[str, Any] | None
            try:
                decoded = json.loads(raw_arguments) if raw_arguments.strip() else {}
                arguments = decoded if isinstance(decoded, dict) else None
            except (json.JSONDecodeError, ValueError):
                arguments = None  # rejected later as a malformed-argument call
            parsed.append(
                ProviderToolCall(
                    call_id=call_id,
                    name=name.strip(),
                    arguments=arguments,
                    raw_arguments=raw_arguments,
                )
            )
        return parsed


# ---------------------------------------------------------------------------
# factory
# ---------------------------------------------------------------------------

def build_provider(settings: AgentSettings) -> LLMProvider:
    """Build the configured provider, validating that it is configured.

    Raises :class:`AgentNotConfiguredError` when no usable credentials/model
    are present, and :class:`AgentProviderError` when the requested provider
    dialect is unknown.
    """
    if settings.provider not in ("openai-compat",):
        raise AgentProviderError(f"Unsupported agent provider {settings.provider!r}")
    if not settings.is_configured:
        raise AgentNotConfiguredError()
    provider = OpenAICompatProvider(settings)
    _log.debug("provider built label=%s", safe_text(settings.connection_label, 120))
    return provider


__all__ = [
    "LLMProvider",
    "OpenAICompatProvider",
    "ProviderToolCall",
    "ProviderTurn",
    "build_provider",
]
