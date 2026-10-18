"""MCP client for the Phase 4B agent.

Uses the *official* MCP Python SDK's Streamable HTTP client
(:func:`mcp.client.streamable_http.streamable_http_client` +
:class:`mcp.client.session.ClientSession`) — the same transport family the
Phase 4A server implements and that was verified end-to-end over real HTTP.
The agent does **not** duplicate the tool registry: every callable tool and
its JSON schema is discovered through MCP ``tools/list``.  Because the
BlastRadius MCP server is read-only by construction (Phase 4A), discovery is
also authorization: only the eleven read-only tools can ever be executed.

Responses are parsed strictly: protocol errors and tool-execution errors
(``is_error``) are turned into typed agent errors; successful results are
returned as JSON-safe dicts with a per-result character cap so a huge graph
answer can never blow the conversation budget.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import CallToolResult

from app.agent.config import AgentSettings
from app.agent.errors import AgentMCPUnavailableError, AgentToolError
from app.core.logging import get_logger, safe_text

_log = get_logger("agent.mcp")


@dataclass(frozen=True)
class DiscoveredTool:
    """One tool advertised by the MCP server (name/description/JSON schema)."""

    name: str
    description: str
    input_schema: dict[str, Any] = field(default_factory=dict)


class MCPToolClient:
    """Async context manager around one MCP Streamable HTTP session."""

    def __init__(self, settings: AgentSettings) -> None:
        self._settings = settings
        self._session: ClientSession | None = None
        self._session_cm: Any = None
        self._transport_cm: Any = None
        self._transport_entered: bool = False

    # -- lifecycle ----------------------------------------------------------
    async def __aenter__(self) -> "MCPToolClient":
        """Open the transport and negotiate an MCP session.

        Connection/session failures (including the transport's internal
        task-group teardown, which surfaces as ``CancelledError``) are
        converted into a single deterministic :class:`AgentMCPUnavailableError`.
        This is safe: that cancellation originates from the transport's own
        scope dying, not from the caller's task, and swallowing it here keeps
        anyio cancel-scope accounting intact.
        """
        self._transport_cm = streamable_http_client(self._settings.mcp_url)
        try:
            read_stream, write_stream = await self._transport_cm.__aenter__()
        except BaseException as exc:
            # The transport generator never yielded: do NOT call __aexit__
            # (it would re-enter a half-built anyio task group).
            self._transport_cm = None
            self._session_cm = None
            self._session = None
            raise AgentMCPUnavailableError(
                "Could not connect to the configured MCP endpoint",
                details={"reason": _reason(exc)},
            ) from None
        self._transport_entered = True
        try:
            self._session_cm = ClientSession(read_stream, write_stream)
            self._session = await self._session_cm.__aenter__()
            await self._session.initialize()
        except BaseException as exc:
            # Close what was entered (same task), swallowing secondary errors
            # so the original failure surfaces cleanly.
            self._session = None
            await self._safe_close(self._close_entered(self._session_cm))
            await self._safe_close(self._close_transport())
            raise AgentMCPUnavailableError(
                "Could not initialize an MCP session with the configured endpoint",
                details={"reason": _reason(exc)},
            ) from None
        return self

    async def __aexit__(self, *exc_info: Any) -> None:
        await self._teardown()

    async def _safe_close(self, coro: Any) -> None:
        try:
            await coro
        except BaseException as exc:  # noqa: BLE001 - teardown must not mask the original error
            _log.debug("mcp client teardown secondary error reason=%s", _reason(exc))

    async def _teardown(self) -> None:
        self._session = None
        if self._session_cm is not None:
            session_cm, self._session_cm = self._session_cm, None
            await self._close_entered(session_cm)
        await self._close_transport()

    async def _close_entered(self, cm: Any) -> None:
        try:
            await cm.__aexit__(None, None, None)
        except BaseException as exc:  # noqa: BLE001 - teardown must not mask the original error
            _log.debug("mcp client teardown secondary error reason=%s", _reason(exc))

    async def _close_transport(self) -> None:
        if self._transport_cm is not None and self._transport_entered:
            self._transport_entered = False
            await self._close_entered(self._transport_cm)
        self._transport_cm = None

    # -- discovery ----------------------------------------------------------
    async def discover_tools(self) -> list[DiscoveredTool]:
        """List the read-only tools advertised by the MCP server."""
        self._require_session()
        assert self._session is not None
        try:
            listing = await self._session.list_tools()
        except Exception as exc:
            raise AgentMCPUnavailableError(
                "MCP tools/list failed", details={"reason": type(exc).__name__}
            ) from exc
        discovered: list[DiscoveredTool] = []
        for tool in listing.tools:
            schema = tool.input_schema if isinstance(tool.input_schema, dict) else {}
            discovered.append(
                DiscoveredTool(
                    name=tool.name,
                    description=(tool.description or "")[:2_000],
                    input_schema=schema,
                )
            )
        return discovered

    # -- execution ----------------------------------------------------------
    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        read_timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        """Execute one tool call and return its parsed, size-capped payload."""
        self._require_session()
        assert self._session is not None
        try:
            result: CallToolResult = await self._session.call_tool(  # type: ignore[assignment]
                name,
                arguments,
                read_timeout_seconds=read_timeout_seconds,
            )
        except Exception as exc:
            raise AgentToolError(name, f"The MCP call for {name!r} failed: {type(exc).__name__}") from exc
        payload = self._parse_result(name, result)
        if len(payload_render(payload)) > self._settings.max_tool_result_chars:
            payload = {"_truncated": True, "reason": "tool result exceeded the per-result character cap"}
        return payload

    # -- parsing -------------------------------------------------------------
    def _parse_result(self, name: str, result: CallToolResult) -> dict[str, Any]:
        if result.is_error:
            text = _first_text(result)
            raise AgentToolError(name, safe_text(text or "the tool reported an error", 300))
        structured = result.structured_content
        if structured is not None:
            if isinstance(structured, dict):
                return structured
            return {"value": structured}
        text = _first_text(result)
        if text is None:
            return {"empty": True}
        try:
            decoded = json.loads(text)
        except (json.JSONDecodeError, ValueError):
            return {"text": text}
        if isinstance(decoded, dict):
            return decoded
        return {"value": decoded}

    def _require_session(self) -> None:
        if self._session is None:
            raise AgentMCPUnavailableError("The MCP session is not open")


def _first_text(result: CallToolResult) -> str | None:
    for item in result.content or []:
        text = getattr(item, "text", None)
        if isinstance(text, str):
            return text
    return None


def _reason(exc: Exception) -> str:
    """Bounded exception classification for error envelopes (no payloads)."""
    return type(exc).__module__.split(".")[0] + "." + type(exc).__name__


def payload_render(payload: dict[str, Any]) -> str:
    """Canonical JSON rendering used for caps and evidence sizes."""
    return json.dumps(payload, ensure_ascii=True, default=str)


__all__ = ["DiscoveredTool", "MCPToolClient", "payload_render"]
