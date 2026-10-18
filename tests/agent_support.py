"""Deterministic test doubles for the Phase 4B agent suite.

Mirrors :mod:`tests.support` (graph/OSV fakes).  These doubles implement the
*production interfaces* (:class:`app.agent.provider.LLMProvider` and the
:class:`app.agent.mcp_client.MCPToolClient` async contract) so the bounded
loop, the validation rules and the grounding scanner are exercised against
the real code paths — only the LLM network and the MCP transport are
replaced.  Real-MCP-transport behaviour is covered separately in
``tests/test_agent_integration.py``.
"""

from __future__ import annotations

import asyncio
import json
from collections.abc import Iterable, Mapping
from typing import Any

from pydantic import SecretStr

from app.agent.config import AgentSettings
from app.agent.mcp_client import DiscoveredTool
from app.agent.provider import LLMProvider, ProviderToolCall, ProviderTurn

FAKE_ANALYSIS_ID = "analysis_agent_1"
FAKE_REPOSITORY_ID = "github.com/example/agent-demo"
FAKE_COMMIT_SHA = "b" * 40

#: Minimal discovered-tool registry mirroring the real MCP server surface.
AGENT_TOOL_NAMES: tuple[str, ...] = (
    "graph.health",
    "analysis.status",
    "analysis.statistics",
    "analysis.packages",
    "analysis.dependency_edges",
    "package.neighborhood",
    "analysis.vulnerabilities",
    "analysis.blast_radius",
    "vulnerability.get",
    "vulnerability.components",
    "osv.lookup",
    "findings.priority",
    "findings.detail",
    "remediation.groups",
    "remediation.group",
    "remediation.issue_preview",
)


def agent_settings(**overrides: Any) -> AgentSettings:
    """Build an offline-agent settings object (key set, timeout short)."""
    values: dict[str, Any] = {
        "api_key": SecretStr("test-key-123"),
        "model": "test-model-1",
        "timeout_seconds": 10.0,
        "mcp_url": "http://127.0.0.1:9/mcp/",
        **overrides,
    }
    return AgentSettings(**values)


class ScriptedTurn:
    """One scripted provider turn: text reply and/or requested tool calls."""

    def __init__(
        self,
        content: str | None = None,
        tool_calls: Iterable[tuple[str, Mapping[str, Any]]] | None = None,
        call_ids: Iterable[str] | None = None,
        *,
        malformed: set[int] | None = None,
        exception: Exception | None = None,
    ) -> None:
        self.content = content
        pairs = list(tool_calls or [])
        ids = [f"call_{i}" for i in range(len(pairs))]
        if call_ids is not None:
            ids = list(call_ids)
        malformed = malformed or set()
        self.tool_calls = [
            ProviderToolCall(
                call_id=ids[i],
                name=name,
                arguments=None if i in malformed else dict(arguments),
                raw_arguments="<malformed>" if i in malformed else json.dumps(dict(arguments)),
            )
            for i, (name, arguments) in enumerate(pairs)
        ]
        self.exception = exception


class ScriptedProvider(LLMProvider):
    """Records calls, replays scripted turns, raises scripted exceptions."""

    def __init__(self, turns: Iterable[ScriptedTurn], *, endless: bool = False) -> None:
        self._turns = list(turns)
        self._endless = endless
        self.index = 0
        self.messages: list[list[dict[str, Any]]] = []
        self.tool_specs: list[list[dict[str, Any]]] = []
        self.closed = False

    def complete(self, messages: list[dict[str, Any]], tools: list[dict[str, Any]]) -> ProviderTurn:
        self.messages.append([dict(m) for m in messages])
        self.tool_specs.append([dict(t) for t in tools])
        if not self._endless and self.index >= len(self._turns):
            raise AssertionError("ScriptedProvider ran out of scripted turns")
        turn = self._turns[min(self.index, len(self._turns) - 1)]
        self.index += 1
        if turn.exception is not None:
            raise turn.exception
        return ProviderTurn(
            content=turn.content,
            tool_calls=list(turn.tool_calls),
            finish_reason="tool_calls" if turn.tool_calls else "stop",
        )

    def close(self) -> None:
        self.closed = True


class RecordingMCPClient:
    """Eager in-memory stand-in for :class:`MCPToolClient`.

    ``discover_tools`` replays ``tools``; ``call_tool`` looks up
    ``payloads[name]`` and records executed calls; set ``error_for`` to make
    selected tools fail like the real ``AgentToolError`` path.
    """

    def __init__(
        self,
        *,
        tools: Iterable[DiscoveredTool],
        payloads: Mapping[str, Mapping[str, Any]] | None = None,
        error_for: Mapping[str, str] | None = None,
        discovery_error: Exception | None = None,
    ) -> None:
        from app.agent.errors import AgentToolError

        self._error_type = AgentToolError
        self.tools = list(tools)
        self.payloads = dict(payloads or {})
        self.error_for = dict(error_for or {})
        self.discovery_error = discovery_error
        self.executed: list[tuple[str, dict[str, Any]]] = []
        self.opened = False
        self.closed = False

    async def discover_tools(self) -> list[DiscoveredTool]:
        if self.discovery_error is not None:
            raise self.discovery_error
        return list(self.tools)

    async def call_tool(
        self,
        name: str,
        arguments: dict[str, Any],
        *,
        read_timeout_seconds: float | None = None,
    ) -> dict[str, Any]:
        self.executed.append((name, dict(arguments)))
        if name in self.error_for:
            raise self._error_type(name, self.error_for[name])
        payload = self.payloads.get(name, {"ok": True, "echo": {"name": name}})
        return json.loads(json.dumps(payload))  # round-trip like the wire format

    async def __aenter__(self) -> "RecordingMCPClient":
        self.opened = True
        return self

    async def __aexit__(self, *_exc_info: Any) -> None:
        self.closed = self.opened


def make_discovered_tools(
    required_overrides: Mapping[str, list[str]] | None = None,
) -> list[DiscoveredTool]:
    """Build the 16 expected discovered tools with minimal JSON schemas."""
    required: dict[str, list[str]] = {
        "graph.health": [],
        "analysis.status": ["analysis_id"],
        "analysis.statistics": ["analysis_id"],
        "analysis.packages": ["analysis_id"],
        "analysis.dependency_edges": ["analysis_id"],
        "package.neighborhood": ["package_id"],
        "analysis.vulnerabilities": ["analysis_id"],
        "analysis.blast_radius": ["analysis_id", "package_id"],
        "vulnerability.get": ["vulnerability_id"],
        "vulnerability.components": ["vulnerability_id"],
        "osv.lookup": ["package_name"],
        "findings.priority": ["analysis_id"],
        "findings.detail": ["analysis_id", "finding_id"],
        "remediation.groups": ["analysis_id"],
        "remediation.group": ["analysis_id", "group_id"],
        "remediation.issue_preview": ["analysis_id"],
    }
    required.update(required_overrides or {})
    return [
        DiscoveredTool(
            name=name,
            description=f"Read-only tool {name}.",
            input_schema={"type": "object", "required": list(names)},
        )
        for name, names in required.items()
    ]


def run_async(coro_factory: Any) -> Any:
    """Run an async agent flow from sync tests (own event loop)."""
    return asyncio.run(coro_factory())


__all__ = [
    "AGENT_TOOL_NAMES",
    "FAKE_ANALYSIS_ID",
    "FAKE_COMMIT_SHA",
    "FAKE_REPOSITORY_ID",
    "RecordingMCPClient",
    "ScriptedProvider",
    "ScriptedTurn",
    "agent_settings",
    "make_discovered_tools",
    "run_async",
]
