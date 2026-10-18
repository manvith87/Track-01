"""Opt-in LIVE Phase 4B tests: a real LLM provider + real MCP transport.

Skipped unless *all* of the following hold:

* ``BLASTRADIUS_AGENT_LIVE_TESTS=1``;
* a provider is configured (``BLASTRADIUS_AGENT_MODEL`` plus
  ``BLASTRADIUS_AGENT_API_KEY`` or ``OPENAI_API_KEY``).

The MCP server side still runs the offline graph fakes through the
production seams (no FalkorDB, no OSV) — what is *live* is the LLM: the
model must discover the tools over MCP ``tools/list``, decide to call
``graph.health``, receive the real tool result, and produce a grounded
answer.  The exact model name and the observed answer are printed for the
record.

This module documents that live LLM execution was NOT tested in this
repository's default environment (no provider credentials are configured).
"""

from __future__ import annotations

import asyncio
import os
import socket
import threading
import time
from collections.abc import Iterator
from typing import Any
from unittest import mock

import pytest
import uvicorn

from app.agent.agent import BlastAgent
from app.agent.config import AgentSettings
from app.graph.queries import GET_ANALYSIS, GET_STATISTICS
from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.main import create_app
from tests.support import FakeGraphClient, FakeQueryResult

HOST = "127.0.0.1"
ANALYSIS_ID = "analysis_agent_live_1"
REPOSITORY_ID = "github.com/example/agent-live-demo"
COMMIT_SHA = "c" * 40

LIVE_FLAG = os.environ.get("BLASTRADIUS_AGENT_LIVE_TESTS") == "1"
_LIVE_SETTINGS: AgentSettings | None = None
if LIVE_FLAG:
    try:
        _LIVE_SETTINGS = AgentSettings.from_env()
    except ValueError:
        _LIVE_SETTINGS = None

skip_without_credentials = pytest.mark.skipif(
    not (LIVE_FLAG and _LIVE_SETTINGS is not None and _LIVE_SETTINGS.is_configured),
    reason=(
        "live agent test: set BLASTRADIUS_AGENT_LIVE_TESTS=1, "
        "BLASTRADIUS_AGENT_MODEL and BLASTRADIUS_AGENT_API_KEY (or OPENAI_API_KEY)"
    ),
)


class _AlwaysUpGraphClient:
    def __init__(self, settings: Any) -> None:
        self.settings = settings

    def ping(self) -> bool:  # noqa: A003
        return True

    def close(self) -> None:
        self.closed = True


def _fake_graph_services() -> tuple[GraphService, VulnerabilityGraphService]:
    client = FakeGraphClient()
    client.connect()
    client.canned[GET_ANALYSIS] = FakeQueryResult(
        ["id", "repository_id", "commit_sha", "status"],
        [[ANALYSIS_ID, REPOSITORY_ID, COMMIT_SHA, "success"]],
    )
    client.canned[GET_STATISTICS] = FakeQueryResult(
        ["repositories", "packages", "dependency_edges", "vulnerability_edges"],
        [[1, 3, 2, 0]],
    )
    graph_service = GraphService(client)
    return graph_service, VulnerabilityGraphService(client, graph_service)


@pytest.fixture(scope="module")
def live_mcp_url() -> Iterator[str]:
    patches = [
        mock.patch("app.mcp.tools._graph_services", _fake_graph_services),
        mock.patch("app.mcp.tools.GraphClient", _AlwaysUpGraphClient),
    ]
    for patcher in patches:
        patcher.start()
    app = create_app()
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 0))
    sock.listen(64)
    port = sock.getsockname()[1]
    server = uvicorn.Server(uvicorn.Config(app, host=HOST, port=port, log_level="warning"))
    thread = threading.Thread(
        target=server.run, kwargs={"sockets": [sock]}, name="agent-live-test-server", daemon=True
    )
    thread.start()
    deadline = time.monotonic() + 30.0
    while not server.started and time.monotonic() < deadline:
        time.sleep(0.01)
    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        for patcher in patches:
            patcher.stop()
        pytest.fail("the live-test app did not start")
    try:
        yield f"http://{HOST}:{port}/mcp/"
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        sock.close()
        for patcher in patches:
            patcher.stop()


@skip_without_credentials
def test_real_llm_calls_graph_health_over_mcp(live_mcp_url: str) -> None:
    assert _LIVE_SETTINGS is not None
    settings = _LIVE_SETTINGS.model_copy(update={"mcp_url": live_mcp_url})
    agent = BlastAgent(settings)
    result = asyncio.run(
        agent.ask(
            "Is the FalkorDB graph connected? Use your tools to check, then answer briefly.",
            ANALYSIS_ID,
        )
    )
    print(f"\nLIVE model={settings.model} rounds={result.rounds_used}")
    print(f"LIVE answer={result.answer}")
    print(f"LIVE tool_calls={[(r.name, r.status) for r in result.tool_calls]}")
    executed = [r for r in result.tool_calls if r.status == "executed"]
    assert executed, "the live model did not invoke any MCP tool"
    assert any(r.name == "graph.health" for r in executed)
    assert result.grounded is True
