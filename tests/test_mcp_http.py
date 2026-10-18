"""Protocol-level MCP HTTP integration tests (offline by default).

These tests exercise the *real* MCP protocol lifecycle over real HTTP against
the real FastAPI application: uvicorn serves the app on a loopback port in a
background thread of the test process (so the graph-service seams stay
patchable), and the tests are driven with the official MCP SDK client
(``mcp.client.streamable_http.streamable_http_client`` + ``ClientSession``).
No direct Python function calls replace the protocol in this module.

Verified lifecycle:

1. connection to the mounted MCP endpoint (``/mcp/``);
2. ``initialize`` handshake and capability negotiation;
3. the required ``notifications/initialized`` message (sent automatically by
   ``ClientSession.initialize``; proven indirectly — requests issued after the
   notification are served, so the server accepted the session as
   initialized);
4. ``tools/list`` returns all sixteen registered tools under their documented
   names (``graph.health``, ``analysis.statistics``, ...);
5. ``tools/call`` of two read-only tools with structured results;
6. error mapping: invalid arguments (and unknown ids) raise ``MCPError`` in the
   tool and surface as JSON-RPC protocol errors (``INVALID_PARAMS``); an
   unregistered tool surfaces as a ``CallToolResult(isError=True)`` result, as
   per the SDK's tool-error contract;
7. session termination (DELETE on close via ``terminate_on_close=True``) and
   clean application shutdown (asserted at fixture teardown).

Graph/OSV services are faked through the production seams
(``app.mcp.tools._graph_services`` and ``app.mcp.tools.GraphClient``), so no
FalkorDB connection and no OSV network request are made.  The opt-in live
suites in ``tests/test_graph_integration.py``, ``tests/test_osv_live.py`` and
``tests/test_mcp_live.py`` stay separate from this module.
"""

from __future__ import annotations

import asyncio
import json
import socket
import threading
import time
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator, Callable, Iterator
from typing import Any
from unittest import mock

import pytest
import uvicorn
from mcp import MCPError
from mcp.client.session import ClientSession
from mcp.client.streamable_http import streamable_http_client
from mcp.types import INVALID_PARAMS

from app.graph.queries import GET_ANALYSIS, GET_STATISTICS
from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.main import create_app
from tests.support import FakeGraphClient, FakeQueryResult


# ---------------------------------------------------------------------------
# constants / fakes
# ---------------------------------------------------------------------------

HOST = "127.0.0.1"

ANALYSIS_ID = "analysis_http_1"
REPOSITORY_ID = "github.com/example/demo"
COMMIT_SHA = "a" * 40

EXPECTED_TOOLS = sorted(
    [
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
    ]
)


class _IdAwareGraphClient(FakeGraphClient):
    """Fake graph client that answers GET_ANALYSIS only for ``ANALYSIS_ID``.

    The base fake returns canned rows regardless of query params.  This
    subclass filters the analysis lookup by the requested id, so an unknown
    analysis id deterministically raises ``GraphRecordNotFoundError`` inside
    the service instead of silently succeeding.
    """

    def query(
        self,
        cypher: str,
        *,
        params: dict[str, Any] | None = None,
        timeout: int | None = None,
        read_only: bool = False,
    ) -> FakeQueryResult:
        params = params or {}
        if cypher == GET_ANALYSIS and params.get("analysis_id") != ANALYSIS_ID:
            return FakeQueryResult(["id"], [])
        return super().query(cypher, params=params, timeout=timeout, read_only=read_only)


class _AlwaysUpGraphClient:
    """Fake ``GraphClient`` backing ``graph.health``: ping() always True.

    Replaces ``app.mcp.tools.GraphClient`` through the module seam, so the
    health probe never opens a real FalkorDB connection.
    """

    def __init__(self, settings: Any) -> None:
        self.settings = settings

    def ping(self) -> bool:  # noqa: A003 - mirrors the real client API
        return True

    def close(self) -> None:
        self.closed = True


def _fake_graph_services() -> tuple[GraphService, VulnerabilityGraphService]:
    """Replacement for ``app.mcp.tools._graph_services`` backed by fakes."""
    client = _IdAwareGraphClient()
    client.connect()
    client.canned[GET_ANALYSIS] = FakeQueryResult(
        ["id", "repository_id", "commit_sha", "status"],
        [[ANALYSIS_ID, REPOSITORY_ID, COMMIT_SHA, "success"]],
    )
    client.canned[GET_STATISTICS] = FakeQueryResult(
        ["repositories", "packages", "dependency_edges", "vulnerability_edges"],
        [[1, 2, 1, 0]],
    )
    graph_service = GraphService(client)
    return graph_service, VulnerabilityGraphService(client, graph_service)


def _result_payload(result: Any) -> dict[str, Any]:
    """Extract the tool's structured payload from a ``CallToolResult``."""
    if result.structured_content is not None:
        return result.structured_content
    assert result.content, "tool result must carry content"
    return json.loads(result.content[0].text)


@asynccontextmanager
async def _session(mcp_url: str) -> AsyncIterator[tuple[ClientSession, Any]]:
    """Open a real MCP client session (initialize + initialized notification)."""
    async with streamable_http_client(mcp_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            init_result = await session.initialize()
            yield session, init_result


def _run(coro: Callable[[], Any]) -> Any:
    """Run an async client flow in a sync test (own event loop, cleaned up)."""
    return asyncio.run(coro)


@asynccontextmanager
async def _connected(mcp_url: str) -> AsyncIterator[ClientSession]:
    """Open an initialized MCP client session and yield only the session."""
    async with streamable_http_client(mcp_url) as (read_stream, write_stream):
        async with ClientSession(read_stream, write_stream) as session:
            await session.initialize()
            yield session


# ---------------------------------------------------------------------------
# server fixture (real uvicorn app on a loopback port)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def mcp_url() -> Iterator[str]:
    """Serve the real FastAPI app on a loopback HTTP port in a thread.

    Stability contract:

    * the ports and sessions are unique (a pre-bound socket), there is no
      cross-test state sharing;
    * the readiness wait is a bounded poll on uvicorn's ``started`` flag, not
      an arbitrary fixed sleep;
    * on teardown the harness asserts the server thread exits cleanly — the
      "graceful shutdown" part of the lifecycle.
    """
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

    config = uvicorn.Config(app, host=HOST, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [sock]},
        name="mcp-http-test-server",
        daemon=True,
    )
    thread.start()

    ready_deadline = time.monotonic() + 30.0
    while not server.started and time.monotonic() < ready_deadline:
        if not thread.is_alive():
            break
        time.sleep(0.01)

    if not server.started:
        server.should_exit = True
        thread.join(timeout=5)
        sock.close()
        for patcher in patches:
            patcher.stop()
        pytest.fail("the FastAPI app did not start a uvicorn listener within 30s")

    base = f"http://{HOST}:{port}"
    try:
        yield f"{base}/mcp/"
    finally:
        server.should_exit = True  # graceful shutdown via uvicorn's main loop
        thread.join(timeout=15)
        assert not thread.is_alive(), "the app thread did not exit cleanly"
        sock.close()
        for patcher in patches:
            patcher.stop()


# ---------------------------------------------------------------------------
# 1-5: initialize, tools/list, tools/call over the real protocol
# ---------------------------------------------------------------------------

def test_protocol_lifecycle_initialization_tools_and_calls(mcp_url: str) -> None:
    """Full happy-path protocol lifecycle: init, negotiate, list, call."""

    async def flow() -> None:
        async with _session(mcp_url) as (session, init_result):
            # 2. protocol negotiation happened
            assert init_result.protocol_version
            assert init_result.server_info.name == "blastradius"
            assert init_result.server_info.title == "BlastRadius MCP Server"
            assert "graph.health" in init_result.instructions
            assert init_result.capabilities.tools is not None

            # 4. all sixteen tools are listed under their documented names
            listing = await session.list_tools()
            assert sorted(tool.name for tool in listing.tools) == EXPECTED_TOOLS

            # 5. graph.health over the protocol (faked ping, no FalkorDB)
            health = await session.call_tool("graph.health")
            assert health.is_error is not True
            payload = _result_payload(health)
            assert payload["connected"] is True
            assert payload["error"] is None

            # 5. analysis.statistics over the protocol (faked graph reads)
            stats = await session.call_tool(
                "analysis.statistics", {"analysis_id": ANALYSIS_ID}
            )
            assert stats.is_error is not True
            payload = _result_payload(stats)
            assert payload["repositories"] == 1
            assert payload["packages"] == 2
            assert payload["dependency_edges"] == 1
            assert payload["vulnerability_edges"] == 0

    _run(flow())


def test_analysis_statistics_unknown_analysis_maps_to_invalid_params(
    mcp_url: str,
) -> None:
    """A missing analysis surfaces as a protocol-level error to the client.

    The fakes only answer GET_ANALYSIS for ANALYSIS_ID; any other id raises
    GraphRecordNotFoundError inside the service, mapped to INVALID_PARAMS
    (never to an invented "connected"/"result" payload).
    """

    async def flow() -> None:
        async with _connected(mcp_url) as session:
            with pytest.raises(MCPError) as excinfo:
                await session.call_tool(
                    "analysis.statistics", {"analysis_id": "analysis_missing"}
                )
            assert excinfo.value.code == INVALID_PARAMS

    _run(flow())


# ---------------------------------------------------------------------------
# 6b: invalid arguments -> INVALID_PARAMS over the protocol
# ---------------------------------------------------------------------------

def test_invalid_tool_arguments_are_protocol_errors(mcp_url: str) -> None:
    """Empty analysis_id must be rejected by the server as INVALID_PARAMS."""

    async def flow() -> None:
        async with _connected(mcp_url) as session:
            with pytest.raises(MCPError) as excinfo:
                await session.call_tool(
                    "analysis.statistics", {"analysis_id": "   "}
                )
            assert excinfo.value.code == INVALID_PARAMS
            assert "analysis_id" in excinfo.value.message

            with pytest.raises(MCPError):
                await session.call_tool("analysis.packages", {"analysis_id": ""})

    _run(flow())


def test_unknown_tool_returns_an_is_error_result(mcp_url: str) -> None:
    """An unregistered tool is answered as a tool-execution error result.

    MCP maps tool-level failures into ``CallToolResult(isError=True)`` (a
    JSON-RPC *error* is reserved for protocol failures like INVALID_PARAMS —
    contrast with :func:`test_invalid_tool_arguments_are_protocol_errors`,
    where our tools raise ``MCPError`` and the client receives a JSON-RPC
    error).  The client therefore does not raise for this case; the caller
    inspects ``is_error``.
    """

    async def flow() -> None:
        async with _connected(mcp_url) as session:
            result = await session.call_tool("tool.does_not_exist", {})
            assert result.is_error is True
            text = result.content[0].text
            assert "Unknown tool" in text
            assert "tool.does_not_exist" in text

    _run(flow())


def test_invalid_arguments_are_rejected_before_a_result(mcp_url: str) -> None:
    """An out-of-window neighborhood depth is INVALID_PARAMS, never a result."""

    async def flow() -> None:
        async with _connected(mcp_url) as session:
            with pytest.raises(MCPError) as excinfo:
                await session.call_tool(
                    "package.neighborhood",
                    {"package_id": "pkg_x", "depth": 99},
                )
            assert excinfo.value.code == INVALID_PARAMS

    _run(flow())


# ---------------------------------------------------------------------------
# 7: session termination and re-initialization; graceful shutdown
# ---------------------------------------------------------------------------

def test_session_close_then_fresh_initialization(mcp_url: str) -> None:
    """Session cleanup: DELETE on close; a fresh client connects cleanly after."""

    async def flow() -> None:
        async with streamable_http_client(mcp_url) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                first = await session.initialize()
                assert first.server_info.name == "blastradius"
        # Exiting the async contexts sent DELETE (terminate_on_close=True);
        # the server accepted the termination without surfacing an error.
        # A brand-new client must initialize as a fresh session immediately:
        async with _session(mcp_url) as (second_session, init_result):
            listing = await second_session.list_tools()
            assert sorted(tool.name for tool in listing.tools) == EXPECTED_TOOLS
            assert init_result.protocol_version

    _run(flow())


def test_health_probe_via_raw_http_request(mcp_url: str) -> None:
    """The parent REST API stays reachable while the MCP transport is served."""
    import urllib.request

    with urllib.request.urlopen(
        f"{mcp_url.rsplit('/mcp/', 1)[0]}/health", timeout=10
    ) as response:
        body = json.loads(response.read().decode("utf-8"))
    assert response.status == 200
    assert body["status"] == "ok"
