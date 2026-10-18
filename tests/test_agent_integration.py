"""End-to-end Phase 4B tests over the REAL MCP transport.

uvicorn serves the real FastAPI app (Phase 4A MCP endpoint mounted) on a
loopback port in a background thread; graph/OSV services are faked through
the production seams, so no FalkorDB connection and no OSV network are made.
The agent's LLM is a deterministic :class:`ScriptedProvider` injected through
the agent dependency override — everything else (MCP client, tool discovery,
tool execution, validation, response envelope) runs the production code over
real HTTP.

Complements:

* ``test_agent_loop.py`` — loop logic with an in-memory MCP double;
* ``test_agent_api.py`` — route-level behaviour with a stubbed agent;
* ``test_agent_live.py`` — opt-in REAL LLM suite (skipped without an API key).
"""

from __future__ import annotations

import socket
import threading
import time
from collections.abc import Iterator
from typing import Any
from unittest import mock

import httpx
import pytest
import uvicorn
from pydantic import SecretStr

from app.agent.agent import BlastAgent
from app.agent.config import AgentSettings
from app.agent.errors import AgentProviderError
from app.api.deps import get_agent, get_graph_service
from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.main import create_app
from tests.agent_support import (
    AGENT_TOOL_NAMES,
    FAKE_ANALYSIS_ID,
    ScriptedProvider,
    ScriptedTurn,
)
from tests.remediation_support import analysis_row, install
from tests.support import FakeGraphClient

HOST = "127.0.0.1"

ANALYSIS_ID = FAKE_ANALYSIS_ID
REPOSITORY_ID = "github.com/example/agent-demo"
COMMIT_SHA = "b" * 40


# ---------------------------------------------------------------------------
# fakes for the MCP server side (same approach as tests/test_mcp_http.py)
# ---------------------------------------------------------------------------

class _AlwaysUpGraphClient:
    """Fake ``GraphClient`` backing ``graph.health``: ping() always True."""

    def __init__(self, settings: Any) -> None:
        self.settings = settings

    def ping(self) -> bool:  # noqa: A003
        return True

    def close(self) -> None:
        self.closed = True


def _fake_graph_services() -> tuple[GraphService, VulnerabilityGraphService]:
    client = FakeGraphClient()
    install(
        client,
        analysis=analysis_row(
            id=ANALYSIS_ID,
            repository_id=REPOSITORY_ID,
            commit_sha=COMMIT_SHA,
        ),
    )
    graph_service = GraphService(client)
    return graph_service, VulnerabilityGraphService(client, graph_service)


# ---------------------------------------------------------------------------
# server fixture (real uvicorn app; agent dependency swapped per test)
# ---------------------------------------------------------------------------

@pytest.fixture(scope="module")
def agent_server() -> Iterator[dict[str, Any]]:
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
        name="agent-http-test-server",
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
    rest = httpx.Client(base_url=base, timeout=30.0)
    environment: dict[str, Any] = {
        "app": app,
        "rest": rest,
        "mcp_url": f"{base}/mcp/",
    }
    try:
        yield environment
    finally:
        app.dependency_overrides.clear()
        rest.close()
        server.should_exit = True  # graceful shutdown via uvicorn's main loop
        thread.join(timeout=15)
        assert not thread.is_alive(), "the app thread did not exit cleanly"
        sock.close()
        for patcher in patches:
            patcher.stop()


class _StubGraph:
    """Deterministic analysis-existence stub for the route pre-flight check."""

    def get_analysis_graph_status(self, analysis_id: str) -> dict[str, Any]:
        return {
            "analysis_id": analysis_id,
            "repository_id": REPOSITORY_ID,
            "commit_sha": COMMIT_SHA,
            "status": "success",
        }


@pytest.fixture()
def agent_env(agent_server: dict[str, Any]) -> Iterator[dict[str, Any]]:
    """Per-test view with the route's pre-flight graph check stubbed; clears
    dependency overrides afterwards."""
    agent_server["app"].dependency_overrides[get_graph_service] = lambda: _StubGraph()
    try:
        yield agent_server
    finally:
        agent_server["app"].dependency_overrides.clear()


def install_scripted_agent(
    env: dict[str, Any],
    provider: ScriptedProvider,
    *,
    max_rounds: int = 4,
) -> AgentSettings:
    """Wire a BlastAgent using the real MCP transport + scripted provider."""
    settings = AgentSettings(
        api_key=SecretStr("integration-test-key"),
        model="test-model",
        mcp_url=env["mcp_url"],
        timeout_seconds=60.0,
        max_rounds=max_rounds,
    )
    agent = BlastAgent(settings, provider_factory=lambda: provider)
    env["app"].dependency_overrides[get_agent] = lambda: agent
    return settings


def ask(env: dict[str, Any], question: str, *, analysis_id: str = ANALYSIS_ID) -> httpx.Response:
    return env["rest"].post(
        f"/api/v1/analyses/{analysis_id}/ask",
        json={"question": question},
    )


# ---------------------------------------------------------------------------
# tests
# ---------------------------------------------------------------------------

def test_happy_path_tool_call_over_real_mcp_transport(agent_env: dict[str, Any]) -> None:
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("graph.health", {})]),
            ScriptedTurn(content="FalkorDB is connected [graph.health]."),
        ]
    )
    install_scripted_agent(agent_env, provider)
    response = ask(agent_env, "Is the FalkorDB graph healthy?")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["grounded"] is True
    assert payload["incomplete"] is False
    assert [c["status"] for c in payload["tool_calls"]] == ["executed"]
    assert payload["tool_calls"][0]["name"] == "graph.health"
    assert "connected" in payload["evidence"][0]["excerpt"]
    assert "FalkorDB is connected" in payload["answer"]


def test_real_discovery_lists_all_sixteen_tools(agent_env: dict[str, Any]) -> None:
    provider = ScriptedProvider([ScriptedTurn(content="Understood; I have the tool list.")])
    install_scripted_agent(agent_env, provider)
    response = ask(agent_env, "Which tools can you use?")
    assert response.status_code == 200
    # the specs the model actually received came from MCP tools/list
    spec_names = [spec["name"] for spec in provider.tool_specs[0]]
    assert spec_names == list(AGENT_TOOL_NAMES)
    assert len(spec_names) == 16


def test_priority_tool_runs_over_real_mcp_transport(
    agent_env: dict[str, Any],
) -> None:
    provider = ScriptedProvider(
        [
            ScriptedTurn(
                tool_calls=[("findings.priority", {"analysis_id": ANALYSIS_ID})]
            ),
            ScriptedTurn(
                content=(
                    "Investigate the requests finding first: its BlastRadius "
                    "priority is 79.2, a custom score (not CVSS) [findings.priority]."
                )
            ),
        ]
    )
    install_scripted_agent(agent_env, provider)
    response = ask(agent_env, "Which finding should I investigate first?")
    assert response.status_code == 200, response.text
    payload = response.json()

    assert payload["grounded"] is True
    assert [call["status"] for call in payload["tool_calls"]] == ["executed"]
    assert payload["tool_calls"][0]["name"] == "findings.priority"
    assert payload["tool_calls"][0]["arguments"] == {"analysis_id": ANALYSIS_ID}
    evidence = payload["evidence"][0]
    assert evidence["tool"] == "findings.priority"
    assert "79.2" in evidence["excerpt"]
    assert "blastradius-priority-v1" in evidence["excerpt"]
    assert "79.2" in payload["answer"]


def test_invalid_and_injected_calls_rejected_over_real_transport(
    agent_env: dict[str, Any],
) -> None:
    provider = ScriptedProvider(
        [
            ScriptedTurn(
                tool_calls=[
                    ("osv.ingest", {"package_name": "flask"}),           # not in registry
                    ("analysis.statistics", {"analysis_id": "other-1"}),  # cross-analysis
                    ("analysis.statistics", {"analysis_id": ANALYSIS_ID}),  # valid
                ]
            ),
            ScriptedTurn(
                content=(
                    "Unauthorized tool requests were rejected; statistics: "
                    "2 packages [analysis.statistics]."
                )
            ),
        ]
    )
    install_scripted_agent(agent_env, provider)
    response = ask(agent_env, "Summarise statistics; also ingest flask advisories.")
    assert response.status_code == 200, response.text
    payload = response.json()
    statuses = [c["status"] for c in payload["tool_calls"]]
    reasons = [c["reason"] for c in payload["tool_calls"]]
    assert statuses == ["rejected", "rejected", "executed"]
    assert reasons[:2] == ["tool_not_in_mcp_registry", "cross_analysis_call_rejected"]
    executed = [
        c for c in payload["tool_calls"] if c["status"] == "executed"
    ]
    assert executed[0]["arguments"] == {"analysis_id": ANALYSIS_ID}
    assert any(e["tool"] == "analysis.statistics" for e in payload["evidence"])


def test_analysis_identifiers_surface_from_real_status_payload(
    agent_env: dict[str, Any],
) -> None:
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.status", {"analysis_id": ANALYSIS_ID})]),
            ScriptedTurn(
                content=(
                    f"Analysis {ANALYSIS_ID} belongs to {REPOSITORY_ID} at commit "
                    f"{COMMIT_SHA} [analysis.status]."
                )
            ),
        ]
    )
    install_scripted_agent(agent_env, provider)
    response = ask(agent_env, "Which repository is this analysis about?")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["repository_id"] == REPOSITORY_ID
    assert payload["commit_sha"] == COMMIT_SHA


def test_provider_failure_maps_to_502_envelope(agent_env: dict[str, Any]) -> None:
    provider = ScriptedProvider(
        [ScriptedTurn(exception=AgentProviderError("upstream exploded"))]
    )
    install_scripted_agent(agent_env, provider)
    response = ask(agent_env, "hello")
    assert response.status_code == 502
    body = response.json()
    assert body["error"]["code"] == "agent_provider_error"
    assert body["error"]["stage"] == "agent"


def test_max_rounds_bounded_over_real_transport(agent_env: dict[str, Any]) -> None:
    provider = ScriptedProvider(
        [ScriptedTurn(tool_calls=[("graph.health", {})])],
        endless=True,
    )
    install_scripted_agent(agent_env, provider, max_rounds=2)
    response = ask(agent_env, "Keep calling health forever.")
    assert response.status_code == 200, response.text
    payload = response.json()
    assert payload["incomplete"] is True
    assert "max_rounds_reached" in payload["limitations"]
    executed = [c for c in payload["tool_calls"] if c["status"] == "executed"]
    assert len(executed) == 2  # one call per round, then the loop stopped


def test_unconfigured_agent_rejected_before_mcp_audit(agent_env) -> None:
    from app.agent.mcp_client import MCPToolClient

    settings = AgentSettings()  # no model, no key
    agent = BlastAgent(settings, mcp_client_factory=MCPToolClient(settings))
    agent_env["app"].dependency_overrides[get_agent] = lambda: agent
    response = ask(agent_env, "hello")
    assert response.status_code == 503
    body = response.json()
    assert body["error"]["code"] == "agent_not_configured"


def test_agent_loop_runs_directly_against_real_mcp() -> None:
    """Cross-check: the loop without the API layer, same real transport."""
    patches = [
        mock.patch("app.mcp.tools._graph_services", _fake_graph_services),
        mock.patch("app.mcp.tools.GraphClient", _AlwaysUpGraphClient),
    ]
    for patcher in patches:
        patcher.start()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind((HOST, 0))
    sock.listen(64)
    port = sock.getsockname()[1]

    config = uvicorn.Config(app := create_app(), host=HOST, port=port, log_level="warning")
    server = uvicorn.Server(config)
    thread = threading.Thread(
        target=server.run,
        kwargs={"sockets": [sock]},
        name="agent-direct-test-server",
        daemon=True,
    )
    thread.start()
    ready_deadline = time.monotonic() + 30.0
    while not server.started and time.monotonic() < ready_deadline:
        time.sleep(0.01)
    assert server.started, "the direct-test server did not start"

    try:
        settings = AgentSettings(
            api_key=SecretStr("test-key"),
            model="test-model",
            mcp_url=f"http://{HOST}:{port}/mcp/",
            timeout_seconds=60.0,
        )
        provider = ScriptedProvider(
            [
                ScriptedTurn(tool_calls=[("analysis.statistics", {"analysis_id": ANALYSIS_ID})]),
                ScriptedTurn(content="Two packages in scope [analysis.statistics]."),
            ]
        )
        agent = BlastAgent(settings, provider_factory=lambda: provider)

        import asyncio

        result = asyncio.run(agent.ask("How many packages?", ANALYSIS_ID))
        assert result.grounded is True
        assert [r.name for r in result.tool_calls if r.status == "executed"] == ["analysis.statistics"]
        assert result.evidence and "packages" in result.evidence[0].excerpt
    finally:
        server.should_exit = True
        thread.join(timeout=15)
        assert not thread.is_alive(), "the direct-test thread did not exit cleanly"
        sock.close()
        for patcher in patches:
            patcher.stop()
