"""API endpoint tests for the Phase 4B agent (POST /api/v1/analyses/{id}/ask).

The agent and graph dependencies are overridden with deterministic stubs so
the route, response model, validation and error envelope are exercised
offline.  The agent loop itself is covered in ``test_agent_loop.py`` and the
real-MCP-transport flow in ``test_agent_integration.py``.
"""

from __future__ import annotations

from typing import Any, Callable

import pytest
from fastapi.testclient import TestClient

from app.agent.agent import BlastAgent
from app.agent.config import AgentSettings
from app.agent.errors import (
    AgentMCPUnavailableError,
    AgentNotConfiguredError,
    AgentProviderError,
    AgentProviderTimeoutError,
)
from app.api.deps import get_agent, get_graph_service
from app.core.errors import InputValidationError
from app.graph.errors import GraphRecordNotFoundError
from app.main import create_app
from tests.agent_support import (
    FAKE_ANALYSIS_ID,
    FAKE_COMMIT_SHA,
    FAKE_REPOSITORY_ID,
)

QUESTION = "Which advisories affect this analysis?"


class StubGraph:
    """Graph service stub for the pre-flight analysis check."""

    def get_analysis_graph_status(self, analysis_id: str) -> dict[str, Any]:
        if analysis_id != FAKE_ANALYSIS_ID:
            raise GraphRecordNotFoundError(
                f"Analysis {analysis_id!r} was not found",
                details={"analysis_id": analysis_id},
            )
        return {
            "analysis_id": FAKE_ANALYSIS_ID,
            "repository_id": FAKE_REPOSITORY_ID,
            "commit_sha": FAKE_COMMIT_SHA,
            "status": "success",
        }


class StubAgent:
    """Agent stub returning a canned result or raising a canned error."""

    def __init__(
        self,
        outcome: Any,
        *,
        record: Callable[[str, str, int | None], None] | None = None,
    ) -> None:
        self._outcome = outcome
        self._record = record
        self.calls: list[dict[str, Any]] = []

    def ask_sync(
        self, question: str, analysis_id: str, *, max_rounds: int | None = None
    ) -> Any:
        self.calls.append(
            {"question": question, "analysis_id": analysis_id, "max_rounds": max_rounds}
        )
        if isinstance(self._outcome, Exception):
            raise self._outcome
        return self._outcome


def canned_result() -> Any:
    from app.agent.evidence import AgentResult, EvidenceReference, ToolCallRecord

    return AgentResult(
        analysis_id=FAKE_ANALYSIS_ID,
        answer="Analysis uses requests and Flask; Flask is linked to CVE-2023-0001 [analysis.status].",
        grounded=True,
        incomplete=False,
        rounds_used=2,
        tool_calls=[
            ToolCallRecord(
                round_index=1,
                name="analysis.status",
                status="executed",
                result_chars=88,
                arguments={"analysis_id": FAKE_ANALYSIS_ID},
            ),
            ToolCallRecord(
                round_index=2,
                name="osv.ingest",
                status="rejected",
                reason="tool_not_in_mcp_registry",
                arguments={"package_name": "flask"},
            ),
        ],
        evidence=[
            EvidenceReference(
                round_index=1,
                tool="analysis.status",
                sequence=1,
                excerpt='{"analysis_id": "analysis_agent_1", "status": "success"}',
                result_chars=88,
            )
        ],
        limitations=[],
        repository_id=FAKE_REPOSITORY_ID,
        commit_sha=FAKE_COMMIT_SHA,
        advisory_links=["https://osv.dev/vulnerability/CVE-2023-0001"],
    )


@pytest.fixture
def client_factory():
    created: list[TestClient] = []

    def factory(
        *,
        graph: Any = None,
        agent: Any = None,
    ) -> TestClient:
        app = create_app()
        app.dependency_overrides[get_graph_service] = lambda: graph if graph is not None else StubGraph()
        app.dependency_overrides[get_agent] = lambda: agent if agent is not None else StubAgent(canned_result())
        client = TestClient(app)
        created.append(client)
        return client

    yield factory
    for client in created:
        client.close()


def post(client: TestClient, body: dict[str, Any], analysis_id: str = FAKE_ANALYSIS_ID):
    return client.post(f"/api/v1/analyses/{analysis_id}/ask", json=body)


# ---------------------------------------------------------------------------
# happy path
# ---------------------------------------------------------------------------

def test_ask_returns_structured_grounded_answer(client_factory) -> None:
    client = client_factory()
    response = post(client, {"question": QUESTION})
    assert response.status_code == 200
    payload = response.json()
    assert payload["analysis_id"] == FAKE_ANALYSIS_ID
    assert payload["answer"].startswith("Analysis uses")
    assert payload["grounded"] is True
    assert payload["incomplete"] is False
    assert payload["rounds_used"] == 2
    assert payload["repository_id"] == FAKE_REPOSITORY_ID
    assert payload["commit_sha"] == FAKE_COMMIT_SHA
    assert payload["advisory_links"] == ["https://osv.dev/vulnerability/CVE-2023-0001"]
    assert [c["status"] for c in payload["tool_calls"]] == ["executed", "rejected"]
    assert payload["tool_calls"][1]["reason"] == "tool_not_in_mcp_registry"
    assert payload["evidence"][0]["tool"] == "analysis.status"
    assert payload["limitations"] == []


def test_ask_passes_max_rounds_through_to_the_agent(client_factory) -> None:
    agent = StubAgent(canned_result())
    client = client_factory(agent=agent)
    response = post(client, {"question": QUESTION, "max_rounds": 2})
    assert response.status_code == 200
    assert agent.calls[0]["max_rounds"] == 2


def test_ask_bounds_the_answer_schema_fields(client_factory) -> None:
    client = client_factory()
    payload = post(client, {"question": QUESTION}).json()
    # every documented key present, no undocumented keys
    expected = {
        "analysis_id", "answer", "grounded", "incomplete", "rounds_used",
        "tool_calls", "evidence", "limitations", "repository_id",
        "commit_sha", "advisory_links",
    }
    assert set(payload) == expected


# ---------------------------------------------------------------------------
# request validation
# ---------------------------------------------------------------------------

def test_empty_question_is_rejected(client_factory) -> None:
    client = client_factory()
    response = post(client, {"question": ""})
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "invalid_input"
    assert body["error"]["stage"] == "validation"


def test_oversized_question_is_rejected(client_factory) -> None:
    client = client_factory()
    response = post(client, {"question": "x" * 1001})
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_input"


@pytest.mark.parametrize("rounds", [0, 9])
def test_out_of_bound_max_rounds_is_rejected(client_factory, rounds: int) -> None:
    client = client_factory()
    response = post(client, {"question": QUESTION, "max_rounds": rounds})
    assert response.status_code == 422


def test_missing_question_is_rejected(client_factory) -> None:
    client = client_factory()
    response = post(client, {})
    assert response.status_code == 422


def test_unsupported_content_type_is_rejected(client_factory) -> None:
    client = client_factory()
    response = client.post(
        f"/api/v1/analyses/{FAKE_ANALYSIS_ID}/ask",
        content=b"hello",
        headers={"Content-Type": "text/plain"},
    )
    assert response.status_code in (422, 400)


# ---------------------------------------------------------------------------
# analysis scoping
# ---------------------------------------------------------------------------

def test_unknown_analysis_is_404_before_any_llm_work(client_factory) -> None:
    agent = StubAgent(AssertionError("agent must not be invoked"))
    client = client_factory(agent=agent)
    response = post(client, {"question": QUESTION}, analysis_id="missing-analysis")
    assert response.status_code == 404
    body = response.json()
    assert body["error"]["code"] == "repository_not_found"
    assert body["error"]["stage"] == "unknown"  # existing GraphRecordNotFoundError convention
    assert agent.calls == []  # the pre-flight check blocked the agent


# ---------------------------------------------------------------------------
# error mapping
# ---------------------------------------------------------------------------

@pytest.mark.parametrize(
    ("error", "status", "code", "stage"),
    [
        (AgentNotConfiguredError(), 503, "agent_not_configured", "agent"),
        (AgentProviderError("provider 500"), 502, "agent_provider_error", "agent"),
        (AgentProviderTimeoutError(), 504, "agent_timeout", "agent"),
        (AgentMCPUnavailableError("mcp down"), 502, "agent_mcp_unavailable", "agent"),
        (InputValidationError("bad question"), 400, "invalid_input", "validation"),
    ],
)
def test_agent_errors_use_the_shared_envelope(
    client_factory, error: Exception, status: int, code: str, stage: str
) -> None:
    client = client_factory(agent=StubAgent(error))
    response = post(client, {"question": QUESTION})
    assert response.status_code == status
    body = response.json()
    assert body["error"]["code"] == code
    assert body["error"]["stage"] == stage
    assert body["error"]["message"]


def test_error_reveals_no_secrets(client_factory) -> None:
    client = client_factory(agent=StubAgent(AgentProviderError("provider exploded")))
    response = post(client, {"question": QUESTION})
    json_text = response.text
    assert "Bearer" not in json_text
    assert "Authorization" not in json_text
    assert "api_key" not in json_text


def test_real_unconfigured_agent_yields_503(client_factory) -> None:
    # The REAL default construction path: a completely unconfigured
    # BlastAgent raises AgentNotConfiguredError before touching MCP.
    def must_not_open_mcp() -> Any:
        raise AssertionError("MCP must not open")

    real_agent = BlastAgent(AgentSettings(), mcp_client_factory=must_not_open_mcp)
    client = client_factory(agent=real_agent)
    response = post(client, {"question": QUESTION})
    assert response.status_code == 503
    body = response.json()
    assert body["error"]["code"] == "agent_not_configured"
    assert "BLASTRADIUS_AGENT_MODEL" in body["error"]["message"]
