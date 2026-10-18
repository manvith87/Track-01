"""Evidence-grounded agent API endpoint for BlastRadius Phase 4B.

Route (mounted under ``/api/v1`` by the version-one router):

* ``POST /api/v1/analyses/{analysis_id}/ask`` - ask a security question
  about one ingested analysis and get a structured answer grounded in MCP
  tool results.

Error handling follows the Phase 2/3 conventions (shared error envelope):

* ``404`` - analysis not found (checked before any LLM spend, mirroring the
  vulnerability endpoints);
* ``422`` - request validation (empty/too-long question);
* ``503`` - agent unconfigured (no provider model/key);
* ``502`` - provider error or MCP endpoint unavailable;
* ``504`` - provider timeout.

Secrets never appear in responses; tool-call arguments are echoed bounded and
redacted by :func:`app.agent.evidence.strip_argument_values`.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Path

from app.agent.agent import BlastAgent
from app.agent.evidence import AgentResult
from app.api.deps import get_agent, get_graph_service
from app.api.v1.agent_schemas import AgentAskRequest, AgentAskResponse
from app.core.logging import get_logger, safe_text
from app.graph.service import GraphService

router = APIRouter(tags=["agent"])

_log = get_logger("api.agent")

_RESPONSES: dict[int | str, dict[str, Any]] = {
    404: {"description": "Analysis not found"},
    422: {"description": "Invalid question or options"},
    503: {"description": "Agent not configured (missing provider model/key)"},
    502: {"description": "Model provider or MCP endpoint failure"},
    504: {"description": "Model provider timeout"},
}


@router.post(
    "/analyses/{analysis_id}/ask",
    response_model=AgentAskResponse,
    status_code=200,
    responses=_RESPONSES,
    summary="Ask a security question about one analysis",
    description=(
        "Runs the Phase 4B evidence-grounded agent: the question and the "
        "MCP-discovered read-only tool schemas are sent to the configured LLM "
        "provider, tool calls are validated (allowlist + analysis scope) and "
        "executed through MCP, and the final answer must pass a deterministic "
        "grounding check against the collected evidence. The agent never "
        "writes to the graph and never invents vulnerability data."
    ),
)
def ask_analysis(
    analysis_id: str = Path(...),
    body: AgentAskRequest = ...,
    graph: GraphService = Depends(get_graph_service),
    agent: BlastAgent = Depends(get_agent),
) -> AgentAskResponse:
    """Answer one security question about one analysis."""
    # Pre-flight: a missing analysis must be a clean 404, not an agent answer
    # about empty evidence. GraphRecordNotFoundError -> 404 envelope.
    graph.get_analysis_graph_status(analysis_id)
    _log.info(
        "agent ask analysis_id=%s question=%s",
        safe_text(analysis_id, 120),
        safe_text(body.question, 80),
    )
    result: AgentResult = agent.ask_sync(body.question, analysis_id, max_rounds=body.max_rounds)
    return AgentAskResponse.from_result(result)


__all__ = ["router"]
