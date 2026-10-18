"""Tests for the bounded, evidence-grounded agent loop (Phase 4B).

The loop is exercised against deterministic doubles implementing the exact
production interfaces: :class:`tests.agent_support.ScriptedProvider` (the LLM)
and :class:`tests.agent_support.RecordingMCPClient` (the MCP transport).  No
network, no FalkorDB, no sleep-based waits.
"""

from __future__ import annotations

from typing import Any

import pytest

from app.agent.agent import FALLBACK_ANSWER_TEMPLATE, BlastAgent
from app.agent.config import AgentSettings
from app.agent.errors import (
    AgentMCPUnavailableError,
    AgentNotConfiguredError,
    AgentProviderError,
    AgentProviderTimeoutError,
)
from app.core.errors import InputValidationError
from tests.agent_support import (
    FAKE_ANALYSIS_ID,
    FAKE_COMMIT_SHA,
    FAKE_REPOSITORY_ID,
    RecordingMCPClient,
    ScriptedProvider,
    ScriptedTurn,
    agent_settings,
    make_discovered_tools,
    run_async,
)

Q = "What does the security posture of this analysis look like?"


def make_agent(
    *,
    settings: AgentSettings | None = None,
    provider: ScriptedProvider | None = None,
    mcp: RecordingMCPClient | None = None,
) -> tuple[BlastAgent, ScriptedProvider, RecordingMCPClient]:
    settings = settings or agent_settings()
    provider = provider or ScriptedProvider([ScriptedTurn(content="All clear.")])
    mcp = mcp or RecordingMCPClient(tools=make_discovered_tools())
    agent = BlastAgent(
        settings,
        provider_factory=lambda: provider,
        mcp_client_factory=lambda: mcp,
    )
    return agent, provider, mcp


# ---------------------------------------------------------------------------
# tool registry / discovery
# ---------------------------------------------------------------------------

def test_tools_sent_to_the_llm_come_from_mcp_discovery() -> None:
    mcp = RecordingMCPClient(tools=make_discovered_tools())
    agent, provider, _ = make_agent(mcp=mcp)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert result.grounded is True
    specs = provider.tool_specs[0]
    assert [spec["name"] for spec in specs] == [tool.name for tool in mcp.tools]
    assert len(specs) == 16  # the discovered read-only surface, nothing else


def test_tool_specs_carry_discovered_schemas() -> None:
    tools = make_discovered_tools({"osv.lookup": ["package_name", "ecosystem"]})
    agent, provider, _ = make_agent(mcp=RecordingMCPClient(tools=tools))
    run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    lookup_spec = next(s for s in provider.tool_specs[0] if s["name"] == "osv.lookup")
    assert lookup_spec["parameters"]["required"] == ["package_name", "ecosystem"]


# ---------------------------------------------------------------------------
# tool selection / sequential execution
# ---------------------------------------------------------------------------

def test_correct_tool_selected_and_executed_with_scope() -> None:
    payloads = {
        "analysis.vulnerabilities": {"count": 1, "items": [{"id": "CVE-2024-1234"}]},
    }
    mcp = RecordingMCPClient(tools=make_discovered_tools(), payloads=payloads)
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.vulnerabilities", {"analysis_id": FAKE_ANALYSIS_ID})]),
            ScriptedTurn(content="One advisory exists: CVE-2024-1234 [analysis.vulnerabilities]."),
        ]
    )
    agent, _, mcp_ = make_agent(provider=provider, mcp=mcp)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert mcp_.executed == [("analysis.vulnerabilities", {"analysis_id": FAKE_ANALYSIS_ID})]
    assert [r.status for r in result.tool_calls] == ["executed"]
    assert result.rounds_used == 2
    assert result.grounded is True
    assert result.incomplete is False
    assert result.evidence[0].tool == "analysis.vulnerabilities"
    assert result.evidence[0].sequence == 1


def test_sequential_tool_calls_across_rounds() -> None:
    payloads = {
        "analysis.status": {
            "analysis_id": FAKE_ANALYSIS_ID,
            "repository_id": FAKE_REPOSITORY_ID,
            "commit_sha": FAKE_COMMIT_SHA,
            "status": "success",
        },
        "analysis.statistics": {"repositories": 1, "packages": 3, "dependency_edges": 5},
    }
    mcp = RecordingMCPClient(tools=make_discovered_tools(), payloads=payloads)
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.status", {"analysis_id": FAKE_ANALYSIS_ID})]),
            ScriptedTurn(tool_calls=[("analysis.statistics", {"analysis_id": FAKE_ANALYSIS_ID})]),
            ScriptedTurn(
                content=(
                    f"Status success for {FAKE_ANALYSIS_ID} ({FAKE_REPOSITORY_ID}) "
                    "[analysis.status]; statistics recorded [analysis.statistics]."
                )
            ),
        ]
    )
    agent, _, mcp_ = make_agent(provider=provider, mcp=mcp)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert [name for name, _args in mcp_.executed] == ["analysis.status", "analysis.statistics"]
    assert [e.sequence for e in result.evidence] == [1, 2]
    assert result.repository_id == FAKE_REPOSITORY_ID
    assert result.commit_sha == FAKE_COMMIT_SHA
    assert result.grounded is True


def test_tool_result_is_fed_back_as_tool_message() -> None:
    mcp = RecordingMCPClient(
        tools=make_discovered_tools(),
        payloads={"analysis.status": {"status": "success"}},
    )
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.status", {"analysis_id": FAKE_ANALYSIS_ID})]),
            ScriptedTurn(
                tool_calls=[("analysis.statistics", {"analysis_id": FAKE_ANALYSIS_ID})]
            ),
            ScriptedTurn(content="done"),
        ]
    )
    agent, _, _ = make_agent(provider=provider, mcp=mcp)
    run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    second_round = provider.messages[1]
    assert second_round[-1]["role"] == "tool"
    assert '{"status": "success"}' in second_round[-1]["content"]
    assert second_round[-2]["role"] == "assistant"
    assert second_round[-2]["tool_calls"] == [
        {"call_id": "call_0", "name": "analysis.status", "arguments": {"analysis_id": FAKE_ANALYSIS_ID}}
    ]


# ---------------------------------------------------------------------------
# invalid tools / arguments (prompt-injection behaviour included)
# ---------------------------------------------------------------------------

def test_unknown_tool_is_rejected_and_reported_to_the_model() -> None:
    # Simulates a prompt-injected request for an inaccessible tool.
    provider = ScriptedProvider(
        [
            ScriptedTurn(
                tool_calls=[
                    ("osv.ingest", {"package_name": "x"}),
                    ("graph.delete", {}),
                ]
            ),
            ScriptedTurn(content="I asked for tools that are not available to me."),
        ]
    )
    agent, _, mcp = make_agent(provider=provider)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert mcp.executed == []  # nothing outside the MCP registry executed
    assert [r.status for r in result.tool_calls] == ["rejected", "rejected"]
    assert {r.reason for r in result.tool_calls} == {"tool_not_in_mcp_registry"}
    assert "tool_not_in_mcp_registry" in result.limitations
    # the model actually received the rejection feedback
    next_round = provider.messages[1]
    rejects = [m for m in next_round if m["role"] == "tool"]
    assert len(rejects) == 2
    assert json_body_error(rejects[0]["content"]) == "tool_not_in_mcp_registry"


def json_body_error(content: str) -> str:
    import json

    return json.loads(content)["error"]


def test_missing_required_argument_is_rejected_locally() -> None:
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.statistics", {})]),
            ScriptedTurn(content="ok"),
        ]
    )
    agent, _, mcp = make_agent(provider=provider)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert mcp.executed == []
    assert result.tool_calls[0].status == "rejected"
    assert result.tool_calls[0].reason == "missing_required_argument:analysis_id"


def test_malformed_arguments_are_rejected_locally() -> None:
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.statistics", {"analysis_id": FAKE_ANALYSIS_ID})], malformed={0}),
            ScriptedTurn(content="ok"),
        ]
    )
    agent, _, mcp = make_agent(provider=provider)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert result.tool_calls[0].status == "rejected"
    assert result.tool_calls[0].reason == "malformed_arguments"
    assert mcp.executed == []


def test_cross_analysis_call_rejected_but_cross_repo_lookup_allowed() -> None:
    payloads = {"vulnerability.get": {"id": "CVE-2024-1234", "aliases": [], "summary": "..."}}
    mcp = RecordingMCPClient(tools=make_discovered_tools(), payloads=payloads)
    provider = ScriptedProvider(
        [
            ScriptedTurn(
                tool_calls=[
                    ("analysis.statistics", {"analysis_id": "someone-elses-analysis"}),
                    ("vulnerability.get", {"vulnerability_id": "CVE-2024-1234"}),
                ]
            ),
            ScriptedTurn(
                content="Cross-analysis access was refused; advisory CVE-2024-1234 looked up [vulnerability.get]."
            ),
        ]
    )
    agent, _, mcp_ = make_agent(provider=provider, mcp=mcp)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    statuses = [r.status for r in result.tool_calls]
    reasons = [r.reason for r in result.tool_calls]
    assert statuses == ["rejected", "executed"]
    assert reasons == ["cross_analysis_call_rejected", None]
    assert ("vulnerability.get", {"vulnerability_id": "CVE-2024-1234"}) in mcp_.executed
    assert ("analysis.statistics", {"analysis_id": "someone-elses-analysis"}) not in mcp_.executed
    assert result.limitations


def test_per_round_tool_budget_records_overflow_rejections() -> None:
    settings = agent_settings(max_tool_calls_per_round=2)
    provider = ScriptedProvider(
        [
            ScriptedTurn(
                tool_calls=[
                    ("analysis.status", {"analysis_id": FAKE_ANALYSIS_ID}),
                    ("analysis.statistics", {"analysis_id": FAKE_ANALYSIS_ID}),
                    ("analysis.packages", {"analysis_id": FAKE_ANALYSIS_ID}),
                ]
            ),
            ScriptedTurn(content="done"),
        ]
    )
    agent, _, mcp = make_agent(settings=settings, provider=provider)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    executed = [r for r in result.tool_calls if r.status == "executed"]
    assert len(executed) == 2  # capped
    assert len(mcp.executed) == 2
    overflow = [r for r in result.tool_calls if r.status == "rejected"]
    assert overflow and overflow[0].reason == "tool_budget_per_round_exceeded"


def test_tool_failure_reported_and_loop_continues() -> None:
    mcp = RecordingMCPClient(
        tools=make_discovered_tools(),
        error_for={"analysis.status": "FalkorDB unreachable"},
    )
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.status", {"analysis_id": FAKE_ANALYSIS_ID})]),
            ScriptedTurn(content="The analysis status tool failed; no status evidence is available."),
        ]
    )
    agent, _, mcp_ = make_agent(provider=provider, mcp=mcp)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert [r.status for r in result.tool_calls] == ["failed"]
    assert "FalkorDB unreachable" in result.tool_calls[0].reason  # type: ignore[operator]
    assert "tool_failure" in result.limitations
    assert result.evidence == []
    assert result.grounded is True and result.incomplete is False
    assert mcp_.executed == [("analysis.status", {"analysis_id": FAKE_ANALYSIS_ID})]
    failure_feedback = provider.messages[1][-1]
    assert failure_feedback["role"] == "tool"
    assert json_body_error(failure_feedback["content"]) == "tool_failure"


# ---------------------------------------------------------------------------
# limits: rounds / evidence / time
# ---------------------------------------------------------------------------

def test_max_rounds_stop_the_loop_with_a_deterministic_fallback() -> None:
    settings = agent_settings(max_rounds=2)
    provider = ScriptedProvider(
        [ScriptedTurn(tool_calls=[("analysis.status", {"analysis_id": FAKE_ANALYSIS_ID})])],
        endless=True,
    )
    agent, _, mcp = make_agent(settings=settings, provider=provider)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert result.incomplete is True
    assert "max_rounds_reached" in result.limitations
    assert result.rounds_used == 2
    assert len(mcp.executed) == 2  # one tool call per round
    expected = FALLBACK_ANSWER_TEMPLATE.format(tool_names="analysis.status", limitations="max_rounds_reached")[:14]
    assert result.answer[:14] == expected[:14]
    assert result.grounded is True  # deterministic summary, no fabricated facts


def test_evidence_budget_stops_further_tool_execution() -> None:
    big_marker = "y" * 200
    settings = agent_settings(max_evidence_chars=200)
    mcp = RecordingMCPClient(
        tools=make_discovered_tools(),
        payloads={"analysis.packages": {"packages": [big_marker]}},
    )
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.packages", {"analysis_id": FAKE_ANALYSIS_ID})]),
            ScriptedTurn(tool_calls=[("analysis.statistics", {"analysis_id": FAKE_ANALYSIS_ID})]),
            ScriptedTurn(content="done summarising collected evidence"),
        ]
    )
    agent, _, mcp_ = make_agent(settings=settings, provider=provider, mcp=mcp)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert len(mcp_.executed) == 1  # second call blocked by the evidence budget
    rejected = [r for r in result.tool_calls if r.status == "rejected"]
    assert rejected and rejected[0].reason == "evidence_budget_reached"


def test_time_budget_exhaustion_stops_before_extra_rounds(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    # Patch the agent module's ``time`` reference (NOT the shared stdlib
    # module) with a scripted clock: deadline base, round-1 check,
    # post-execution check, round-2 check (expired).
    class _SeqClock:
        def __init__(self, values: list[float]) -> None:
            self._values = iter(values)

        def monotonic(self) -> float:
            return next(self._values)

    monkeypatch.setattr(
        "app.agent.agent.time", _SeqClock([100.0, 100.1, 100.2, 10_000.0])
    )
    settings = agent_settings(timeout_seconds=10.0)
    mcp = RecordingMCPClient(
        tools=make_discovered_tools(),
        payloads={"analysis.status": {"status": "success"}},
    )
    provider = ScriptedProvider([ScriptedTurn(tool_calls=[("analysis.status", {"analysis_id": FAKE_ANALYSIS_ID})]), ScriptedTurn(content="never reached")], endless=True)
    agent, _, mcp_ = make_agent(settings=settings, provider=provider, mcp=mcp)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert result.incomplete is True
    assert "time_budget_exhausted" in result.limitations
    assert len(mcp_.executed) == 1
    assert result.rounds_used == 1


def test_max_rounds_override_is_clamped() -> None:
    settings = agent_settings(max_rounds=8)
    provider = ScriptedProvider(
        [ScriptedTurn(tool_calls=[("analysis.status", {"analysis_id": FAKE_ANALYSIS_ID})])],
        endless=True,
    )
    agent, _, _ = make_agent(settings=settings, provider=provider)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID, max_rounds=99))
    assert result.rounds_used == 8


# ---------------------------------------------------------------------------
# grounding: fabricated findings are withheld/flagged, evidence stays source of truth
# ---------------------------------------------------------------------------

def _grounding_fixture(*, strict: bool) -> tuple[BlastAgent, ScriptedProvider, RecordingMCPClient, AgentSettings]:
    settings = agent_settings(strict_grounding=strict)
    mcp = RecordingMCPClient(
        tools=make_discovered_tools(),
        payloads={
            "analysis.vulnerabilities": {
                "count": 1,
                "items": [{"id": "CVE-2024-1234", "link": "https://osv.dev/vulnerability/CVE-2024-1234"}],
            },
        },
    )
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.vulnerabilities", {"analysis_id": FAKE_ANALYSIS_ID})]),
            ScriptedTurn(
                content=(
                    "Confirmed advisory CVE-2024-1234 (https://osv.dev/vulnerability/CVE-2024-1234) "
                    "only. Additionally CVE-2030-9999 has severity 9.8."
                )
            ),
        ]
    )
    agent, _p, _m = make_agent(settings=settings, provider=provider, mcp=mcp)
    return agent, provider, mcp, settings


def test_grounding_withholds_fabricated_identifiers_in_strict_mode() -> None:
    agent, provider, mcp, _ = _grounding_fixture(strict=True)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert result.grounded is False
    assert "ungrounded_content_withheld" in result.limitations
    assert result.answer.startswith("Answer withheld:")
    assert "CVE-2030-9999" not in result.answer
    # the one grounded advisory link is still surfaced structurally
    assert result.advisory_links == ["https://osv.dev/vulnerability/CVE-2024-1234"]


def test_grounding_flags_but_keeps_answer_in_non_strict_mode() -> None:
    agent, provider, mcp, _ = _grounding_fixture(strict=False)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert result.grounded is False
    assert "ungrounded_content_flagged" in result.limitations
    assert "CVE-2030-9999" in result.answer  # kept but flagged


def test_evidence_backed_identifiers_are_accepted() -> None:
    mcp = RecordingMCPClient(
        tools=make_discovered_tools(),
        payloads={
            "analysis.vulnerabilities": {
                "count": 1,
                "items": [{"id": "CVE-2024-1234"}],
            },
        },
    )
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.vulnerabilities", {"analysis_id": FAKE_ANALYSIS_ID})]),
            ScriptedTurn(content="Advisory CVE-2024-1234 is the only result [analysis.vulnerabilities]."),
        ]
    )
    agent, _, _ = make_agent(provider=provider, mcp=mcp)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert result.grounded is True
    assert result.limitations == []


# ---------------------------------------------------------------------------
# provider / MCP failure modes
# ---------------------------------------------------------------------------

def test_unconfigured_provider_yields_stable_error_before_mcp() -> None:
    mcp = RecordingMCPClient(tools=make_discovered_tools())

    def provider_factory() -> ScriptedProvider:
        raise AgentNotConfiguredError()

    agent = BlastAgent(
        agent_settings(),
        provider_factory=provider_factory,  # type: ignore[arg-type]
        mcp_client_factory=lambda: mcp,
    )
    with pytest.raises(AgentNotConfiguredError):
        run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert mcp.opened is False


def test_provider_failure_mid_loop_propagates_and_cleans_up() -> None:
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.status", {"analysis_id": FAKE_ANALYSIS_ID})]),
            ScriptedTurn(exception=AgentProviderError("provider exploded")),
        ]
    )
    agent, _, mcp = make_agent(provider=provider)
    with pytest.raises(AgentProviderError):
        run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert provider.closed is True
    assert mcp.closed is True


def test_provider_timeout_propagates() -> None:
    provider = ScriptedProvider([ScriptedTurn(exception=AgentProviderTimeoutError())])
    agent, _, _ = make_agent(provider=provider)
    with pytest.raises(AgentProviderTimeoutError):
        run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))


def test_mcp_discovery_failure_maps_to_unavailable() -> None:
    mcp = RecordingMCPClient(
        tools=make_discovered_tools(),
        discovery_error=AgentMCPUnavailableError("connection refused"),
    )
    agent, _provider_object, mcp_ = make_agent(mcp=mcp)
    with pytest.raises(AgentMCPUnavailableError):
        run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert mcp_.opened is True
    assert mcp_.closed is True


def test_unusable_endpoint_maps_to_unavailable_error() -> None:
    # The real MCPToolClient wraps connection failures deterministically
    # (port 9 / discard on the loopback interface is never listening).
    from app.agent.mcp_client import MCPToolClient

    settings = agent_settings(mcp_url="http://127.0.0.1:9/mcp/")
    agent = BlastAgent(settings, mcp_client_factory=lambda: MCPToolClient(settings))
    with pytest.raises(AgentMCPUnavailableError):
        run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))


# ---------------------------------------------------------------------------
# empty / edge results
# ---------------------------------------------------------------------------

def test_empty_model_response_falls_back_deterministically() -> None:
    provider = ScriptedProvider(
        [
            ScriptedTurn(tool_calls=[("analysis.status", {"analysis_id": FAKE_ANALYSIS_ID})]),
            ScriptedTurn(content="   "),
        ]
    )
    agent, _, mcp = make_agent(provider=provider)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert result.incomplete is True
    assert "empty_model_response" in result.limitations
    assert "analysis.status" in result.answer


def test_empty_question_rejected_before_any_call() -> None:
    agent, provider, mcp = make_agent()
    with pytest.raises(InputValidationError):
        run_async(lambda: agent.ask("   ", FAKE_ANALYSIS_ID))
    assert provider.index == 0
    assert mcp.opened is False


def test_oversized_question_rejected_by_settings_cap() -> None:
    settings = agent_settings(max_question_chars=10)
    agent, provider, _ = make_agent(settings=settings)
    with pytest.raises(InputValidationError):
        run_async(lambda: agent.ask("x" * 11, FAKE_ANALYSIS_ID))
    assert provider.index == 0


def test_provider_turn_with_only_tool_calls_and_no_final_is_bounded() -> None:
    settings = agent_settings(max_rounds=1)
    provider = ScriptedProvider(
        [ScriptedTurn(tool_calls=[("analysis.status", {"analysis_id": FAKE_ANALYSIS_ID})])],
        endless=False,
    )
    agent, _, mcp = make_agent(settings=settings, provider=provider)
    result = run_async(lambda: agent.ask(Q, FAKE_ANALYSIS_ID))
    assert result.rounds_used == 1
    assert result.incomplete is True
    assert "max_rounds_reached" in result.limitations
    assert len(mcp.executed) == 1
    assert "analysis.status" in result.answer
