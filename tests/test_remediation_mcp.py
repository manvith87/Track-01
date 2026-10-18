"""Read-only MCP tool tests for Phase 5 prioritization/remediation.

The tool functions are called directly with the shared ``_graph_services``
seam patched to a canned ``FakeGraphClient``.  This exercises argument
validation, graph scoping and the exact serialized shapes the agent consumes.
"""

from __future__ import annotations

import asyncio
from typing import Any

import pytest
from mcp import MCPError
from mcp.types import INVALID_PARAMS

from app.mcp.tools import (
    findings_detail,
    findings_priority,
    remediation_group,
    remediation_groups,
)
from app.models.ids import stable_id
from tests.remediation_support import (
    ANALYSIS,
    PKG_REQUESTS,
    VULN_REQUESTS,
    install,
)
from tests.support import FakeGraphClient

FINDING_ID = stable_id("finding", ANALYSIS, PKG_REQUESTS, VULN_REQUESTS)
GROUP_ID = stable_id("fixgroup", ANALYSIS, PKG_REQUESTS, "2.32.1")


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _patch(
    monkeypatch: pytest.MonkeyPatch, client: FakeGraphClient
) -> None:
    from app.graph.service import GraphService
    from app.graph.vulnerability import VulnerabilityGraphService

    def services() -> tuple[GraphService, VulnerabilityGraphService]:
        graph = GraphService(client)
        return graph, VulnerabilityGraphService(client, graph)

    monkeypatch.setattr("app.mcp.tools._graph_services", services)


def _client(**kwargs: Any) -> FakeGraphClient:
    client = FakeGraphClient()
    install(client, **kwargs)
    return client


# ---------------------------------------------------------------------------
# findings.priority
# ---------------------------------------------------------------------------

def test_findings_priority_returns_ranked_findings(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _client())
    result = _run(findings_priority(ANALYSIS))

    assert result["analysis_id"] == ANALYSIS
    assert result["count"] == 2
    assert result["total"] == 2
    assert result["skip"] == 0
    assert result["limit"] == 25
    assert result["analysis_context"]["complete"] is True
    first = result["findings"][0]
    assert first["vulnerability_id"] == VULN_REQUESTS
    assert first["priority"]["rank"] == 1
    assert first["priority"]["score"] == 79.2
    assert first["priority"]["formula_version"] == "blastradius-priority-v1"
    assert first["priority"]["severity"]["numeric_score"] == 9.8
    assert first["priority"]["reachability"]["status"] == "direct"
    assert first["priority"]["remediation_available"] is True
    assert result["limitations"] == ["reachability_traversal_bounded_at_5_hops"]


def test_findings_priority_paginates(monkeypatch: pytest.MonkeyPatch) -> None:
    _patch(monkeypatch, _client())
    result = _run(findings_priority(ANALYSIS, skip=1, limit=1))
    assert result["count"] == 1
    assert result["total"] == 2
    assert result["findings"][0]["vulnerability_id"] != VULN_REQUESTS


@pytest.mark.parametrize(
    "analysis_id, skip, limit",
    [
        ("", 0, 25),
        ("   ", 0, 25),
        (ANALYSIS, -1, 25),
        (ANALYSIS, 0, 0),
        (ANALYSIS, 0, 101),
    ],
)
def test_findings_priority_validates_arguments(
    monkeypatch: pytest.MonkeyPatch,
    analysis_id: str,
    skip: int,
    limit: int,
) -> None:
    _patch(monkeypatch, _client())
    with pytest.raises(MCPError) as excinfo:
        _run(findings_priority(analysis_id, skip=skip, limit=limit))
    assert excinfo.value.code == INVALID_PARAMS


def test_findings_priority_unknown_analysis_is_an_mcp_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeGraphClient()
    client.connect()
    _patch(monkeypatch, client)
    with pytest.raises(MCPError) as excinfo:
        _run(findings_priority(ANALYSIS))
    assert excinfo.value.code == INVALID_PARAMS


# ---------------------------------------------------------------------------
# findings.detail
# ---------------------------------------------------------------------------

def test_findings_detail_returns_factors_and_plan(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _client())
    result = _run(findings_detail(ANALYSIS, FINDING_ID))

    finding = result["finding"]
    assert finding["finding_id"] == FINDING_ID
    assert finding["priority"]["score"] == 79.2
    assert finding["priority"]["severity"]["numeric_score"] == 9.8
    assert [factor["name"] for factor in finding["priority"]["factors"]] == [
        "severity",
        "reachability",
        "impact",
        "remediation",
    ]

    remediation = result["remediation"]
    assert remediation["package_name"] == "requests"
    assert remediation["candidates"][0]["proposed_version"] == "2.32.1"
    assert remediation["candidates"][0]["resolver_executed"] is False
    assert remediation["candidates"][0]["compatibility"] == "constraints_satisfied"
    assert result["limitations"] == ["reachability_traversal_bounded_at_5_hops"]


def test_findings_detail_validates_ids_and_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _client())

    for analysis_id, finding_id in (
        ("", FINDING_ID),
        ("   ", FINDING_ID),
        (ANALYSIS, ""),
        (ANALYSIS, "   "),
    ):
        with pytest.raises(MCPError) as excinfo:
            _run(findings_detail(analysis_id, finding_id))
        assert excinfo.value.code == INVALID_PARAMS

    with pytest.raises(MCPError) as excinfo:
        _run(findings_detail(ANALYSIS, "finding_missing"))
    assert excinfo.value.code == INVALID_PARAMS

    other_analysis_finding = stable_id(
        "finding", "analysis_other", PKG_REQUESTS, VULN_REQUESTS
    )
    with pytest.raises(MCPError):
        _run(findings_detail(ANALYSIS, other_analysis_finding))


# ---------------------------------------------------------------------------
# remediation.groups
# ---------------------------------------------------------------------------

def test_remediation_groups_returns_ranked_groups(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _client())
    result = _run(remediation_groups(ANALYSIS))

    assert result["count"] == 2
    assert result["total"] == 2
    assert [group["package_name"] for group in result["groups"]] == [
        "requests",
        "urllib3",
    ]
    first = result["groups"][0]
    assert first["group_id"] == GROUP_ID
    assert first["coverage"] == "confirmed_advisory"
    assert first["ranking"]["verified_resolved_count"] == 1
    assert first["ranking"]["verified_resolved_priority_sum"] == 79.2
    assert first["ranking"]["compatibility_tier_label"] == "constraints_satisfied"
    assert result["unresolved_findings"] == []
    assert result["unresolved_findings_truncated"] is False


def test_remediation_groups_paginates_and_validates(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _client())
    result = _run(remediation_groups(ANALYSIS, skip=1, limit=1))
    assert result["count"] == 1
    assert result["total"] == 2
    assert result["groups"][0]["package_name"] == "urllib3"

    for analysis_id, skip, limit in (
        ("", 0, 10),
        (ANALYSIS, -1, 10),
        (ANALYSIS, 0, 0),
        (ANALYSIS, 0, 101),
    ):
        with pytest.raises(MCPError) as excinfo:
            _run(remediation_groups(analysis_id, skip=skip, limit=limit))
        assert excinfo.value.code == INVALID_PARAMS


def test_remediation_groups_unknown_analysis_is_an_mcp_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    client = FakeGraphClient()
    client.connect()
    _patch(monkeypatch, client)
    with pytest.raises(MCPError) as excinfo:
        _run(remediation_groups(ANALYSIS))
    assert excinfo.value.code == INVALID_PARAMS


# ---------------------------------------------------------------------------
# remediation.group
# ---------------------------------------------------------------------------

def test_remediation_group_returns_evidence(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _client())
    result = _run(remediation_group(ANALYSIS, GROUP_ID))

    group = result["group"]
    assert group["group_id"] == GROUP_ID
    assert group["package_name"] == "requests"
    assert group["proposed_version"] == "2.32.1"
    assert group["candidates"][0]["selected"] is True
    assert group["constraint_checks"][0]["satisfied"] is True
    assert group["advisory_evidence"][0]["vulnerability_id"] == VULN_REQUESTS
    assert group["ranking"]["verified_resolved_count"] == 1
    assert result["limitations"] == ["reachability_traversal_bounded_at_5_hops"]


def test_remediation_group_validates_ids_and_scope(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    _patch(monkeypatch, _client())

    for analysis_id, group_id in (
        ("", GROUP_ID),
        (ANALYSIS, ""),
        (ANALYSIS, "   "),
    ):
        with pytest.raises(MCPError) as excinfo:
            _run(remediation_group(analysis_id, group_id))
        assert excinfo.value.code == INVALID_PARAMS

    with pytest.raises(MCPError) as excinfo:
        _run(remediation_group(ANALYSIS, "group_missing"))
    assert excinfo.value.code == INVALID_PARAMS

    other_analysis_group = stable_id(
        "fixgroup", "analysis_other", PKG_REQUESTS, "2.32.1"
    )
    with pytest.raises(MCPError):
        _run(remediation_group(ANALYSIS, other_analysis_group))
