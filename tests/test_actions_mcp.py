"""MCP tests for the Phase 6 preview-only tool.

``remediation.issue_preview`` is the only Phase 6 tool: it may *prepare* an
issue proposal but can never create one.  These tests call the tool function
directly with the ``_github_issue_service`` seam patched to the real service
over fake transports.
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest
from mcp import MCPError
from mcp.types import INVALID_PARAMS

from app.mcp.tools import remediation_issue_preview
from tests.actions_support import (
    ANALYSIS,
    FINDING_ID,
    GROUP_ID,
    build_bundle,
    make_action_settings,
)


def _run(coro: Any) -> Any:
    return asyncio.run(coro)


def _patch(monkeypatch: pytest.MonkeyPatch, bundle: Any) -> None:
    monkeypatch.setattr(
        "app.mcp.tools._github_issue_service", lambda: bundle.service
    )


def test_issue_preview_tool_returns_the_proposal(tmp_path: Path, monkeypatch) -> None:
    bundle = build_bundle(tmp_path)
    _patch(monkeypatch, bundle)
    result = _run(remediation_issue_preview(ANALYSIS, group_id=GROUP_ID))
    assert result["state"] == "PREVIEWED"
    assert result["action_id"].startswith("act_")
    assert result["payload_digest"].startswith("sha256:")
    assert result["template_version"] == "blastradius-issue-v1"
    assert result["title"].startswith("[BlastRadius] Upgrade requests")
    assert "### Verified findings" in result["body"]
    assert result["selection"] == {"group_id": GROUP_ID, "finding_id": None}
    assert any("No GitHub write has been performed" in note for note in result["notes"])
    # the tool never creates an issue and never searches: read-only preflight only
    assert [r.method for r in bundle.github.requests] == ["GET"]


def test_issue_preview_tool_accepts_a_finding_id(tmp_path: Path, monkeypatch) -> None:
    bundle = build_bundle(tmp_path)
    _patch(monkeypatch, bundle)
    result = _run(remediation_issue_preview(ANALYSIS, finding_id=FINDING_ID))
    assert result["selection"] == {"group_id": None, "finding_id": FINDING_ID}


def test_issue_preview_tool_requires_an_analysis_id(tmp_path: Path, monkeypatch) -> None:
    bundle = build_bundle(tmp_path)
    _patch(monkeypatch, bundle)
    with pytest.raises(MCPError) as excinfo:
        _run(remediation_issue_preview("   ", group_id=GROUP_ID))
    assert excinfo.value.code == INVALID_PARAMS


@pytest.mark.parametrize(
    "call",
    [
        {},
        {"group_id": GROUP_ID, "finding_id": FINDING_ID},
    ],
)
def test_issue_preview_tool_requires_exactly_one_selector(
    tmp_path: Path, monkeypatch, call: dict[str, str]
) -> None:
    bundle = build_bundle(tmp_path)
    _patch(monkeypatch, bundle)
    with pytest.raises(MCPError) as excinfo:
        _run(remediation_issue_preview(ANALYSIS, **call))
    assert excinfo.value.code == INVALID_PARAMS
    assert "exactly one" in excinfo.value.message


def test_issue_preview_tool_unknown_group_is_invalid_params(
    tmp_path: Path, monkeypatch
) -> None:
    bundle = build_bundle(tmp_path)
    _patch(monkeypatch, bundle)
    with pytest.raises(MCPError) as excinfo:
        _run(remediation_issue_preview(ANALYSIS, group_id="fixgroup_missing"))
    assert excinfo.value.code == INVALID_PARAMS


def test_issue_preview_tool_unknown_analysis_is_invalid_params(
    tmp_path: Path, monkeypatch
) -> None:
    from app.graph.queries import GET_ANALYSIS
    from tests.remediation_support import install, query_result
    from tests.support import FakeGraphClient, FakeQueryResult

    class _IdAwareGraphClient(FakeGraphClient):
        def query(self, cypher, *, params=None, timeout=None, read_only=False):  # type: ignore[override]
            if cypher == GET_ANALYSIS and (params or {}).get("analysis_id") != ANALYSIS:
                return FakeQueryResult([], [])
            return super().query(cypher, params=params, timeout=timeout, read_only=read_only)

    client = _IdAwareGraphClient()
    install(client)
    from app.graph.queries import GET_REPOSITORY
    from tests.actions_support import repository_row

    client.canned[GET_REPOSITORY] = query_result([repository_row()])
    bundle = build_bundle(tmp_path, graph_client=client)
    _patch(monkeypatch, bundle)
    with pytest.raises(MCPError) as excinfo:
        _run(remediation_issue_preview("analysis_missing", group_id=GROUP_ID))
    assert excinfo.value.code == INVALID_PARAMS


def test_issue_preview_tool_reports_disabled_writes_with_a_code(
    tmp_path: Path, monkeypatch
) -> None:
    settings = make_action_settings(tmp_path, enabled=False)
    bundle = build_bundle(tmp_path, settings=settings)
    _patch(monkeypatch, bundle)
    with pytest.raises(MCPError) as excinfo:
        _run(remediation_issue_preview(ANALYSIS, group_id=GROUP_ID))
    assert excinfo.value.code == -32603  # INTERNAL_ERROR: a deployment condition
    assert excinfo.value.data["code"] == "github_write_disabled"
    assert bundle.github.requests == []


def test_issue_preview_tool_never_posts_or_searches(tmp_path: Path, monkeypatch) -> None:
    bundle = build_bundle(tmp_path)
    _patch(monkeypatch, bundle)
    _run(remediation_issue_preview(ANALYSIS, group_id=GROUP_ID))
    _run(remediation_issue_preview(ANALYSIS, finding_id=FINDING_ID))
    assert bundle.github.posts == []
    assert all(r.url.path != "/search/issues" for r in bundle.github.requests)
