"""Shared deterministic fixtures for the Phase 5 remediation test suite.

Builds canned ``FakeGraphClient`` results for the queries
:class:`~app.remediation.service.RemediationService` issues, so the full
orchestration (findings -> priorities -> candidates -> groups) is exercised
against the real service code with zero network and zero FalkorDB.
"""

from __future__ import annotations

import json
from typing import Any

from app.graph.queries import (
    GET_ANALYSIS,
    GET_DECLARATIONS,
    GET_EDGES,
    GET_PACKAGES,
    GET_STATISTICS,
    GET_VULNERABILITIES,
    dependency_impact_summary_template,
    modeled_entry_paths_template,
)
from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.remediation.models import FindingInput
from app.remediation.service import TRAVERSAL_DEPTH, RemediationService
from tests.support import FakeGraphClient, FakeQueryResult

ANALYSIS = "analysis_p5_1"
REPO = "github.com/example/priority-demo"
COMMIT = "c" * 40
PKG_REQUESTS = "pkg_requests_2320"
PKG_URLLIB3 = "pkg_urllib3_200"
VULN_REQUESTS = "GHSA-1234-5678-9012"
VULN_URLLIB3 = "GHSA-aaaa-bbbb-cccc"


# ---------------------------------------------------------------------------
# domain row builders (shapes mirror the graph queries)
# ---------------------------------------------------------------------------

def ecosystem_range(
    introduced: str,
    *,
    fixed: str | None = None,
    last_affected: str | None = None,
    limit: str | None = None,
) -> dict[str, Any]:
    return {
        "type": "ECOSYSTEM",
        "repo": None,
        "events": [
            {
                "introduced": introduced,
                "fixed": fixed,
                "last_affected": last_affected,
                "limit": limit,
            }
        ],
    }


def ranges_json(*ranges: dict[str, Any]) -> str:
    return json.dumps(list(ranges))


def analysis_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": ANALYSIS,
        "repository_id": REPO,
        "commit_sha": COMMIT,
        "status": "success",
        "warning_count": 0,
        "error_count": 0,
        "resolved_packages": 2,
        "unknown_relation_packages": 0,
        "conflicting_packages": 0,
        "unsupported_formats": 0,
    }
    row.update(overrides)
    return row


def stats_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "repositories": 1,
        "files": 4,
        "manifests": 2,
        "declarations": 2,
        "packages": 2,
        "dependency_edges": 2,
        "resolved_packages": 2,
        "vulnerability_edges": 2,
    }
    row.update(overrides)
    return row


def package_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": PKG_REQUESTS,
        "normalized_name": "requests",
        "version": "2.32.0",
        "ecosystem": "pypi",
        "relation": "direct",
        "is_dev": False,
        "is_optional": False,
        "is_root_project": False,
        "groups": [],
        "marker": None,
        "source_manifest": "poetry.lock",
    }
    row.update(overrides)
    return row


def urllib3_package_row(**overrides: Any) -> dict[str, Any]:
    row = package_row(
        id=PKG_URLLIB3,
        normalized_name="urllib3",
        version="2.0.0",
        relation="transitive",
        source_manifest="poetry.lock",
    )
    row.update(overrides)
    return row


def declaration_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "id": "decl_requests",
        "normalized_name": "requests",
        "version_constraint": ">=2.32,<3",
        "constraint_scheme": "pep440",
        "is_exact_pin": False,
        "resolved_version": "2.32.0",
        "manifest_path": "pyproject.toml",
        "line_number": 12,
        "scope": "runtime",
        "evidence": "declared in [project.dependencies]",
    }
    row.update(overrides)
    return row


def edge_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "from_id": "pkg_demo_app",
        "from_name": "demo-app",
        "from_version": "0.1.0",
        "to_id": PKG_REQUESTS,
        "to_name": "requests",
        "to_version": "2.32.0",
        "constraint": ">=2.32,<3",
        "to_resolved_version": "2.32.0",
        "marker": None,
        "extras": None,
        "optional": False,
        "dev": False,
        "source_manifest": "poetry.lock",
    }
    row.update(overrides)
    return row


def finding_row(**overrides: Any) -> dict[str, Any]:
    row: dict[str, Any] = {
        "package_id": PKG_REQUESTS,
        "package_name": "requests",
        "package_version": "2.32.0",
        "ecosystem": "pypi",
        "package_relation": "direct",
        "is_dev": False,
        "is_optional": False,
        "is_root_project": False,
        "groups": [],
        "package_marker": None,
        "source_manifest": "poetry.lock",
        "vulnerability_id": VULN_REQUESTS,
        "summary": "Demo advisory for requests",
        "aliases": ["CVE-2026-0001"],
        "severities": ["CVSS_V3 9.8"],
        "references": ["ADVISORY https://example.test/advisory/1"],
        "withdrawn": None,
        "published": "2026-01-01T00:00:00Z",
        "modified": "2026-02-01T00:00:00Z",
        "fixed_versions": ["2.32.1"],
        "ranges_json": ranges_json(ecosystem_range("0", fixed="2.32.1")),
        "osv_modified": "2026-02-01T00:00:00Z",
        "match_type": "version",
        "repository_id": REPO,
        "commit_sha": COMMIT,
        "last_synced_at": "2026-02-02T00:00:00+00:00",
    }
    row.update(overrides)
    return row


def urllib3_finding_row(**overrides: Any) -> dict[str, Any]:
    row = finding_row(
        package_id=PKG_URLLIB3,
        package_name="urllib3",
        package_version="2.0.0",
        package_relation="transitive",
        vulnerability_id=VULN_URLLIB3,
        summary="Demo advisory for urllib3",
        aliases=["CVE-2026-0002"],
        severities=["CVSS_V3 6.5"],
        fixed_versions=["2.0.7"],
        ranges_json=ranges_json(ecosystem_range("0", fixed="2.0.7")),
        references=["ADVISORY https://example.test/advisory/2"],
    )
    row.update(overrides)
    return row


def query_result(rows: list[dict[str, Any]]) -> FakeQueryResult:
    """Turn uniform row dicts into a positionally-correct query result."""
    if not rows:
        return FakeQueryResult([], [])
    columns = list(rows[0].keys())
    return FakeQueryResult(columns, [[row.get(column) for column in columns] for row in rows])


# ---------------------------------------------------------------------------
# canned installation + service factory
# ---------------------------------------------------------------------------

def install(
    client: FakeGraphClient,
    *,
    analysis: dict[str, Any] | None = None,
    stats: dict[str, Any] | None = None,
    packages: list[dict[str, Any]] | None = None,
    declarations: list[dict[str, Any]] | None = None,
    edges: list[dict[str, Any]] | None = None,
    findings: list[dict[str, Any]] | None = None,
    entry_rows: list[dict[str, Any]] | None = None,
    impact_rows: list[dict[str, Any]] | None = None,
) -> FakeGraphClient:
    """Can every query the remediation service issues for one analysis."""
    client.connect()
    packages = packages if packages is not None else [package_row(), urllib3_package_row()]
    declarations = declarations if declarations is not None else [declaration_row()]
    edges = edges if edges is not None else [edge_row()]
    findings = findings if findings is not None else [finding_row(), urllib3_finding_row()]
    entry_rows = entry_rows if entry_rows is not None else []
    impact_rows = impact_rows if impact_rows is not None else []

    effective_stats = stats_row(
        declarations=len(declarations),
        packages=len(packages),
        resolved_packages=len(packages),
        dependency_edges=len(edges),
        vulnerability_edges=len(findings),
    )
    effective_stats.update(stats or {})

    client.canned[GET_ANALYSIS] = query_result([analysis or analysis_row()])
    client.canned[GET_STATISTICS] = query_result([effective_stats])
    client.canned[GET_PACKAGES] = query_result(packages)
    client.canned[GET_DECLARATIONS] = query_result(declarations)
    client.canned[GET_EDGES] = query_result(edges)
    client.canned[GET_VULNERABILITIES] = query_result(findings)
    client.canned[modeled_entry_paths_template(TRAVERSAL_DEPTH)] = query_result(entry_rows)
    client.canned[dependency_impact_summary_template(TRAVERSAL_DEPTH)] = query_result(impact_rows)
    return client


def make_service(client: FakeGraphClient) -> RemediationService:
    graph_service = GraphService(client)
    vuln_service = VulnerabilityGraphService(client, graph_service)
    return RemediationService(graph_service, vuln_service)


def one_package_service(client: FakeGraphClient) -> RemediationService:
    """A single direct package (requests) with one confirmable finding."""
    install(client, packages=[package_row()], edges=[], findings=[finding_row()])
    return make_service(client)


def make_input(**overrides: Any) -> FindingInput:
    """A FindingInput with sensible defaults, for priority unit tests."""
    values: dict[str, Any] = {
        "finding_id": "finding_test_1",
        "vulnerability_id": VULN_REQUESTS,
        "severities": ("CVSS_V3 9.8",),
        "package_id": PKG_REQUESTS,
        "package_name": "requests",
        "package_version": "2.32.0",
        "ecosystem": "pypi",
        "dependency_role": "direct",
        "fixed_versions": ("2.32.1",),
    }
    values.update(overrides)
    return FindingInput(**values)


__all__ = [
    "ANALYSIS",
    "COMMIT",
    "PKG_REQUESTS",
    "PKG_URLLIB3",
    "REPO",
    "VULN_REQUESTS",
    "VULN_URLLIB3",
    "analysis_row",
    "declaration_row",
    "ecosystem_range",
    "edge_row",
    "finding_row",
    "install",
    "make_input",
    "make_service",
    "one_package_service",
    "package_row",
    "query_result",
    "ranges_json",
    "stats_row",
    "urllib3_finding_row",
    "urllib3_package_row",
]
