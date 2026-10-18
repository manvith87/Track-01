"""MCP tool implementations for BlastRadius Phase 4A.

Every tool is read-only and wraps an existing service method:

* :class:`~app.graph.service.GraphService` — graph reads (health, analysis
  status/statistics/packages/dependency-edges, package neighbourhood).
* :class:`~app.graph.vulnerability.VulnerabilityGraphService` — vulnerability
  reads (analysis vulnerabilities, impact paths, vulnerability detail,
  vulnerability components).
* :class:`~app.osv.service.OsvService` — read-only OSV lookup (no ingestion).

No graph-write, OSV-sync, or arbitrary-Cypher capability is exposed.
"""

from __future__ import annotations

from typing import Any

from mcp.types import INVALID_PARAMS, INTERNAL_ERROR
from mcp import MCPError
from pydantic import ValidationError

from app.actions.models import IssuePreviewRequest
from app.actions.service import GitHubIssueService
from app.api.deps import get_action_settings, get_action_store, get_osv_service
from app.core.errors import BlastRadiusError, InputValidationError
from app.github.issue_client import GitHubIssueClient
from app.graph.client import GraphClient
from app.graph.config import get_graph_settings
from app.graph.errors import GraphError, GraphRecordNotFoundError
from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.osv.errors import OsvError
from app.remediation.service import RemediationService

from app.mcp.server import mcp


# ---------------------------------------------------------------------------
# service helpers
# ---------------------------------------------------------------------------

def _graph_services() -> tuple[GraphService, VulnerabilityGraphService]:
    """Build a graph client and both graph services sharing one client.

    The FalkorDB client connects lazily on first query, so no explicit
    ``connect()`` is needed here.  The caller is responsible for closing the
    client (see :func:`_with_graph_services`).
    """
    client = GraphClient(get_graph_settings())
    graph_service = GraphService(client)
    vuln_service = VulnerabilityGraphService(client, graph_service)
    return graph_service, vuln_service


# ---------------------------------------------------------------------------
# error conversion
# ---------------------------------------------------------------------------

def _to_mcp_error(exc: Exception, operation: str) -> MCPError:
    """Convert a service-layer exception into a structured :class:`MCPError`."""
    if isinstance(exc, InputValidationError):
        return MCPError(INVALID_PARAMS, exc.message)
    if isinstance(exc, GraphRecordNotFoundError):
        return MCPError(INVALID_PARAMS, exc.message)
    if isinstance(exc, GraphError):
        return MCPError(INTERNAL_ERROR, exc.message)
    if isinstance(exc, OsvError):
        return MCPError(
            INTERNAL_ERROR,
            exc.message,
            data={"operation": operation, "retryable": exc.retryable},
        )
    if isinstance(exc, BlastRadiusError):
        return MCPError(
            INTERNAL_ERROR,
            exc.message,
            data={"operation": operation, "code": exc.code.value, "retryable": exc.retryable},
        )
    return MCPError(INTERNAL_ERROR, str(exc) or exc.__class__.__name__)


# ---------------------------------------------------------------------------
# tools
# ---------------------------------------------------------------------------

@mcp.tool(name="graph.health")
async def graph_health() -> dict[str, Any]:
    """Report whether the configured FalkorDB graph is reachable.

    Never raises: when the graph is unreachable it returns
    ``connected: false`` with an error message instead.

    The probe uses the same injected graph services as every other tool, so
    the reported graph and connection always match the graph the other tools
    would actually read.  The shared client is left open for its owner (the
    transport layer) to manage, exactly like every other tool.
    """
    graph_service, _vuln_service = _graph_services()
    client = graph_service.client
    settings = client.settings
    try:
        connected = client.ping()
    except Exception as exc:  # noqa: BLE001 - the probe must never fail
        connected = False
        return {
            "connected": False,
            "graph_name": settings.graph_name,
            "connection": settings.connection_label,
            "error": str(exc) or exc.__class__.__name__,
        }
    return {
        "connected": connected,
        "graph_name": settings.graph_name,
        "connection": settings.connection_label,
        "error": None,
    }


@mcp.tool(name="analysis.status")
async def analysis_status(analysis_id: str) -> dict[str, Any]:
    """Return graph ingestion status and incomplete-data indicators for one analysis.

    Args:
        analysis_id: Stable analysis id (``stable_id("analysis",
            canonical_id, commit_sha)``).
    """
    if not analysis_id or not analysis_id.strip():
        raise MCPError(INVALID_PARAMS, "analysis_id must not be empty")
    analysis_id = analysis_id.strip()
    graph_service, _vuln_service = _graph_services()
    try:
        return graph_service.get_analysis_graph_status(analysis_id)
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "analysis.status") from exc


@mcp.tool(name="analysis.statistics")
async def analysis_statistics(analysis_id: str) -> dict[str, Any]:
    """Return actual node/relationship counts for one analysis.

    Args:
        analysis_id: Stable analysis id.
    """
    if not analysis_id or not analysis_id.strip():
        raise MCPError(INVALID_PARAMS, "analysis_id must not be empty")
    analysis_id = analysis_id.strip()
    graph_service, _vuln_service = _graph_services()
    try:
        return graph_service.get_graph_statistics(analysis_id)
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "analysis.statistics") from exc


@mcp.tool(name="analysis.packages")
async def analysis_packages(
    analysis_id: str,
    skip: int = 0,
    limit: int = 200,
) -> dict[str, Any]:
    """Return package declarations and known resolved versions for one analysis.

    Args:
        analysis_id: Stable analysis id.
        skip: Number of records to skip (ge 0).
        limit: Maximum records to return (1..1000).
    """
    if not analysis_id or not analysis_id.strip():
        raise MCPError(INVALID_PARAMS, "analysis_id must not be empty")
    if skip < 0:
        raise MCPError(INVALID_PARAMS, "skip must be >= 0")
    if limit < 1 or limit > 1000:
        raise MCPError(INVALID_PARAMS, "limit must be between 1 and 1000")
    analysis_id = analysis_id.strip()
    graph_service, _vuln_service = _graph_services()
    try:
        return graph_service.get_repository_packages(
            analysis_id, skip=skip, limit=limit
        )
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "analysis.packages") from exc


@mcp.tool(name="analysis.dependency_edges")
async def analysis_dependency_edges(
    analysis_id: str,
    skip: int = 0,
    limit: int = 200,
) -> dict[str, Any]:
    """Return lockfile-derived dependency edges for one analysis.

    Args:
        analysis_id: Stable analysis id.
        skip: Number of records to skip (ge 0).
        limit: Maximum records to return (1..1000).
    """
    if not analysis_id or not analysis_id.strip():
        raise MCPError(INVALID_PARAMS, "analysis_id must not be empty")
    if skip < 0:
        raise MCPError(INVALID_PARAMS, "skip must be >= 0")
    if limit < 1 or limit > 1000:
        raise MCPError(INVALID_PARAMS, "limit must be between 1 and 1000")
    analysis_id = analysis_id.strip()
    graph_service, _vuln_service = _graph_services()
    try:
        return graph_service.get_dependency_edges(
            analysis_id, skip=skip, limit=limit
        )
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "analysis.dependency_edges") from exc


@mcp.tool(name="package.neighborhood")
async def package_neighborhood(
    package_id: str,
    depth: int = 1,
) -> dict[str, Any]:
    """Return a bounded DEPENDS_ON neighbourhood of a package.

    Args:
        package_id: Stable package id
            (``stable_id("pkg", canonical_id, commit_sha, normalized_name,
            version)``).
        depth: Maximum traversal depth (1..5).
    """
    if not package_id or not package_id.strip():
        raise MCPError(INVALID_PARAMS, "package_id must not be empty")
    if depth < 1 or depth > 5:
        raise MCPError(INVALID_PARAMS, "depth must be between 1 and 5")
    package_id = package_id.strip()
    graph_service, _vuln_service = _graph_services()
    try:
        return graph_service.get_dependency_neighborhood(package_id, depth=depth)
    except GraphError as exc:
        raise _to_mcp_error(exc, "package.neighborhood") from exc


@mcp.tool(name="analysis.vulnerabilities")
async def analysis_vulnerabilities(
    analysis_id: str,
    skip: int = 0,
    limit: int = 200,
) -> dict[str, Any]:
    """Return vulnerabilities confirmed for an analysis's resolved packages.

    Args:
        analysis_id: Stable analysis id.
        skip: Number of records to skip (ge 0).
        limit: Maximum records to return (1..1000).
    """
    if not analysis_id or not analysis_id.strip():
        raise MCPError(INVALID_PARAMS, "analysis_id must not be empty")
    if skip < 0:
        raise MCPError(INVALID_PARAMS, "skip must be >= 0")
    if limit < 1 or limit > 1000:
        raise MCPError(INVALID_PARAMS, "limit must be between 1 and 1000")
    analysis_id = analysis_id.strip()
    _graph_service, vuln_service = _graph_services()
    try:
        return vuln_service.get_analysis_vulnerabilities(
            analysis_id, skip=skip, limit=limit
        )
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "analysis.vulnerabilities") from exc


@mcp.tool(name="analysis.blast_radius")
async def analysis_blast_radius(
    analysis_id: str,
    vulnerability_id: str | None = None,
    depth: int = 3,
    skip: int = 0,
    limit: int = 200,
) -> dict[str, Any]:
    """Return explainable impact chains from affected packages to dependents.

    ``hop_count == 0`` rows are the affected packages themselves;
    ``hop_count >= 1`` rows depend on them through :DEPENDS_ON chains.

    Args:
        analysis_id: Stable analysis id.
        vulnerability_id: Restrict paths to one vulnerability id (optional).
        depth: Maximum DEPENDS_ON hops (0..5).
        skip: Number of paths to skip (ge 0).
        limit: Maximum paths to return (1..1000).
    """
    if not analysis_id or not analysis_id.strip():
        raise MCPError(INVALID_PARAMS, "analysis_id must not be empty")
    if depth < 0 or depth > 5:
        raise MCPError(INVALID_PARAMS, "depth must be between 0 and 5")
    if skip < 0:
        raise MCPError(INVALID_PARAMS, "skip must be >= 0")
    if limit < 1 or limit > 1000:
        raise MCPError(INVALID_PARAMS, "limit must be between 1 and 1000")
    if vulnerability_id is not None and not vulnerability_id.strip():
        raise MCPError(INVALID_PARAMS, "vulnerability_id must not be empty")
    analysis_id = analysis_id.strip()
    vulnerability_id = vulnerability_id.strip() if vulnerability_id else None
    _graph_service, vuln_service = _graph_services()
    try:
        return vuln_service.get_impact_paths(
            analysis_id,
            vulnerability_id=vulnerability_id,
            depth=depth,
            skip=skip,
            limit=limit,
        )
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "analysis.blast_radius") from exc


@mcp.tool(name="vulnerability.get")
async def vulnerability_get(vulnerability_id: str) -> dict[str, Any]:
    """Return one stored OSV vulnerability record exactly as mirrored.

    Cross-repository by design: returns the shared OSV record regardless of
    which analysis recorded it.

    Args:
        vulnerability_id: OSV record id (e.g. GHSA-..., CVE-..., PYSEC-...).
    """
    if not vulnerability_id or not vulnerability_id.strip():
        raise MCPError(INVALID_PARAMS, "vulnerability_id must not be empty")
    vulnerability_id = vulnerability_id.strip()
    _graph_service, vuln_service = _graph_services()
    try:
        return vuln_service.get_vulnerability(vulnerability_id)
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "vulnerability.get") from exc


@mcp.tool(name="vulnerability.components")
async def vulnerability_components(
    vulnerability_id: str,
    skip: int = 0,
    limit: int = 200,
) -> dict[str, Any]:
    """Return graph components (packages) affected by one vulnerability.

    Cross-repository by design: every row carries its own
    ``repository_id``/``commit_sha`` so callers can filter per analysis.
    Returns an empty list when no components are linked (does not raise).

    Args:
        vulnerability_id: OSV record id.
        skip: Number of components to skip (ge 0).
        limit: Maximum components to return (1..1000).
    """
    if not vulnerability_id or not vulnerability_id.strip():
        raise MCPError(INVALID_PARAMS, "vulnerability_id must not be empty")
    if skip < 0:
        raise MCPError(INVALID_PARAMS, "skip must be >= 0")
    if limit < 1 or limit > 1000:
        raise MCPError(INVALID_PARAMS, "limit must be between 1 and 1000")
    vulnerability_id = vulnerability_id.strip()
    _graph_service, vuln_service = _graph_services()
    try:
        return vuln_service.get_vulnerability_components(
            vulnerability_id, skip=skip, limit=limit
        )
    except GraphError as exc:
        raise _to_mcp_error(exc, "vulnerability.components") from exc


@mcp.tool(name="osv.lookup")
async def osv_lookup(
    name: str,
    ecosystem: str = "pypi",
    version: str | None = None,
) -> dict[str, Any]:
    """Live read-only OSV.dev lookup for one package (no graph writes).

    Without ``version`` the results are name-level matches
    (``match_type="name"``, ``confirmed=false``) and are informational only.

    Args:
        name: Package name (PyPI spelling, 1..200 characters).
        ecosystem: Package ecosystem (currently only "pypi" is supported).
        version: Exact resolved version (1..100 characters, optional).
    """
    if not name or not name.strip():
        raise MCPError(INVALID_PARAMS, "name must not be empty")
    if len(name) > 200:
        raise MCPError(INVALID_PARAMS, "name must not exceed 200 characters")
    if not ecosystem or not ecosystem.strip():
        raise MCPError(INVALID_PARAMS, "ecosystem must not be empty")
    if len(ecosystem) > 100:
        raise MCPError(INVALID_PARAMS, "ecosystem must not exceed 100 characters")
    if version is not None:
        version = version.strip()
        if not version:
            raise MCPError(INVALID_PARAMS, "version must not be empty")
        if len(version) > 100:
            raise MCPError(INVALID_PARAMS, "version must not exceed 100 characters")

    name = name.strip()
    ecosystem = ecosystem.strip()

    osv_service = get_osv_service()
    try:
        result = osv_service.lookup(ecosystem, name, version)
    except InputValidationError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except OsvError as exc:
        raise _to_mcp_error(exc, "osv.lookup") from exc

    return {
        "ecosystem": result.ecosystem,
        "upstream_ecosystem": result.upstream_ecosystem,
        "package_name": result.package_name,
        "version": result.version,
        "match_type": result.match_type,
        "confirmed": result.confirmed(),
        "count": result.count,
        "vulnerabilities": [v.model_dump() for v in result.vulnerabilities],
        "errors": list(result.errors),
    }


# ---------------------------------------------------------------------------
# Phase 5: deterministic prioritization / remediation (read-only)
# ---------------------------------------------------------------------------

def _remediation_service() -> RemediationService:
    """Build the deterministic Phase 5 service on the shared graph services."""
    graph_service, vuln_service = _graph_services()
    return RemediationService(graph_service, vuln_service)


@mcp.tool(name="findings.priority")
async def findings_priority(
    analysis_id: str,
    skip: int = 0,
    limit: int = 25,
) -> dict[str, Any]:
    """Return version-confirmed findings ranked by the deterministic priority formula.

    The score is BlastRadius's custom, documented score — it is never a CVSS
    score. Advisory severity, reachability, impact and remediation
    availability are exposed as separate factor fields together with the raw
    facts behind them.

    Args:
        analysis_id: Stable analysis id.
        skip: Ranked findings to skip (ge 0).
        limit: Maximum findings to return (1..100).
    """
    if not analysis_id or not analysis_id.strip():
        raise MCPError(INVALID_PARAMS, "analysis_id must not be empty")
    if skip < 0:
        raise MCPError(INVALID_PARAMS, "skip must be >= 0")
    if limit < 1 or limit > 100:
        raise MCPError(INVALID_PARAMS, "limit must be between 1 and 100")
    analysis_id = analysis_id.strip()
    service = _remediation_service()
    try:
        report = service.analyze(analysis_id)
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "findings.priority") from exc
    page = report.findings[skip : skip + limit]
    return {
        "analysis_id": report.analysis_id,
        "repository_id": report.repository_id,
        "commit_sha": report.commit_sha,
        "count": len(page),
        "total": len(report.findings),
        "skip": skip,
        "limit": limit,
        "analysis_context": report.context.model_dump(),
        "findings": [finding.model_dump() for finding in page],
        "limitations": report.limitations,
    }


@mcp.tool(name="findings.detail")
async def findings_detail(analysis_id: str, finding_id: str) -> dict[str, Any]:
    """Return one finding's full risk explanation and its package remediation plan.

    Use this to answer "why did this finding get its priority": every factor
    contribution, the advisory severity evidence, the modeled entry points and
    dependent components are field-level data, not prose.

    Args:
        analysis_id: Stable analysis id.
        finding_id: Finding id returned by ``findings.priority``.
    """
    if not analysis_id or not analysis_id.strip():
        raise MCPError(INVALID_PARAMS, "analysis_id must not be empty")
    if not finding_id or not finding_id.strip():
        raise MCPError(INVALID_PARAMS, "finding_id must not be empty")
    analysis_id = analysis_id.strip()
    finding_id = finding_id.strip()
    service = _remediation_service()
    try:
        finding, plan, limitations = service.find_finding(analysis_id, finding_id)
    except InputValidationError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "findings.detail") from exc
    return {
        "finding": finding.model_dump(),
        "remediation": plan.model_dump() if plan is not None else None,
        "limitations": limitations,
    }


@mcp.tool(name="remediation.groups")
async def remediation_groups(
    analysis_id: str,
    skip: int = 0,
    limit: int = 10,
) -> dict[str, Any]:
    """Return ranked fix groups (dependency changes that resolve findings).

    Ranking counts only advisory-range-validated resolutions; compatibility
    status comes from recorded constraints (no resolver is executed). Findings
    no candidate can verifiably resolve are listed separately with reasons.

    Args:
        analysis_id: Stable analysis id.
        skip: Ranked groups to skip (ge 0).
        limit: Maximum groups to return (1..100).
    """
    if not analysis_id or not analysis_id.strip():
        raise MCPError(INVALID_PARAMS, "analysis_id must not be empty")
    if skip < 0:
        raise MCPError(INVALID_PARAMS, "skip must be >= 0")
    if limit < 1 or limit > 100:
        raise MCPError(INVALID_PARAMS, "limit must be between 1 and 100")
    analysis_id = analysis_id.strip()
    service = _remediation_service()
    try:
        report = service.analyze(analysis_id)
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "remediation.groups") from exc
    page = report.groups[skip : skip + limit]
    unresolved = report.unresolved_findings
    truncated = len(unresolved) > 100
    return {
        "analysis_id": report.analysis_id,
        "repository_id": report.repository_id,
        "commit_sha": report.commit_sha,
        "count": len(page),
        "total": len(report.groups),
        "skip": skip,
        "limit": limit,
        "analysis_context": report.context.model_dump(),
        "groups": [group.model_dump() for group in page],
        "unresolved_findings": [item.model_dump() for item in unresolved[:100]],
        "unresolved_findings_truncated": truncated,
        "limitations": report.limitations,
    }


@mcp.tool(name="remediation.group")
async def remediation_group(analysis_id: str, group_id: str) -> dict[str, Any]:
    """Return one fix group with its evidence and compatibility checks.

    Args:
        analysis_id: Stable analysis id.
        group_id: Fix-group id returned by ``remediation.groups``.
    """
    if not analysis_id or not analysis_id.strip():
        raise MCPError(INVALID_PARAMS, "analysis_id must not be empty")
    if not group_id or not group_id.strip():
        raise MCPError(INVALID_PARAMS, "group_id must not be empty")
    analysis_id = analysis_id.strip()
    group_id = group_id.strip()
    service = _remediation_service()
    try:
        group, limitations = service.find_group(analysis_id, group_id)
    except InputValidationError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "remediation.group") from exc
    return {"group": group.model_dump(), "limitations": limitations}


# ---------------------------------------------------------------------------
# Phase 6: approved GitHub issue preview (read-only; never writes to GitHub)
# ---------------------------------------------------------------------------

def _github_issue_service() -> GitHubIssueService:
    """Build the Phase 6 preview service on the shared graph services.

    The service enforces the configuration gates itself (writes disabled by
    default, dedicated token, confirmation secret) and only ever creates a
    *preview* here; the write happens exclusively through the authorized
    confirmation endpoint.
    """
    graph_service, vuln_service = _graph_services()
    settings = get_action_settings()
    return GitHubIssueService(
        remediation=RemediationService(graph_service, vuln_service),
        graph=graph_service,
        github=GitHubIssueClient(settings),
        store=get_action_store(),
        settings=settings,
    )


@mcp.tool(name="remediation.issue_preview")
async def remediation_issue_preview(
    analysis_id: str,
    group_id: str | None = None,
    finding_id: str | None = None,
) -> dict[str, Any]:
    """Prepare — but never create — a GitHub issue preview for a fix group or finding.

    This tool performs **no GitHub write**. It builds the exact title and body
    that an explicitly approved confirmation would create, together with the
    server-issued ``action_id``, the ``payload_digest`` and the expiry. Issue
    creation requires the user to confirm that action through BlastRadius's
    secret-protected confirmation step; an assistant must never claim the issue
    was created, must not invent or alter the ``action_id`` / ``payload_digest``,
    and cannot authorize the write by itself. Only server-issued identifiers are
    accepted: the repository, versions and evidence come from the analysis.

    Args:
        analysis_id: Stable analysis id.
        group_id: Fix-group id returned by ``remediation.groups`` (exactly one
            of group_id/finding_id is required).
        finding_id: Finding id returned by ``findings.priority`` (exactly one
            of group_id/finding_id is required).
    """
    if not analysis_id or not analysis_id.strip():
        raise MCPError(INVALID_PARAMS, "analysis_id must not be empty")
    try:
        request = IssuePreviewRequest(
            group_id=(group_id or None),
            finding_id=(finding_id or None),
        )
    except ValidationError as exc:
        raise MCPError(INVALID_PARAMS, "Provide exactly one of group_id or finding_id") from exc
    service = _github_issue_service()
    try:
        preview = service.preview(analysis_id.strip(), request)
    except InputValidationError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphRecordNotFoundError as exc:
        raise MCPError(INVALID_PARAMS, exc.message) from exc
    except GraphError as exc:
        raise _to_mcp_error(exc, "remediation.issue_preview") from exc
    except BlastRadiusError as exc:
        raise _to_mcp_error(exc, "remediation.issue_preview") from exc
    return preview.model_dump(mode="json")


__all__ = [
    "graph_health",
    "analysis_status",
    "analysis_statistics",
    "analysis_packages",
    "analysis_dependency_edges",
    "package_neighborhood",
    "analysis_vulnerabilities",
    "analysis_blast_radius",
    "vulnerability_get",
    "vulnerability_components",
    "osv_lookup",
    "findings_priority",
    "findings_detail",
    "remediation_groups",
    "remediation_group",
    "remediation_issue_preview",
]
