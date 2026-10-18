"""Vulnerability intelligence API endpoints for BlastRadius Phase 3.

The endpoints follow the Phase 2 graph conventions: failures use the shared
error envelope, missing records are ``404`` and upstream/transport failures
are typed :class:`~app.osv.errors.OsvError` subclasses handled globally.

Routes are mounted under ``/api/v1`` by the version-one router:

* ``GET  /api/v1/osv/vulnerabilities`` - live OSV lookup (read-only)
* ``POST /api/v1/analyses/{analysis_id}/vulnerabilities`` - targeted OSV ingestion
* ``GET  /api/v1/analyses/{analysis_id}/vulnerabilities`` - graph view (affected packages)
* ``GET  /api/v1/analyses/{analysis_id}/vulnerabilities/blast-radius`` - impact paths
* ``GET  /api/v1/vulnerabilities/{vulnerability_id}`` - stored record + components

Name-only lookups are explicitly reported as ``match_type="name"`` and never
become vulnerability claims; scope (repository/commit) travels with every
stored edge through the originating ``:Package`` node.
"""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, Path, Query

from app.api.deps import (
    get_graph_service,
    get_osv_service,
    get_vulnerability_service,
)
from app.api.v1.vulnerability_schemas import (
    AnalysisVulnerabilitiesResponse,
    AnalysisVulnerabilityItem,
    ImpactPathOut,
    OsvLookupResponse,
    VulnerabilityBlastRadiusResponse,
    VulnerabilityComponentOut,
    VulnerabilityDetailResponse,
    VulnerabilityIngestError,
    VulnerabilityIngestResponse,
    match_to_edge_payload,
)
from app.core.errors import InputValidationError
from app.core.logging import get_logger, safe_text
from app.graph.errors import GraphRecordNotFoundError
from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.osv.service import OsvPackageItem, OsvService

_log = get_logger("api.vulnerabilities")

router = APIRouter(tags=["vulnerabilities"])


def _string_list(value: Any) -> list[str]:
    if isinstance(value, (list, tuple)):
        return [str(item) for item in value if item is not None]
    if isinstance(value, str) and value:
        return [value]
    return []


def _parse_severities(value: Any) -> list[dict[str, str]]:
    """Rebuild ``{type, score}`` entries from the stored ``TYPE score`` strings."""
    parsed: list[dict[str, str]] = []
    for item in _string_list(value):
        parts = item.split(" ", 1)
        entry = {"type": parts[0]} if len(parts) == 1 else {"type": parts[0], "score": parts[1]}
        parsed.append(entry)
    return parsed


# ---------------------------------------------------------------------------
# Live OSV lookup (read-only, no graph writes)
# ---------------------------------------------------------------------------

@router.get(
    "/osv/vulnerabilities",
    response_model=OsvLookupResponse,
    summary="Look up vulnerabilities for one package (live OSV, no graph writes)",
)
def lookup_vulnerabilities_endpoint(
    name: str = Query(..., min_length=1, max_length=200, description="Package name (PyPI spelling)."),
    ecosystem: str = Query(default="pypi", description="Package ecosystem (e.g. 'pypi')."),
    version: str | None = Query(
        default=None, min_length=1, max_length=100,
        description="Exact resolved version; omitted means a name-level (unconfirmed) lookup.",
    ),
    osv: OsvService = Depends(get_osv_service),
) -> OsvLookupResponse:
    """Query the OSV.dev database for one package, by ecosystem/name/version.

    Without ``version`` the results are name-level matches and are reported as
    ``match_type="name"``/``confirmed=false``; they are informational and not
    written anywhere.
    """
    result = osv.lookup(ecosystem, name, version)
    return OsvLookupResponse.from_result(result)


# ---------------------------------------------------------------------------
# Targeted OSV ingestion into the graph
# ---------------------------------------------------------------------------

@router.post(
    "/analyses/{analysis_id}/vulnerabilities",
    response_model=VulnerabilityIngestResponse,
    summary="Ingest OSV vulnerabilities for one analysis's resolved packages",
    responses={404: {"description": "Analysis not found in the graph"}},
)
def ingest_analysis_vulnerabilities_endpoint(
    analysis_id: str = Path(..., description="Graph analysis identifier."),
    graph: GraphService = Depends(get_graph_service),
    osv: OsvService = Depends(get_osv_service),
    vulnerability_service: VulnerabilityGraphService = Depends(get_vulnerability_service),
) -> VulnerabilityIngestResponse:
    """Run a targeted OSV sync for one persisted analysis.

    Every resolved package of the analysis is queried on OSV (batched
    discovery, then full-record hydration).  Only version-confirmed matches —
    OSV confirmed the exact resolved version is affected — become
    ``AFFECTED_BY`` edges.  Packages without a resolved version are reported
    and untouched.  The run is idempotent: repeating it refreshes stored
    records instead of duplicating them.
    """
    cap = osv.settings.max_packages_per_ingest
    # GraphRecordNotFoundError propagates to the shared error envelope (404).
    analysis = graph.get_analysis_graph_status(analysis_id)
    repository_id = analysis.get("repository_id")
    commit_sha = analysis.get("commit_sha")
    if not repository_id or not commit_sha:
        raise GraphRecordNotFoundError(
            f"Analysis {analysis_id!r} has no associated repository/commit",
            details={"analysis_id": analysis_id},
        )
    packages = graph.get_repository_packages(analysis_id, limit=cap + 1)

    rows = packages.get("rows", [])
    if len(rows) > cap:
        raise InputValidationError(
            f"Analysis {analysis_id!r} has more resolved packages than the ingestion cap "
            f"({cap}); raise BLASTRADIUS_OSV_MAX_PACKAGES_PER_INGEST to cover it"
        )

    items: list[OsvPackageItem] = []
    unresolved_packages: list[str] = []
    for row in rows:
        version = row.get("version")
        if not version:
            unresolved_packages.append(str(row.get("normalized_name") or row.get("id")))
            continue
        items.append(
            OsvPackageItem(
                ecosystem=str(row.get("ecosystem") or "pypi"),
                package_name=str(row.get("normalized_name") or ""),
                original_name=str(row.get("original_name")) if row.get("original_name") else None,
                version=str(version),
            )
        )

    _log.info(
        "osv ingest start analysis_id=%s packages=%d unresolved=%d",
        safe_text(analysis_id, 80),
        len(items),
        len(unresolved_packages),
    )

    # Typed OsvError failures of the whole run propagate to the error envelope.
    report = osv.sync(items)

    edge_payloads = [
        match_to_edge_payload(match, repository_id=str(repository_id), commit_sha=str(commit_sha))
        for match in report.matches
    ]
    summary = vulnerability_service.record_vulnerabilities(
        list(report.vulnerabilities),
        edge_payloads,
        repository_id=str(repository_id),
        commit_sha=str(commit_sha),
    )
    last_sync = vulnerability_service.get_last_sync(analysis_id)

    response = VulnerabilityIngestResponse(
        analysis_id=analysis_id,
        repository_id=str(repository_id),
        commit_sha=str(commit_sha),
        status=report.status,
        packages_scanned=report.items_scanned,
        items_with_matches=report.items_with_matches,
        items_without_matches=report.items_without_matches,
        vulnerabilities_found=report.vulnerability_count,
        vulnerabilities_created=summary.vulnerabilities_created,
        vulnerabilities_updated=summary.vulnerabilities_updated,
        edges_created=summary.edges_created,
        edges_updated=summary.edges_updated,
        skipped_edges=summary.skipped_edges,
        last_synced_at=last_sync.get("last_synced_at"),
        errors=[VulnerabilityIngestError.from_sync_error(error) for error in report.errors],
    )
    _log.info(
        "osv ingest done analysis_id=%s status=%s vulns=%d edges=%d errors=%d",
        safe_text(analysis_id, 80),
        response.status,
        response.vulnerabilities_found,
        response.edges_created + response.edges_updated,
        len(response.errors),
    )
    return response


# ---------------------------------------------------------------------------
# Graph-backed reads
# ---------------------------------------------------------------------------

@router.get(
    "/analyses/{analysis_id}/vulnerabilities",
    response_model=AnalysisVulnerabilitiesResponse,
    summary="Return vulnerabilities affecting the analysis's packages",
    responses={404: {"description": "Analysis not found in the graph"}},
)
def list_analysis_vulnerabilities_endpoint(
    analysis_id: str = Path(..., description="Graph analysis identifier."),
    skip: int = Query(default=0, ge=0, description="Number of records to skip."),
    limit: int = Query(default=200, ge=1, le=1000, description="Maximum records to return."),
    vulnerability_service: VulnerabilityGraphService = Depends(get_vulnerability_service),
) -> AnalysisVulnerabilitiesResponse:
    """Return, per package, the vulnerabilities confirmed for its resolved version."""
    result = vulnerability_service.get_analysis_vulnerabilities(analysis_id, skip=skip, limit=limit)
    last_sync = vulnerability_service.get_last_sync(analysis_id)
    items = [
        AnalysisVulnerabilityItem(
            vulnerability_id=str(row.get("vulnerability_id")),
            summary=row.get("summary") if isinstance(row.get("summary"), str) else None,
            package_id=str(row.get("package_id") or ""),
            package_name=str(row.get("package_name") or ""),
            package_version=row.get("package_version") if isinstance(row.get("package_version"), str) else None,
            ecosystem=row.get("ecosystem") if isinstance(row.get("ecosystem"), str) else None,
            match_type=row.get("match_type") if isinstance(row.get("match_type"), str) else None,
            fixed_versions=_string_list(row.get("fixed_versions")),
            aliases=_string_list(row.get("aliases")),
            severities=_parse_severities(row.get("severities")),
            published=row.get("published") if isinstance(row.get("published"), str) else None,
            modified=row.get("modified") if isinstance(row.get("modified"), str) else None,
            last_synced_at=row.get("last_synced_at") if isinstance(row.get("last_synced_at"), str) else None,
        )
        for row in result.get("rows", [])
        if row.get("vulnerability_id") and row.get("package_id")
    ]
    analysis = vulnerability_service.get_analysis_scope(analysis_id)
    return AnalysisVulnerabilitiesResponse(
        analysis_id=analysis_id,
        repository_id=str(analysis.get("repository_id")),
        commit_sha=str(analysis.get("commit_sha")),
        count=len(items),
        items=items,
        last_synced_at=last_sync.get("last_synced_at"),
    )


@router.get(
    "/analyses/{analysis_id}/vulnerabilities/blast-radius",
    response_model=VulnerabilityBlastRadiusResponse,
    summary="Trace impact chains from affected packages to downstream dependents",
    responses={404: {"description": "Analysis not found in the graph"}},
)
def vulnerability_blast_radius_endpoint(
    analysis_id: str = Path(..., description="Graph analysis identifier."),
    depth: int = Query(default=3, ge=0, le=5, description="Maximum DEPENDS_ON hops to follow."),
    vulnerability_id: str | None = Query(
        default=None, min_length=1, max_length=120,
        description="Restrict paths to one vulnerability id.",
    ),
    skip: int = Query(default=0, ge=0, description="Number of paths to skip."),
    limit: int = Query(default=200, ge=1, le=1000, description="Maximum paths to return."),
    vulnerability_service: VulnerabilityGraphService = Depends(get_vulnerability_service),
) -> VulnerabilityBlastRadiusResponse:
    """Explainable paths: vulnerable package -> dependents impacted through it.

    ``hop_count == 0`` rows are the directly affected packages; ``hop_count >= 1``
    rows depend on them through actual graph relationships.  Every path names
    the vulnerability id supporting the conclusion.
    """
    result = vulnerability_service.get_impact_paths(
        analysis_id,
        vulnerability_id=vulnerability_id,
        depth=depth,
        skip=skip,
        limit=limit,
    )
    paths = [
        ImpactPathOut(
            vulnerability_id=str(row.get("vulnerability_id") or ""),
            vulnerability_summary=row.get("vulnerability_summary") if isinstance(row.get("vulnerability_summary"), str) else None,
            affected_package_id=str(row.get("affected_package_id") or ""),
            affected_package_name=str(row.get("affected_package_name") or ""),
            affected_package_version=row.get("affected_package_version") if isinstance(row.get("affected_package_version"), str) else None,
            downstream_chain=_string_list(row.get("downstream_chain")),
            hop_count=int(row.get("hop_count") or 0),
            match_type=row.get("match_type") if isinstance(row.get("match_type"), str) else None,
            fixed_versions=_string_list(row.get("fixed_versions")),
        )
        for row in result.get("rows", [])
        if row.get("vulnerability_id") and row.get("affected_package_id")
    ]
    analysis = vulnerability_service.get_analysis_scope(analysis_id)
    return VulnerabilityBlastRadiusResponse(
        analysis_id=analysis_id,
        repository_id=str(analysis.get("repository_id")),
        commit_sha=str(analysis.get("commit_sha")),
        depth=depth,
        count=len(paths),
        paths=paths,
    )


@router.get(
    "/vulnerabilities/{vulnerability_id}",
    response_model=VulnerabilityDetailResponse,
    summary="Return one stored vulnerability record and its affected components",
    responses={404: {"description": "Vulnerability not stored in the graph"}},
)
def get_vulnerability_detail_endpoint(
    vulnerability_id: str = Path(..., description="OSV vulnerability identifier, e.g. GHSA-... or CVE-...."),
    skip: int = Query(default=0, ge=0, description="Number of components to skip."),
    limit: int = Query(default=200, ge=1, le=1000, description="Maximum components to return."),
    vulnerability_service: VulnerabilityGraphService = Depends(get_vulnerability_service),
) -> VulnerabilityDetailResponse:
    """One vulnerability exactly as mirrored from OSV, plus its graph components.

    The components are returned across *all* repositories and analyses where the
    vulnerability was seen: the query is intentionally unscoped so a consumer can
    see every affected component for a shared OSV record.  Each component row
    carries its own ``repository_id`` and ``commit_sha``; callers needing an
    analysis-scoped view should filter on those, or use
    ``GET /analyses/{analysis_id}/vulnerabilities`` instead.
    """
    detail = vulnerability_service.get_vulnerability(vulnerability_id)
    components = vulnerability_service.get_vulnerability_components(
        vulnerability_id, skip=skip, limit=limit
    )
    component_items = [
        VulnerabilityComponentOut(
            package_id=str(row.get("package_id") or ""),
            package_name=str(row.get("package_name") or ""),
            package_version=row.get("package_version") if isinstance(row.get("package_version"), str) else None,
            ecosystem=row.get("ecosystem") if isinstance(row.get("ecosystem"), str) else None,
            repository_id=str(row.get("repository_id") or ""),
            commit_sha=str(row.get("commit_sha") or ""),
            match_type=row.get("match_type") if isinstance(row.get("match_type"), str) else None,
            fixed_versions=_string_list(row.get("fixed_versions")),
            last_synced_at=row.get("last_synced_at") if isinstance(row.get("last_synced_at"), str) else None,
        )
        for row in components.get("rows", [])
        if row.get("package_id")
    ]
    return VulnerabilityDetailResponse(
        id=str(detail.get("id") or vulnerability_id),
        summary=detail.get("summary") if isinstance(detail.get("summary"), str) else None,
        details=detail.get("details") if isinstance(detail.get("details"), str) else None,
        aliases=_string_list(detail.get("aliases")),
        related=_string_list(detail.get("related")),
        published=detail.get("published") if isinstance(detail.get("published"), str) else None,
        modified=detail.get("modified") if isinstance(detail.get("modified"), str) else None,
        withdrawn=detail.get("withdrawn") if isinstance(detail.get("withdrawn"), str) else None,
        severities=_parse_severities(detail.get("severities")),
        references=_parse_references(detail),
        affected_packages=_string_list(detail.get("affected_packages")),
        schema_version=detail.get("schema_version") if isinstance(detail.get("schema_version"), str) else None,
        source=detail.get("source") if isinstance(detail.get("source"), str) else None,
        created_at=detail.get("created_at") if isinstance(detail.get("created_at"), str) else None,
        updated_at=detail.get("updated_at") if isinstance(detail.get("updated_at"), str) else None,
        affected_components=component_items,
        affected_component_count=len(component_items),
    )


def _parse_references(detail: dict[str, Any]) -> list[dict[str, str]]:
    """Rebuild ``{type, url}`` from stored ``TYPE url`` reference strings."""
    parsed: list[dict[str, str]] = []
    for item in _string_list(detail.get("references")):
        parts = item.split(" ", 1)
        if len(parts) == 2:
            parsed.append({"type": parts[0], "url": parts[1]})
        else:
            parsed.append({"url": parts[0]})
    return parsed


__all__ = ["router"]
