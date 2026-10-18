"""Deterministic prioritization and remediation orchestration (Phase 5).

Reads the analysis facts that Phases 2/3 already persist (resolved packages,
declarations, ``DEPENDS_ON`` edges, ``AFFECTED_BY`` findings with their stored
OSV ranges) and computes — with no LLM involvement and no graph writes —
prioritized findings, remediation candidates, and ranked fix groups.

Everything is derived; nothing is persisted.  The service is usable while the
LLM provider is unavailable: it only needs the graph.
"""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from app.core.errors import InputValidationError
from app.core.logging import get_logger
from app.graph.errors import GraphRecordNotFoundError
from app.graph.service import GraphService
from app.graph.vulnerability import VulnerabilityGraphService
from app.models.ids import stable_id
from app.remediation.candidates import build_package_plan
from app.remediation.groups import (
    build_fix_group,
    collect_unresolved_findings,
    rank_fix_groups,
)
from app.remediation.models import (
    AnalysisContext,
    AnalysisReport,
    ConstraintSource,
    FindingInput,
    FindingOut,
    FixGroup,
    PackageRef,
    PackageRemediationPlan,
)
from app.remediation.priority import prioritize

_log = get_logger("remediation.service")

#: Fetch/processing bounds.  Exceeding a bound is always reported explicitly
#: instead of silently dropping data.
MAX_FINDINGS = 1000
MAX_PACKAGES = 2000
MAX_DECLARATIONS = 2000
MAX_EDGES = 5000
MAX_CONSTRAINT_SOURCES = 100
MAX_UNRESOLVED_RELATIONSHIPS = 20

#: Reachability/dependent traversals are bounded at this many hops.
TRAVERSAL_DEPTH = 5


def _as_str(value: Any) -> str:
    return "" if value is None else str(value)


def _opt_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _opt_int(value: Any) -> int | None:
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _str_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        return [str(item) for item in value if item is not None]
    return [str(value)]


def _require_text(value: Any, label: str) -> str:
    text = _as_str(value).strip()
    if not text:
        raise InputValidationError(
            f"{label} must not be empty", details={label: value}
        )
    return text


class RemediationService:
    """Compute prioritized findings, candidates and fix groups for an analysis."""

    def __init__(self, graph: GraphService, vulnerabilities: VulnerabilityGraphService) -> None:
        self._graph = graph
        self._vuln = vulnerabilities

    # ------------------------------------------------------------------ #
    # public API
    # ------------------------------------------------------------------ #
    def analyze(self, analysis_id: str) -> AnalysisReport:
        """Compute the full deterministic report for one analysis."""
        analysis_id = _require_text(analysis_id, "analysis_id")
        analysis = self._graph.get_analysis_graph_status(analysis_id)
        repository_id = _as_str(analysis.get("repository_id"))
        commit_sha = _as_str(analysis.get("commit_sha"))
        if not repository_id or not commit_sha:
            raise GraphRecordNotFoundError(
                f"Analysis {analysis_id!r} has no associated repository/commit",
                details={"analysis_id": analysis_id},
            )
        stats = self._graph.get_graph_statistics(analysis_id)

        limitations: list[str] = []
        package_rows = self._fetch(
            self._graph.get_repository_packages(analysis_id, limit=MAX_PACKAGES + 1),
            MAX_PACKAGES,
            "packages_truncated",
            limitations,
        )
        declaration_rows = self._fetch(
            self._graph.get_declarations(analysis_id, limit=MAX_DECLARATIONS + 1),
            MAX_DECLARATIONS,
            "declarations_truncated",
            limitations,
        )
        edge_rows = self._fetch(
            self._graph.get_dependency_edges(analysis_id, limit=MAX_EDGES + 1),
            MAX_EDGES,
            "dependency_edges_truncated",
            limitations,
        )
        vuln_rows = self._fetch(
            self._vuln.get_analysis_vulnerabilities(analysis_id, limit=MAX_FINDINGS + 1),
            MAX_FINDINGS,
            "findings_truncated",
            limitations,
        )
        entry_rows = self._rows(
            self._vuln.get_modeled_entry_paths(analysis_id, depth=TRAVERSAL_DEPTH)
        )
        impact_rows = self._rows(
            self._vuln.get_dependency_impact_summary(analysis_id, depth=TRAVERSAL_DEPTH)
        )

        dependency_edges_present = int(stats.get("dependency_edges", 0) or 0) > 0
        entry_packages_defined = any(
            _opt_str(row.get("relation")) == "direct" or bool(row.get("is_root_project"))
            for row in package_rows
        )
        if not dependency_edges_present:
            limitations.append("no_modeled_dependency_edges")
        else:
            limitations.append("reachability_traversal_bounded_at_5_hops")
        if package_rows and not entry_packages_defined:
            limitations.append("no_entry_packages_defined")
        if int(stats.get("vulnerability_edges", 0) or 0) == 0:
            limitations.append("no_confirmed_vulnerabilities")

        context = self._build_context(analysis, stats, declaration_rows)

        packages_by_id = {_as_str(row.get("id")): row for row in package_rows}
        entry_by_package = {
            _as_str(row.get("package_id")): row
            for row in entry_rows
            if _as_str(row.get("package_id"))
        }
        impact_by_package = {
            _as_str(row.get("package_id")): row
            for row in impact_rows
            if _as_str(row.get("package_id"))
        }

        inputs: list[FindingInput] = []
        for row in vuln_rows:
            item = self._finding_input(
                analysis_id, row, packages_by_id, entry_by_package, impact_by_package
            )
            if item is not None:
                inputs.append(item)

        ranked = prioritize(
            inputs,
            graph_has_dependency_edges=dependency_edges_present,
            entry_packages_defined=entry_packages_defined,
        )

        findings: list[FindingOut] = []
        for item in ranked:
            source = item.inputs
            reasons: list[str] = []
            if not context.complete:
                reasons.append(
                    f"analysis status is {context.analysis_status!r} "
                    f"(errors={context.error_count}, warnings={context.warning_count})"
                )
            finding_limitations: list[str] = []
            if source.withdrawn:
                finding_limitations.append("advisory_withdrawn")
            if source.match_type != "version":
                finding_limitations.append("match_type_not_version")
            findings.append(
                FindingOut(
                    finding_id=source.finding_id,
                    analysis_id=analysis_id,
                    repository_id=repository_id,
                    commit_sha=commit_sha,
                    vulnerability_id=source.vulnerability_id,
                    vulnerability_summary=source.vulnerability_summary,
                    aliases=list(source.aliases),
                    advisory_references=list(source.references),
                    advisory_withdrawn=bool(source.withdrawn),
                    package=PackageRef(
                        package_id=source.package_id,
                        package_name=source.package_name,
                        package_version=source.package_version,
                        ecosystem=source.ecosystem,
                        dependency_role=source.dependency_role,
                        is_dev=source.is_dev,
                        is_optional=source.is_optional,
                        is_root_project=source.is_root_project,
                        groups=list(source.groups),
                        marker=source.marker,
                        source_manifest=source.source_manifest,
                    ),
                    match_type=source.match_type,
                    fixed_versions=list(source.fixed_versions),
                    osv_modified=source.osv_modified,
                    last_synced_at=source.last_synced_at,
                    priority=item.priority,
                    confidence="verified" if context.complete else "reduced",
                    confidence_reasons=reasons,
                    limitations=finding_limitations,
                )
            )

        findings_by_id = {finding.finding_id: finding for finding in findings}
        inputs_by_id = {item.inputs.finding_id: item.inputs for item in ranked}

        declarations_by_name: dict[str, list[dict[str, Any]]] = {}
        for row in declaration_rows:
            name = _opt_str(row.get("normalized_name"))
            if name:
                declarations_by_name.setdefault(name, []).append(row)
        direct_package_ids = {
            _as_str(row.get("id"))
            for row in package_rows
            if _opt_str(row.get("relation")) == "direct" or bool(row.get("is_root_project"))
        }
        edges_by_to_id: dict[str, list[dict[str, Any]]] = {}
        versionless_edges_by_name: dict[str, list[dict[str, Any]]] = {}
        for row in edge_rows:
            to_id = _opt_str(row.get("to_id"))
            if to_id:
                edges_by_to_id.setdefault(to_id, []).append(row)
            if not _opt_str(row.get("to_resolved_version")) and not _opt_str(row.get("to_version")):
                to_name = _opt_str(row.get("to_name"))
                if to_name:
                    versionless_edges_by_name.setdefault(to_name, []).append(row)

        package_order: list[str] = []
        for finding in findings:
            key = finding.package.package_id
            if key not in package_order:
                package_order.append(key)

        plans: list[PackageRemediationPlan] = []
        for package_id in package_order:
            package_findings = [
                finding
                for finding in findings
                if finding.package.package_id == package_id
            ]
            package = package_findings[0].package
            sources = self._constraint_sources(
                package_findings[0].package,
                declarations_by_name.get(package.package_name, []),
                edges_by_to_id.get(package_id, []),
            )
            truncated = len(sources) > MAX_CONSTRAINT_SOURCES
            if truncated:
                sources = sources[:MAX_CONSTRAINT_SOURCES]
            plan = build_package_plan(
                package=package,
                findings=package_findings,
                finding_inputs=inputs_by_id,
                constraint_sources=sources,
                unresolved_relationships=self._unresolved_relationships(
                    package.package_name,
                    declarations_by_name.get(package.package_name, []),
                    versionless_edges_by_name.get(package.package_name, []),
                ),
                migration_concerns=self._migration_concerns(
                    package, edges_by_to_id.get(package_id, []), direct_package_ids
                ),
            )
            if truncated:
                plan = plan.model_copy(
                    update={
                        "limitations": [*plan.limitations, "constraint_checks_truncated"]
                    }
                )
            plans.append(plan)

        groups = rank_fix_groups(
            [
                build_fix_group(
                    analysis_id=analysis_id,
                    repository_id=repository_id,
                    commit_sha=commit_sha,
                    plan=plan,
                    findings_by_id=findings_by_id,
                )
                for plan in plans
                if plan.candidates
            ]
        )
        unresolved = collect_unresolved_findings(plans, findings_by_id)

        return AnalysisReport(
            analysis_id=analysis_id,
            repository_id=repository_id,
            commit_sha=commit_sha,
            context=context,
            findings=findings,
            plans=plans,
            groups=groups,
            unresolved_findings=unresolved,
            limitations=limitations,
        )

    def find_finding(
        self, analysis_id: str, finding_id: str
    ) -> tuple[FindingOut, PackageRemediationPlan | None, list[str]]:
        """Return one finding, its package plan and the analysis limitations."""
        finding_id = _require_text(finding_id, "finding_id")
        report = self.analyze(analysis_id)
        finding = next(
            (item for item in report.findings if item.finding_id == finding_id), None
        )
        if finding is None:
            raise GraphRecordNotFoundError(
                f"Finding {finding_id!r} was not found for this analysis",
                details={"analysis_id": analysis_id, "finding_id": finding_id},
            )
        plan = next(
            (item for item in report.plans if item.package_id == finding.package.package_id),
            None,
        )
        return finding, plan, list(report.limitations)

    def find_group(self, analysis_id: str, group_id: str) -> tuple[FixGroup, list[str]]:
        """Return one fix group and the analysis limitations, scoped to the analysis."""
        group_id = _require_text(group_id, "group_id")
        report = self.analyze(analysis_id)
        group = next((item for item in report.groups if item.group_id == group_id), None)
        if group is None:
            raise GraphRecordNotFoundError(
                f"Fix group {group_id!r} was not found for this analysis",
                details={"analysis_id": analysis_id, "group_id": group_id},
            )
        return group, list(report.limitations)

    # ------------------------------------------------------------------ #
    # internal helpers
    # ------------------------------------------------------------------ #
    @staticmethod
    def _rows(result: Any) -> list[dict[str, Any]]:
        if isinstance(result, dict):
            rows = result.get("rows")
            if isinstance(rows, list):
                return [row for row in rows if isinstance(row, dict)]
        return []

    @classmethod
    def _fetch(
        cls,
        result: Any,
        cap: int,
        truncation_token: str,
        limitations: list[str],
    ) -> list[dict[str, Any]]:
        rows = cls._rows(result)
        if len(rows) > cap:
            limitations.append(truncation_token)
            return rows[:cap]
        return rows

    @staticmethod
    def _build_context(
        analysis: dict[str, Any],
        stats: dict[str, Any],
        declaration_rows: Sequence[dict[str, Any]],
    ) -> AnalysisContext:
        status = _as_str(analysis.get("status")) or "unknown"
        warnings = _opt_int(analysis.get("warning_count")) or 0
        errors = _opt_int(analysis.get("error_count")) or 0
        complete = status == "success" and errors == 0

        targets_without_version = sum(
            1 for row in declaration_rows if _opt_str(row.get("resolved_version")) is None
        )
        notes: list[str] = []
        if status != "success":
            notes.append(f"analysis status is {status!r}")
        if errors:
            notes.append(f"ingestion reported {errors} error(s)")
        if warnings:
            notes.append(f"ingestion reported {warnings} warning(s)")
        unknown_relation = _opt_int(analysis.get("unknown_relation_packages")) or 0
        if unknown_relation:
            notes.append(
                f"{unknown_relation} resolved package(s) lack a direct/transitive classification"
            )
        conflicting = _opt_int(analysis.get("conflicting_packages")) or 0
        if conflicting:
            notes.append(
                f"{conflicting} conflicting package record(s) were reported at ingestion"
            )
        unsupported = _opt_int(analysis.get("unsupported_formats")) or 0
        if unsupported:
            notes.append(
                f"{unsupported} manifest(s) use unsupported formats and were not parsed"
            )

        return AnalysisContext(
            analysis_status=status,
            complete=complete,
            warning_count=warnings,
            error_count=errors,
            resolved_packages=int(stats.get("resolved_packages", 0) or 0),
            dependency_edges=int(stats.get("dependency_edges", 0) or 0),
            vulnerability_edges=int(stats.get("vulnerability_edges", 0) or 0),
            declaration_targets_without_version=targets_without_version,
            notes=notes,
        )

    @staticmethod
    def _finding_input(
        analysis_id: str,
        row: dict[str, Any],
        packages_by_id: dict[str, dict[str, Any]],
        entry_by_package: dict[str, dict[str, Any]],
        impact_by_package: dict[str, dict[str, Any]],
    ) -> FindingInput | None:
        package_id = _as_str(row.get("package_id"))
        vulnerability_id = _as_str(row.get("vulnerability_id"))
        if not package_id or not vulnerability_id:
            return None
        package_row = packages_by_id.get(package_id, {})

        def pick(key: str, fallback: str) -> Any:
            value = row.get(key)
            if value is None:
                value = package_row.get(fallback)
            return value

        entry_row = entry_by_package.get(package_id, {})
        impact_row = impact_by_package.get(package_id, {})
        dependents = sorted(set(_str_list(impact_row.get("dependents"))))
        dependent_count = _opt_int(impact_row.get("dependent_count"))
        if dependent_count is None:
            dependent_count = len(dependents)

        return FindingInput(
            finding_id=stable_id("finding", analysis_id, package_id, vulnerability_id),
            vulnerability_id=vulnerability_id,
            vulnerability_summary=_opt_str(row.get("summary")),
            aliases=tuple(_str_list(row.get("aliases"))),
            references=tuple(_str_list(row.get("references"))),
            withdrawn=_opt_str(row.get("withdrawn")),
            severities=tuple(_str_list(row.get("severities"))),
            package_id=package_id,
            package_name=_as_str(pick("package_name", "normalized_name")) or package_id,
            package_version=_opt_str(pick("package_version", "version")),
            ecosystem=_opt_str(pick("ecosystem", "ecosystem")),
            dependency_role=_opt_str(pick("package_relation", "relation")) or "unknown",
            is_dev=bool(pick("is_dev", "is_dev")),
            is_optional=bool(pick("is_optional", "is_optional")),
            is_root_project=bool(pick("is_root_project", "is_root_project")),
            groups=tuple(_str_list(pick("groups", "groups"))),
            marker=_opt_str(pick("package_marker", "marker")),
            source_manifest=_opt_str(pick("source_manifest", "source_manifest")),
            match_type=_opt_str(row.get("match_type")),
            fixed_versions=tuple(sorted(set(_str_list(row.get("fixed_versions"))))),
            ranges_json=_opt_str(row.get("ranges_json")),
            osv_modified=_opt_str(row.get("osv_modified")),
            last_synced_at=_opt_str(row.get("last_synced_at")),
            entry_points=tuple(sorted(set(_str_list(entry_row.get("entry_points"))))),
            entry_min_hops=_opt_int(entry_row.get("min_hops")),
            dependent_components=tuple(dependents),
            dependent_component_count=dependent_count,
            dependent_min_hops=_opt_int(impact_row.get("min_hops")),
        )

    @staticmethod
    def _constraint_sources(
        package: PackageRef,
        declarations: Sequence[dict[str, Any]],
        incoming_edges: Sequence[dict[str, Any]],
    ) -> list[ConstraintSource]:
        sources: list[ConstraintSource] = []
        seen: set[tuple[str, str, str | None, str | None]] = set()

        ordered_declarations = sorted(
            declarations,
            key=lambda row: (
                _as_str(row.get("manifest_path")),
                _opt_int(row.get("line_number")) or 0,
            ),
        )
        for row in ordered_declarations:
            manifest = _opt_str(row.get("manifest_path")) or "manifest"
            line = _opt_int(row.get("line_number"))
            origin = f"{manifest}:{line}" if line else manifest
            if row.get("is_exact_pin"):
                origin = f"{origin} (exact pin)"
            key = (
                "declaration",
                origin,
                _opt_str(row.get("version_constraint")),
                _opt_str(row.get("constraint_scheme")),
            )
            if key in seen:
                continue
            seen.add(key)
            sources.append(
                ConstraintSource(
                    source="declaration",
                    origin=origin,
                    constraint=key[2],
                    scheme=key[3],
                )
            )

        ordered_edges = sorted(
            incoming_edges,
            key=lambda row: (_as_str(row.get("from_name")), _as_str(row.get("from_version"))),
        )
        for row in ordered_edges:
            from_name = _opt_str(row.get("from_name")) or "unknown dependent"
            from_version = _opt_str(row.get("from_version"))
            origin = f"from {from_name} {from_version or '(version unknown)'}"
            key = ("dependency_edge", origin, _opt_str(row.get("constraint")), None)
            if key in seen:
                continue
            seen.add(key)
            sources.append(
                ConstraintSource(
                    source="dependency_edge",
                    origin=origin,
                    constraint=key[2],
                    scheme=None,
                )
            )
        return sources

    @staticmethod
    def _unresolved_relationships(
        package_name: str,
        declarations: Sequence[dict[str, Any]],
        versionless_edges: Sequence[dict[str, Any]],
    ) -> list[str]:
        items: list[str] = []
        ordered_declarations = sorted(
            declarations,
            key=lambda row: (
                _as_str(row.get("manifest_path")),
                _opt_int(row.get("line_number")) or 0,
            ),
        )
        for row in ordered_declarations:
            if _opt_str(row.get("resolved_version")) is not None:
                continue
            manifest = _opt_str(row.get("manifest_path")) or "manifest"
            constraint = _opt_str(row.get("version_constraint"))
            detail = (
                f"declared as {constraint!r}" if constraint else "declared unconstrained"
            )
            items.append(f"{manifest} {detail} with no lockfile-resolved version")
        for row in sorted(
            versionless_edges,
            key=lambda row: (_as_str(row.get("from_name")), _as_str(row.get("from_version"))),
        ):
            from_name = _opt_str(row.get("from_name")) or "unknown dependent"
            items.append(
                f"dependency edge {from_name} -> {package_name} has no resolved target version"
            )

        deduped = list(dict.fromkeys(items))
        if len(deduped) > MAX_UNRESOLVED_RELATIONSHIPS:
            dropped = len(deduped) - MAX_UNRESOLVED_RELATIONSHIPS
            return [
                *deduped[:MAX_UNRESOLVED_RELATIONSHIPS],
                f"unresolved_relationships_truncated (+{dropped} more)",
            ]
        return deduped

    @staticmethod
    def _migration_concerns(
        package: PackageRef,
        incoming_edges: Sequence[dict[str, Any]],
        direct_package_ids: set[str],
    ) -> list[str]:
        concerns: list[str] = []
        if package.is_dev:
            concerns.append("development-only dependency (dev scope)")
        if package.is_optional:
            concerns.append("optional dependency")
        if package.dependency_role == "transitive":
            direct_dependents = sorted(
                {
                    f"{_opt_str(edge.get('from_name')) or 'unknown'} "
                    f"{_opt_str(edge.get('from_version')) or '(version unknown)'}"
                    for edge in incoming_edges
                    if _as_str(edge.get("from_id")) in direct_package_ids
                }
            )
            if direct_dependents:
                concerns.append(
                    "transitive dependency: resolution normally flows through direct "
                    "dependent(s): " + ", ".join(direct_dependents)
                )
            else:
                concerns.append(
                    "transitive dependency: no direct dependent is modeled, so the "
                    "upgrade may require a lockfile refresh"
                )
        if package.marker or any(_opt_str(edge.get("marker")) for edge in incoming_edges):
            concerns.append(
                "environment-marker-conditional constraints exist; validate the change "
                "per environment"
            )
        return concerns


__all__ = [
    "MAX_CONSTRAINT_SOURCES",
    "MAX_DECLARATIONS",
    "MAX_EDGES",
    "MAX_FINDINGS",
    "MAX_PACKAGES",
    "MAX_UNRESOLVED_RELATIONSHIPS",
    "TRAVERSAL_DEPTH",
    "RemediationService",
]
