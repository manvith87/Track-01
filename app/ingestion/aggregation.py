"""Aggregation: merging parsed manifests into one coherent dependency picture.

This module is where BlastRadius performs the reasoning that no single
manifest can do on its own:

* **resolved versions** are attached to declarations only from a lockfile, and
  only when the lockfile is unambiguous (a lock that pins several versions of
  the same name for different resolution markers is reported, not guessed at);
* **direct vs transitive** is derived from evidence: declarations of the
  project's own manifests plus the workspace root of ``uv.lock`` are direct,
  everything reachable from them through recorded lock edges is transitive,
  and anything else stays ``unknown`` rather than being invented;
* **conflicts** are reported: two different exact pins for the same package and
  marker, a lock that disagrees with a pin, two lockfiles that disagree, or two
  manifests in the same directory declaring different constraints.
"""

from __future__ import annotations

import collections
from dataclasses import dataclass, field

from app.core.config import Settings
from app.core.logging import get_logger
from app.ingestion.discovery import DiscoveredManifest, DiscoveryResult
from app.ingestion.parsers import FORMAT_CAPABILITIES, SUPPORTED_FORMATS
from app.ingestion.parsers.base import ParseOutcome
from app.models.common import (
    DependencyRelation,
    DependencyScope,
    ManifestFormat,
    ManifestParseStatus,
    Severity,
    SupportLevel,
    WarningCode,
)
from app.models.dependencies import (
    DependencyDeclaration,
    DependencyManifestRecord,
    ResolvedDependencyEdge,
    ResolvedPackage,
)
from app.models.ids import stable_id
from app.models.ingestion import FormatCoverage, IngestionError, IngestionWarning
from app.ingestion.parsers.base import warn

_log = get_logger("ingestion.aggregation")


@dataclass(slots=True)
class AggregatedDependencies:
    """Everything the parsers produced, made coherent and ready for Phase 2."""

    manifests: list[DependencyManifestRecord] = field(default_factory=list)
    declarations: list[DependencyDeclaration] = field(default_factory=list)
    resolved_packages: list[ResolvedPackage] = field(default_factory=list)
    edges: list[ResolvedDependencyEdge] = field(default_factory=list)
    warnings: list[IngestionWarning] = field(default_factory=list)
    errors: list[IngestionError] = field(default_factory=list)
    coverage: list[FormatCoverage] = field(default_factory=list)
    conflicting_packages: set[str] = field(default_factory=set)
    direct_declarations: int = 0
    dev_declarations: int = 0
    optional_declarations: int = 0
    transitive_packages: int = 0
    unknown_relation_packages: int = 0
    truncated_warning_count: int = 0


@dataclass(slots=True)
class _ManifestBundle:
    manifest: DiscoveredManifest
    outcome: ParseOutcome


def aggregate_dependencies(
    *,
    repository_id: str,
    commit_sha: str,
    discovery: DiscoveryResult,
    outcomes: dict[str, ParseOutcome | None],
    settings: Settings,
) -> AggregatedDependencies:
    """Merge parse outcomes into stamped, classified dependency records."""
    result = AggregatedDependencies()

    bundles: list[_ManifestBundle] = []
    for manifest in discovery.manifests:
        if manifest.format is None:
            result.manifests.append(_record_for_unsupported(manifest, repository_id, commit_sha))
            continue
        outcome = outcomes.get(manifest.path)
        if outcome is None:
            result.manifests.append(_record_for_unparsed(manifest, repository_id, commit_sha))
            continue
        bundles.append(_ManifestBundle(manifest=manifest, outcome=outcome))

    lock_bundles = [bundle for bundle in bundles if bundle.manifest.format is not None and bundle.manifest.format.is_lockfile]
    non_lock_bundles = [bundle for bundle in bundles if not (bundle.manifest.format is not None and bundle.manifest.format.is_lockfile)]

    if len(lock_bundles) > 1:
        result.warnings.append(
            warn(
                WarningCode.MULTIPLE_LOCKFILES,
                "The repository contains more than one lockfile; resolved versions are reported per lockfile and are "
                "never merged silently",
                severity=Severity.INFO,
                stage=_aggregation_stage(),
                lockfiles=sorted(bundle.manifest.path for bundle in lock_bundles),
            )
        )

    lock_index = _LockIndex(lock_bundles)

    for bundle in lock_bundles:
        if _companion_manifest(bundle.manifest, non_lock_bundles) is None:
            result.warnings.append(
                warn(
                    WarningCode.LOCKFILE_WITHOUT_MANIFEST,
                    "A lockfile has no manifest in the same directory, so resolved packages are reported with "
                    "relation=unknown",
                    severity=Severity.WARNING,
                    stage=_aggregation_stage(),
                    manifest_path=bundle.manifest.path,
                )
            )

    declarations: list[DependencyDeclaration] = []
    for bundle in non_lock_bundles:
        for declaration in bundle.outcome.declarations:
            declarations.append(_stamp_declaration(declaration, repository_id, commit_sha, lock_index))
    declarations = _cap_declarations(declarations, settings, result)

    resolved_packages: list[ResolvedPackage] = []
    edges: list[ResolvedDependencyEdge] = []
    for bundle in lock_bundles:
        classified = _classify_lock_packages(
            bundle,
            non_lock_bundles,
            result,
            repository_id=repository_id,
            commit_sha=commit_sha,
        )
        resolved_packages.extend(classified)
        edges.extend(_stamp_edge(edge, repository_id, commit_sha) for edge in bundle.outcome.edges)

    resolved_packages = resolved_packages[: settings.max_dependencies]
    edges = edges[: settings.max_dependencies * 2]

    result.warnings.extend(_fill_edge_resolutions(edges, lock_bundles))
    result.warnings.extend(_detect_conflicts(declarations, resolved_packages, lock_bundles, settings, result))
    result.declarations = declarations
    result.resolved_packages = resolved_packages
    result.edges = edges
    result.direct_declarations = sum(1 for declaration in declarations if declaration.relation is DependencyRelation.DIRECT)
    result.dev_declarations = sum(1 for declaration in declarations if declaration.scope is DependencyScope.DEV)
    result.optional_declarations = sum(1 for declaration in declarations if declaration.scope is DependencyScope.OPTIONAL)
    result.transitive_packages = sum(
        1 for package in resolved_packages if package.relation is DependencyRelation.TRANSITIVE
    )
    result.unknown_relation_packages = sum(
        1
        for package in resolved_packages
        if package.relation is DependencyRelation.UNKNOWN and not package.is_root_project
    )

    for bundle in bundles:
        if bundle.manifest.format is not None:
            result.manifests.append(
                _record_for_parsed(
                    bundle.manifest,
                    bundle.outcome,
                    repository_id,
                    commit_sha,
                    non_lock_bundles,
                )
            )
    result.manifests.sort(key=lambda record: record.path)
    for bundle in bundles:
        result.warnings.extend(bundle.outcome.warnings)
        result.errors.extend(bundle.outcome.errors)
    result.coverage = _build_coverage(discovery, bundles)
    return result


# ---------------------------------------------------------------------------
# Manifest records
# ---------------------------------------------------------------------------
def _record_for_unsupported(
    manifest: DiscoveredManifest, repository_id: str, commit_sha: str
) -> DependencyManifestRecord:
    return DependencyManifestRecord(
        id=stable_id("man", manifest.path, "unsupported"),
        repository_id=repository_id,
        commit_sha=commit_sha,
        path=manifest.path,
        directory=manifest.directory,
        unsupported_format=manifest.unsupported_format,
        support_level=SupportLevel.UNSUPPORTED,
        status=ManifestParseStatus.SKIPPED,
        size_bytes=manifest.size_bytes,
        skipped_reason=manifest.skipped_reason or "unsupported_format",
    )


def _record_for_unparsed(
    manifest: DiscoveredManifest, repository_id: str, commit_sha: str
) -> DependencyManifestRecord:
    return DependencyManifestRecord(
        id=stable_id("man", manifest.path, manifest.format.value if manifest.format else ""),
        repository_id=repository_id,
        commit_sha=commit_sha,
        path=manifest.path,
        directory=manifest.directory,
        format=manifest.format,
        support_level=manifest.support_level,
        is_lockfile=manifest.is_lockfile,
        size_bytes=manifest.size_bytes,
        sha256=manifest.sha256,
        status=ManifestParseStatus.SKIPPED,
        skipped_reason=manifest.skipped_reason or "not_parsed",
    )


def _record_for_parsed(
    manifest: DiscoveredManifest,
    outcome: ParseOutcome,
    repository_id: str,
    commit_sha: str,
    non_lock_bundles: list[_ManifestBundle],
) -> DependencyManifestRecord:
    companion = _companion_manifest(manifest, non_lock_bundles)
    return DependencyManifestRecord(
        id=stable_id("man", manifest.path, manifest.format.value if manifest.format else ""),
        repository_id=repository_id,
        commit_sha=commit_sha,
        path=manifest.path,
        directory=manifest.directory,
        format=manifest.format,
        support_level=manifest.support_level,
        is_lockfile=manifest.is_lockfile,
        size_bytes=manifest.size_bytes,
        sha256=manifest.sha256,
        status=outcome.status,
        companion_manifest=companion,
        declaration_count=len(outcome.declarations),
        resolved_count=len(outcome.resolved_packages),
        edge_count=len(outcome.edges),
        requires_python=outcome.requires_python,
        sections=dict(sorted(outcome.sections.items())),
        metadata=dict(outcome.metadata),
        warning_codes=tuple(sorted({warning.code.value for warning in outcome.warnings})),
        error_codes=tuple(sorted({error.code.value for error in outcome.errors})),
    )


def _companion_manifest(manifest: DiscoveredManifest, non_lock_bundles: list[_ManifestBundle]) -> str | None:
    """Find the pyproject.toml that belongs to a lockfile (same directory)."""
    if manifest.format is None or not manifest.format.is_lockfile:
        return None
    for bundle in non_lock_bundles:
        if bundle.manifest.directory == manifest.directory and bundle.manifest.format is ManifestFormat.PYPROJECT_TOML:
            return bundle.manifest.path
    return None


# ---------------------------------------------------------------------------
# Lockfile resolution index
# ---------------------------------------------------------------------------
class _LockIndex:
    """Maps declarations to the resolved versions of the nearest lockfile."""

    def __init__(self, lock_bundles: list[_ManifestBundle]) -> None:
        self._lock_dirs: dict[str, list[_ManifestBundle]] = collections.defaultdict(list)
        for bundle in lock_bundles:
            self._lock_dirs[bundle.manifest.directory].append(bundle)

    def resolve(self, declaration: DependencyDeclaration) -> tuple[str | None, str | None]:
        """Return ``(resolved_version, lock_path)`` for a declaration.

        When several lockfiles live in the same directory the version is only
        reported if they agree; disagreement is surfaced by conflict detection
        instead of picking one arbitrarily.
        """
        directory = _directory_of(declaration.provenance.manifest_path)
        bundles = self._nearest(directory)
        if not bundles:
            return None, None

        versions_per_lock: dict[str, set[str]] = {}
        for bundle in bundles:
            versions = {
                package.version
                for package in bundle.outcome.resolved_packages
                if package.normalized_name == declaration.normalized_name
            }
            if versions:
                versions_per_lock[bundle.manifest.path] = versions
        if not versions_per_lock:
            return None, None
        if len(versions_per_lock) == 1:
            lock_path, versions = next(iter(versions_per_lock.items()))
            if len(versions) == 1:
                return next(iter(versions)), lock_path
            return None, None
        all_versions = {version for versions in versions_per_lock.values() for version in versions}
        if len(all_versions) == 1:
            version = next(iter(all_versions))
            return version, sorted(versions_per_lock)[0]
        return None, None

    def _nearest(self, directory: str) -> list[_ManifestBundle]:
        current = directory
        while True:
            bundles = self._lock_dirs.get(current)
            if bundles:
                return bundles
            if current in {"", "."}:
                return []
            current = current.rsplit("/", 1)[0] if "/" in current else "."


def _stamp_declaration(
    declaration: DependencyDeclaration,
    repository_id: str,
    commit_sha: str,
    lock_index: _LockIndex,
) -> DependencyDeclaration:
    resolved_version, resolved_from = lock_index.resolve(declaration)
    return declaration.model_copy(
        update={
            "repository_id": repository_id,
            "commit_sha": commit_sha,
            "resolved_version": resolved_version,
            "resolved_from": resolved_from,
        }
    )


def _stamp_resolved_package(package: ResolvedPackage, repository_id: str, commit_sha: str) -> ResolvedPackage:
    return package.model_copy(update={"repository_id": repository_id, "commit_sha": commit_sha})


def _stamp_edge(edge: ResolvedDependencyEdge, repository_id: str, commit_sha: str) -> ResolvedDependencyEdge:
    return edge.model_copy(update={"repository_id": repository_id, "commit_sha": commit_sha})


def _classify_lock_packages(
    bundle: _ManifestBundle,
    non_lock_bundles: list[_ManifestBundle],
    result: AggregatedDependencies,
    *,
    repository_id: str,
    commit_sha: str,
) -> list[ResolvedPackage]:
    """Assign direct/transitive/unknown to every resolved package of a lockfile."""
    lock_dir = bundle.manifest.directory
    seeds: set[str] = set(bundle.outcome.lock_root_names)
    for other in non_lock_bundles:
        if other.manifest.directory == lock_dir:
            seeds.update(other.outcome.direct_names)

    packages = bundle.outcome.resolved_packages
    by_name: dict[str, list[ResolvedPackage]] = collections.defaultdict(list)
    for package in packages:
        if not package.is_root_project:
            by_name[package.normalized_name].append(package)

    adjacency: dict[str, set[str]] = collections.defaultdict(set)
    for edge in bundle.outcome.edges:
        adjacency[edge.from_name].add(edge.to_name)

    reachable: set[str] = set()
    frontier = [name for name in seeds if name in by_name]
    visited = set(frontier)
    while frontier:
        current = frontier.pop()
        for target in adjacency.get(current, ()):  # type: ignore[arg-type]
            if target in visited:
                continue
            visited.add(target)
            reachable.add(target)
            frontier.append(target)

    classified: list[ResolvedPackage] = []
    unknown_names: set[str] = set()
    for package in packages:
        if package.is_root_project:
            relation = DependencyRelation.DIRECT
        elif package.normalized_name in seeds:
            relation = DependencyRelation.DIRECT
        elif package.normalized_name in reachable:
            relation = DependencyRelation.TRANSITIVE
        else:
            relation = DependencyRelation.UNKNOWN
            unknown_names.add(package.normalized_name)
        classified.append(
            _stamp_resolved_package(
                package.model_copy(update={"relation": relation}),
                repository_id,
                commit_sha,
            )
        )

    if not seeds:
        result.warnings.append(
            warn(
                WarningCode.DIRECTNESS_UNKNOWN,
                "No manifest in the same directory declares which packages are direct, so every resolved package of "
                "this lockfile is reported with relation=unknown",
                severity=Severity.WARNING,
                stage=_aggregation_stage(),
                manifest_path=bundle.manifest.path,
            )
        )
    elif unknown_names:
        result.warnings.append(
            warn(
                WarningCode.DIRECTNESS_UNKNOWN,
                "Some resolved packages are neither declared directly nor reachable from a direct dependency",
                severity=Severity.INFO,
                stage=_aggregation_stage(),
                manifest_path=bundle.manifest.path,
                packages=sorted(unknown_names)[:50],
                package_count=len(unknown_names),
            )
        )
    return classified


def _fill_edge_resolutions(
    edges: list[ResolvedDependencyEdge], lock_bundles: list[_ManifestBundle]
) -> list[IngestionWarning]:
    """Attach resolved versions to edges using each lockfile's package table."""
    versions_by_lock: dict[str, dict[str, set[str]]] = {}
    for bundle in lock_bundles:
        mapping: dict[str, set[str]] = collections.defaultdict(set)
        for package in bundle.outcome.resolved_packages:
            if not package.is_root_project:
                mapping[package.normalized_name].add(package.version)
        versions_by_lock[bundle.manifest.path] = mapping

    warnings: list[IngestionWarning] = []
    ambiguous: set[tuple[str, str]] = set()
    for index, edge in enumerate(edges):
        if edge.to_resolved_version is not None:
            continue
        mapping = versions_by_lock.get(edge.source_manifest, {})
        candidates = mapping.get(edge.to_name, set())
        if len(candidates) == 1:
            edges[index] = edge.model_copy(update={"to_resolved_version": next(iter(candidates))})
        elif len(candidates) > 1:
            ambiguous.add((edge.source_manifest, edge.to_name))

    for manifest_path, name in sorted(ambiguous):
        warnings.append(
            warn(
                WarningCode.CONFLICTING_RESOLVED_VERSIONS,
                "A lockfile resolves several versions of the same package (conditional resolution); the edge target "
                "version is left unset instead of guessing",
                severity=Severity.INFO,
                stage=_aggregation_stage(),
                manifest_path=manifest_path,
                package=name,
                versions=sorted(versions_by_lock.get(manifest_path, {}).get(name, set())),
            )
        )
    return warnings


# ---------------------------------------------------------------------------
# Conflict detection
# ---------------------------------------------------------------------------
def _detect_conflicts(
    declarations: list[DependencyDeclaration],
    resolved_packages: list[ResolvedPackage],
    lock_bundles: list[_ManifestBundle],
    settings: Settings,
    result: AggregatedDependencies,
) -> list[IngestionWarning]:
    warnings: list[IngestionWarning] = []

    pinned: dict[tuple[str, str | None], dict[str, list[DependencyDeclaration]]] = collections.defaultdict(
        lambda: collections.defaultdict(list)
    )
    constraints: dict[tuple[str, str | None, str], dict[str, list[DependencyDeclaration]]] = collections.defaultdict(
        lambda: collections.defaultdict(list)
    )
    for declaration in declarations:
        key = (declaration.normalized_name, declaration.marker)
        if declaration.is_exact_pin and declaration.version_constraint:
            pinned[key][declaration.version_constraint].append(declaration)
        elif declaration.version_constraint:
            directory = _directory_of(declaration.provenance.manifest_path)
            constraints[(declaration.normalized_name, declaration.marker, directory)][
                declaration.version_constraint
            ].append(declaration)

    for (name, marker), versions in sorted(
        pinned.items(), key=lambda item: (item[0][0], item[0][1] or "")
    ):
        if len(versions) < 2:
            continue
        result.conflicting_packages.add(name)
        warnings.append(
            warn(
                WarningCode.CONFLICTING_EXACT_PINS,
                "The same package is pinned to different exact versions for the same environment",
                severity=Severity.WARNING,
                stage=_aggregation_stage(),
                package=name,
                marker=marker,
                declarations={
                    version: [declaration.provenance.manifest_path for declaration in declarations_]
                    for version, declarations_ in sorted(versions.items())
                },
            )
        )

    truncated = 0
    for (name, marker, directory), variants in sorted(
        constraints.items(), key=lambda item: (item[0][0], item[0][1] or "", item[0][2] or "")
    ):
        if len(variants) < 2:
            continue
        if len(warnings) >= settings.max_conflict_warnings:
            truncated += 1
            continue
        warnings.append(
            warn(
                WarningCode.MULTIPLE_CONSTRAINTS_FOR_PACKAGE,
                "Two manifests in the same directory declare different version constraints for the same package",
                severity=Severity.INFO,
                stage=_aggregation_stage(),
                package=name,
                marker=marker,
                directory=directory,
                constraints={
                    constraint: sorted({d.provenance.manifest_path for d in declarations_})
                    for constraint, declarations_ in sorted(variants.items())
                },
            )
        )

    for declaration in declarations:
        if not declaration.is_exact_pin or not declaration.version_constraint or not declaration.resolved_version:
            continue
        pinned_version = declaration.version_constraint[2:]
        if pinned_version != declaration.resolved_version:
            result.conflicting_packages.add(declaration.normalized_name)
            warnings.append(
                warn(
                    WarningCode.PIN_RESOLVED_MISMATCH,
                    "A declared exact pin does not match the version resolved by the lockfile",
                    severity=Severity.WARNING,
                    stage=_aggregation_stage(),
                    manifest_path=declaration.provenance.manifest_path,
                    line_number=declaration.provenance.line_number,
                    package=declaration.original_name,
                    pinned=declaration.version_constraint,
                    resolved=declaration.resolved_version,
                    resolved_from=declaration.resolved_from,
                )
            )

    by_name: dict[str, dict[str, set[str]]] = collections.defaultdict(lambda: collections.defaultdict(set))
    for package in resolved_packages:
        by_name[package.normalized_name][package.source_manifest].add(package.version)
    for name, per_manifest in sorted(by_name.items()):
        all_versions = {version for versions in per_manifest.values() for version in versions}
        if len(per_manifest) > 1 and len(all_versions) > 1:
            result.conflicting_packages.add(name)
            warnings.append(
                warn(
                    WarningCode.CONFLICTING_RESOLVED_VERSIONS,
                    "Two lockfiles resolve the same package to different versions",
                    severity=Severity.WARNING,
                    stage=_aggregation_stage(),
                    package=name,
                    resolutions={manifest: sorted(versions) for manifest, versions in sorted(per_manifest.items())},
                )
            )
        elif len(per_manifest) == 1 and len(all_versions) > 1:
            warnings.append(
                warn(
                    WarningCode.CONFLICTING_RESOLVED_VERSIONS,
                    "A single lockfile resolves several versions of the same package; both are reported with their "
                    "resolution markers",
                    severity=Severity.INFO,
                    stage=_aggregation_stage(),
                    package=name,
                    resolutions={manifest: sorted(versions) for manifest, versions in sorted(per_manifest.items())},
                )
            )

    if truncated:
        result.truncated_warning_count = truncated
        warnings.append(
            warn(
                WarningCode.WARNINGS_TRUNCATED,
                "Further conflicting declaration warnings were suppressed to keep the report readable",
                severity=Severity.INFO,
                stage=_aggregation_stage(),
                suppressed=truncated,
                limit=settings.max_conflict_warnings,
            )
        )
    return warnings


def _cap_declarations(
    declarations: list[DependencyDeclaration],
    settings: Settings,
    result: AggregatedDependencies,
) -> list[DependencyDeclaration]:
    if len(declarations) <= settings.max_dependencies:
        return declarations
    result.warnings.append(
        warn(
            WarningCode.DEPENDENCY_LIMIT_REACHED,
            "The dependency limit was reached; the remaining declarations were dropped from the report",
            stage=_aggregation_stage(),
            limit=settings.max_dependencies,
        )
    )
    return declarations[: settings.max_dependencies]


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------
def _build_coverage(discovery: DiscoveryResult, bundles: list[_ManifestBundle]) -> list[FormatCoverage]:
    coverage: list[FormatCoverage] = []
    for manifest_format in SUPPORTED_FORMATS:
        detected = [manifest for manifest in discovery.manifests if manifest.format is manifest_format]
        parsed = 0
        failed = 0
        for bundle in bundles:
            if bundle.manifest.format is not manifest_format:
                continue
            if bundle.outcome.status is ManifestParseStatus.FAILED:
                failed += 1
            else:
                parsed += 1
        coverage.append(
            FormatCoverage(
                format=manifest_format.value,
                support_level=SupportLevel.SUPPORTED,
                detected_files=len(detected),
                parsed_files=parsed,
                failed_files=failed,
                notes=FORMAT_CAPABILITIES.get(manifest_format),
            )
        )

    unsupported_counts: collections.Counter[str] = collections.Counter(
        manifest.unsupported_format.value
        for manifest in discovery.manifests
        if manifest.unsupported_format is not None
    )
    for name, count in sorted(unsupported_counts.items()):
        coverage.append(
            FormatCoverage(
                format=name,
                support_level=SupportLevel.UNSUPPORTED,
                detected_files=count,
                parsed_files=0,
                failed_files=0,
                notes="Detected but deliberately not parsed; BlastRadius does not guess dependency data",
            )
        )
    return coverage


def _directory_of(path: str) -> str:
    return path.rsplit("/", 1)[0] if "/" in path else "."


def _aggregation_stage():
    from app.models.common import IngestionStage

    return IngestionStage.AGGREGATION


__all__ = ["AggregatedDependencies", "aggregate_dependencies"]
