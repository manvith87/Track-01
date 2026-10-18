"""``uv.lock`` parser.

uv's lockfile is richer than poetry's for graph purposes:

* ``source`` distinguishes the repository's own project (``virtual`` /
  ``editable`` pointing at ``.``) from registry, path, git and URL sources;
* the root project's ``dependencies`` (and ``[package.metadata].requires-dist``)
  establish which packages are **direct**, everything else reachable through
  the recorded edges is **transitive**;
* ``[package.optional-dependencies]`` and ``[package.dev-dependencies]`` tag
  edges as optional / development.

Versions on edges (``{ name = "x", version = "1.2.3" }``) are resolved versions
recorded by uv and are stored as such; ``specifier`` values are constraints and
are kept separate.
"""

from __future__ import annotations

from typing import Any

try:  # pragma: no cover - Python < 3.11 only
    import tomllib
except ModuleNotFoundError:  # pragma: no cover - Python < 3.11 only
    import tomli as tomllib  # type: ignore[no-redef]

from app.core.logging import safe_text
from app.ingestion.parsers.base import (
    ParseOutcome,
    ParserContext,
    RecordOrigin,
    build_edge,
    build_resolved_package,
    err,
    normalize_name,
    warn,
)
from app.ingestion.parsers.pyproject import TomlLineIndex, _line_from_message
from app.models.common import (
    DependencyRelation,
    ErrorCode,
    ManifestFormat,
    ManifestParseStatus,
    Severity,
    SourceKind,
    WarningCode,
)
from app.models.dependencies import ResolvedDependencyEdge

FORMAT = ManifestFormat.UV_LOCK

_SUPPORTED_LOCK_VERSIONS = {1}


def parse_uv_lock(context: ParserContext) -> ParseOutcome:
    """Parse a uv.lock file into resolved packages, direct names and edges."""
    outcome = ParseOutcome()
    index = TomlLineIndex(context.lines)

    try:
        data = tomllib.loads(context.text)
    except tomllib.TOMLDecodeError as exc:
        line = _line_from_message(str(exc))
        outcome.status = ManifestParseStatus.FAILED
        outcome.errors.append(
            err(
                ErrorCode.MANIFEST_PARSE_ERROR,
                "uv.lock is not valid TOML and could not be parsed",
                manifest_path=context.path,
                line_number=line,
                reason=safe_text(exc, 200),
            )
        )
        return outcome

    if not isinstance(data, dict):
        outcome.status = ManifestParseStatus.FAILED
        outcome.errors.append(
            err(ErrorCode.MANIFEST_PARSE_ERROR, "uv.lock did not parse into a TOML table", manifest_path=context.path)
        )
        return outcome

    lock_version = data.get("version")
    if isinstance(lock_version, int):
        outcome.metadata["lock_version"] = lock_version
        if lock_version not in _SUPPORTED_LOCK_VERSIONS:
            outcome.warnings.append(
                warn(
                    WarningCode.MANIFEST_PARSE_ERROR,
                    f"uv.lock lock format version {lock_version} is newer than the versions BlastRadius was tested "
                    "against; parsing continued but some fields may be ignored",
                    severity=Severity.WARNING,
                    manifest_path=context.path,
                    line_number=index.key_line("", "version"),
                )
            )
            outcome.status = ManifestParseStatus.PARTIAL
    else:
        outcome.warnings.append(
            warn(
                WarningCode.MANIFEST_PARSE_ERROR,
                "uv.lock has no 'version' field; the lock format could not be identified",
                severity=Severity.WARNING,
                manifest_path=context.path,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL

    revision = data.get("revision")
    if isinstance(revision, int):
        outcome.metadata["revision"] = revision
    requires_python = data.get("requires-python")
    if isinstance(requires_python, str):
        outcome.requires_python = requires_python
    resolution_markers = data.get("resolution-markers")
    if isinstance(resolution_markers, list):
        outcome.metadata["resolution_markers"] = [str(item) for item in resolution_markers if isinstance(item, str)]

    packages = data.get("package")
    if packages is None:
        outcome.warnings.append(
            warn(
                WarningCode.NO_DEPENDENCIES_FOUND,
                "uv.lock contains no [[package]] entries; there is nothing resolved to report",
                severity=Severity.WARNING,
                manifest_path=context.path,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return outcome
    if not isinstance(packages, list):
        outcome.status = ManifestParseStatus.FAILED
        outcome.errors.append(
            err(
                ErrorCode.MANIFEST_PARSE_ERROR,
                "uv.lock 'package' is not an array of tables",
                manifest_path=context.path,
                line_number=index.section_line("package"),
            )
        )
        return outcome

    block_starts = index.block_start_lines("package")
    root_found = False
    malformed = 0
    for position, package in enumerate(packages):
        line_number = block_starts[position] if position < len(block_starts) else None
        if not isinstance(package, dict):
            malformed += 1
            outcome.warnings.append(
                warn(
                    WarningCode.MALFORMED_ENTRY,
                    "A uv.lock [[package]] entry is not a table and was skipped",
                    manifest_path=context.path,
                    line_number=line_number,
                )
            )
            continue
        is_root = _parse_package(context, index, outcome, package, line_number=line_number, position=position)
        root_found = root_found or is_root

    if not root_found:
        outcome.warnings.append(
            warn(
                WarningCode.DIRECTNESS_UNKNOWN,
                "uv.lock does not contain a workspace root package (source = virtual/editable '.'), so direct versus "
                "transitive dependencies cannot be derived from this file alone",
                severity=Severity.WARNING,
                manifest_path=context.path,
            )
        )
    if malformed:
        outcome.status = ManifestParseStatus.PARTIAL
    if not outcome.resolved_packages and outcome.status is not ManifestParseStatus.FAILED:
        outcome.status = ManifestParseStatus.PARTIAL
        outcome.warnings.append(
            warn(
                WarningCode.NO_DEPENDENCIES_FOUND,
                "uv.lock did not yield any resolvable package",
                severity=Severity.WARNING,
                manifest_path=context.path,
            )
        )
    return outcome


def _parse_package(
    context: ParserContext,
    index: TomlLineIndex,
    outcome: ParseOutcome,
    package: dict[str, Any],
    *,
    line_number: int | None,
    position: int,
) -> bool:
    """Parse one ``[[package]]`` entry. Returns True when it is the workspace root."""
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not name:
        outcome.warnings.append(
            warn(
                WarningCode.MALFORMED_ENTRY,
                "A uv.lock [[package]] entry has no name and was skipped",
                manifest_path=context.path,
                line_number=line_number,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return False
    if not isinstance(version, str) or not version:
        outcome.warnings.append(
            warn(
                WarningCode.MALFORMED_ENTRY,
                "A uv.lock [[package]] entry has no resolved version; the package was skipped because BlastRadius "
                "never invents versions",
                manifest_path=context.path,
                line_number=line_number,
                package=name,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return False

    source_kind, source_reference, is_root = _classify_source(package.get("source"))

    dependencies = package.get("dependencies")
    if is_root:
        # The workspace root's declared dependencies are the project's direct
        # requirements even when the richer ``[package.metadata]`` table is absent.
        _remember_root_dependencies(outcome, dependencies)
        optional_root = package.get("optional-dependencies")
        if isinstance(optional_root, dict):
            for entries in optional_root.values():
                _remember_root_dependencies(outcome, entries)
    edges = _dependency_edges(
        context,
        outcome,
        name=name,
        version=version,
        dependencies=dependencies,
        line_number=line_number,
        optional=False,
        dev=False,
    )

    optional_dependencies = package.get("optional-dependencies")
    if isinstance(optional_dependencies, dict):
        for extra, entries in optional_dependencies.items():
            edges.extend(
                _dependency_edges(
                    context,
                    outcome,
                    name=name,
                    version=version,
                    dependencies=entries,
                    line_number=line_number,
                    optional=True,
                    dev=False,
                    group=str(extra),
                )
            )
    dev_dependencies = package.get("dev-dependencies")
    if isinstance(dev_dependencies, dict):
        for group, entries in dev_dependencies.items():
            edges.extend(
                _dependency_edges(
                    context,
                    outcome,
                    name=name,
                    version=version,
                    dependencies=entries,
                    line_number=line_number,
                    optional=False,
                    dev=True,
                    group=str(group),
                )
            )

    direct_names = _direct_names_from_metadata(package, outcome, line_number=line_number)
    if is_root and dependencies is None and not direct_names:
        outcome.warnings.append(
            warn(
                WarningCode.DIRECTNESS_UNKNOWN,
                "The uv.lock workspace root package declares no dependencies; no direct dependency could be derived",
                severity=Severity.INFO,
                manifest_path=context.path,
                line_number=line_number,
                package=name,
            )
        )

    origin = RecordOrigin(
        path=context.path,
        manifest_format=FORMAT.value,
        section="package",
        line_number=line_number,
        snippet=f'[[package]] name = "{safe_text(name, 80)}" version = "{safe_text(version, 40)}"',
        evidence=(
            f"resolved by uv.lock in [[package]] entry #{position + 1}"
            + (" (workspace root project)" if is_root else "")
        ),
    )
    resolved = build_resolved_package(
        origin=origin,
        original_name=name,
        version=version,
        relation=DependencyRelation.DIRECT if is_root else DependencyRelation.UNKNOWN,
        is_root_project=is_root,
        groups=(),
        marker=None,
        requires_python=None,
        source_kind=source_kind,
        source_reference=source_reference,
        dependency_count=len(edges),
    )
    outcome.resolved_packages.append(resolved)
    outcome.edges.extend(edges)
    outcome.count_section("packages")
    if is_root:
        outcome.count_section("root_packages")
    return is_root


def _classify_source(source: Any) -> tuple[SourceKind, str | None, bool]:
    """Classify a uv.lock ``source`` table."""
    if not isinstance(source, dict):
        return SourceKind.UNKNOWN, None, False
    for key in ("registry",):
        value = source.get(key)
        if isinstance(value, str):
            return SourceKind.REGISTRY, value, False
    for key in ("editable", "virtual", "directory"):
        value = source.get(key)
        if isinstance(value, str):
            is_root = value.strip() in {".", "./"}
            kind = SourceKind.EDITABLE if key == "editable" else SourceKind.PATH
            return kind, value, is_root
    for key, kind in (("git", SourceKind.GIT), ("url", SourceKind.URL), ("path", SourceKind.PATH)):
        value = source.get(key)
        if isinstance(value, str):
            return kind, value, False
    return SourceKind.UNKNOWN, None, False


def _remember_root_dependencies(outcome: ParseOutcome, entries: Any) -> None:
    """Record the workspace root's declared dependency names as direct."""
    if not isinstance(entries, list):
        return
    for entry in entries:
        if isinstance(entry, dict) and isinstance(entry.get("name"), str) and entry["name"]:
            outcome.lock_root_names.add(normalize_name(entry["name"]))


def _direct_names_from_metadata(
    package: dict[str, Any], outcome: ParseOutcome, *, line_number: int | None
) -> dict[str, list[str]]:
    """Collect ``requires-dist`` / ``requires-dev`` names as direct dependencies."""
    metadata = package.get("metadata")
    if not isinstance(metadata, dict):
        return {}
    groups: dict[str, list[str]] = {}

    requires_dist = metadata.get("requires-dist")
    if isinstance(requires_dist, list):
        names = [entry["name"] for entry in requires_dist if isinstance(entry, dict) and isinstance(entry.get("name"), str)]
        if names:
            groups["runtime"] = names
            outcome.lock_root_names.update(normalize_name(name) for name in names)
            outcome.count_section("metadata.requires-dist", len(names))

    requires_dev = metadata.get("requires-dev")
    if isinstance(requires_dev, dict):
        for group, entries in requires_dev.items():
            if not isinstance(entries, list):
                continue
            names = [entry["name"] for entry in entries if isinstance(entry, dict) and isinstance(entry.get("name"), str)]
            if names:
                groups[f"dev:{group}"] = names
                outcome.lock_root_names.update(normalize_name(name) for name in names)
                outcome.count_section("metadata.requires-dev", len(names))
    return groups


def _dependency_edges(
    context: ParserContext,
    outcome: ParseOutcome,
    *,
    name: str,
    version: str,
    dependencies: Any,
    line_number: int | None,
    optional: bool,
    dev: bool,
    group: str | None = None,
) -> list[ResolvedDependencyEdge]:
    """Build edges from a uv.lock dependency list."""
    edges: list[ResolvedDependencyEdge] = []
    if dependencies is None:
        return edges
    if not isinstance(dependencies, list):
        outcome.warnings.append(
            warn(
                WarningCode.MALFORMED_ENTRY,
                "A uv.lock dependency list has an unexpected shape; its edges were skipped",
                manifest_path=context.path,
                line_number=line_number,
                package=name,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return edges

    for entry in dependencies:
        if isinstance(entry, str):  # pragma: no cover - not produced by uv, tolerated anyway
            dep_name, dep_version, specifier, marker, extras = entry, None, None, None, ()
        elif isinstance(entry, dict):
            raw_name = entry.get("name")
            if not isinstance(raw_name, str) or not raw_name:
                outcome.warnings.append(
                    warn(
                        WarningCode.MALFORMED_ENTRY,
                        "A uv.lock dependency entry has no name and was skipped",
                        manifest_path=context.path,
                        line_number=line_number,
                        package=name,
                    )
                )
                outcome.status = ManifestParseStatus.PARTIAL
                continue
            dep_name = raw_name
            dep_version = entry.get("version") if isinstance(entry.get("version"), str) else None
            specifier = entry.get("specifier") if isinstance(entry.get("specifier"), str) else None
            marker = entry.get("marker") if isinstance(entry.get("marker"), str) else None
            raw_extras = entry.get("extra")
            extras = tuple(str(extra) for extra in raw_extras if isinstance(extra, str)) if isinstance(raw_extras, list) else ()
        else:
            outcome.warnings.append(
                warn(
                    WarningCode.MALFORMED_ENTRY,
                    "A uv.lock dependency entry has an unsupported shape and was skipped",
                    manifest_path=context.path,
                    line_number=line_number,
                    package=name,
                )
            )
            outcome.status = ManifestParseStatus.PARTIAL
            continue

        section = "package.dependencies"
        if optional:
            section = f"package.optional-dependencies.{group}" if group else "package.optional-dependencies"
        elif dev:
            section = f"package.dev-dependencies.{group}" if group else "package.dev-dependencies"

        origin = RecordOrigin(
            path=context.path,
            manifest_format=FORMAT.value,
            section=section,
            line_number=line_number,
            snippet=f"{safe_text(name, 40)} -> {safe_text(dep_name, 40)}",
            evidence=(
                f"edge declared by uv.lock package '{name}' {version}"
                + (f" in optional group '{group}'" if optional and group else "")
                + (f" in development group '{group}'" if dev and group else "")
            ),
        )
        edges.append(
            build_edge(
                origin=origin,
                from_name=name,
                from_version=version,
                to_name=dep_name,
                to_version_constraint=specifier,
                to_resolved_version=dep_version,
                marker=marker,
                extras=extras,
                optional=optional,
                dev=dev,
            )
        )
    return edges


__all__ = ["FORMAT", "parse_uv_lock"]
