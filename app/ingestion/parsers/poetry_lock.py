"""``poetry.lock`` parser.

Reads the ``[[package]]`` tables (resolved versions, dev groups, markers,
non-registry sources), the dependency edges declared inside each package and
the ``[metadata]`` block.

What the format supports, and therefore what BlastRadius reports:

* every ``[[package]]`` entry is a **resolved** package with a concrete
  version - those versions are the only resolved versions Phase 1 emits;
* ``groups`` / ``category`` establish whether a package is development-only;
* ``dependencies`` establishes edges (and therefore transitive reachability);
* poetry.lock does **not** mark which packages the root project asked for, so
  directness is derived from the sibling ``pyproject.toml`` during aggregation
  (and stays ``unknown`` when that file is absent).
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

FORMAT = ManifestFormat.POETRY_LOCK


def parse_poetry_lock(context: ParserContext) -> ParseOutcome:
    """Parse a poetry.lock file into resolved packages and dependency edges."""
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
                "poetry.lock is not valid TOML and could not be parsed",
                manifest_path=context.path,
                line_number=line,
                reason=safe_text(exc, 200),
            )
        )
        return outcome

    if not isinstance(data, dict):
        outcome.status = ManifestParseStatus.FAILED
        outcome.errors.append(
            err(ErrorCode.MANIFEST_PARSE_ERROR, "poetry.lock did not parse into a TOML table", manifest_path=context.path)
        )
        return outcome

    metadata = data.get("metadata")
    if isinstance(metadata, dict):
        for key in ("lock-version", "python-versions", "content-hash"):
            value = metadata.get(key)
            if value is not None:
                outcome.metadata[key.replace("-", "_")] = safe_text(value, 120)
        requires_python = metadata.get("python-versions")
        if isinstance(requires_python, str):
            outcome.requires_python = requires_python

    packages = data.get("package")
    if packages is None:
        outcome.warnings.append(
            warn(
                WarningCode.NO_DEPENDENCIES_FOUND,
                "poetry.lock contains no [[package]] entries; there is nothing resolved to report",
                severity=Severity.WARNING,
                manifest_path=context.path,
                line_number=index.section_line("metadata"),
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return outcome
    if not isinstance(packages, list):
        outcome.status = ManifestParseStatus.FAILED
        outcome.errors.append(
            err(
                ErrorCode.MANIFEST_PARSE_ERROR,
                "poetry.lock 'package' is not an array of tables",
                manifest_path=context.path,
                line_number=index.section_line("package"),
            )
        )
        return outcome

    block_starts = index.block_start_lines("package")
    malformed = 0
    for position, package in enumerate(packages):
        line_number = block_starts[position] if position < len(block_starts) else None
        if not isinstance(package, dict):
            malformed += 1
            outcome.warnings.append(
                warn(
                    WarningCode.MALFORMED_ENTRY,
                    "A poetry.lock [[package]] entry is not a table and was skipped",
                    manifest_path=context.path,
                    line_number=line_number,
                )
            )
            continue
        _parse_package(context, index, outcome, package, line_number=line_number, position=position)
        if outcome.status is ManifestParseStatus.FAILED:
            break

    if malformed:
        outcome.status = ManifestParseStatus.PARTIAL
    if not outcome.resolved_packages and outcome.status is not ManifestParseStatus.FAILED:
        outcome.warnings.append(
            warn(
                WarningCode.NO_DEPENDENCIES_FOUND,
                "poetry.lock did not yield any resolvable package",
                severity=Severity.WARNING,
                manifest_path=context.path,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
    return outcome


def _parse_package(
    context: ParserContext,
    index: TomlLineIndex,
    outcome: ParseOutcome,
    package: dict[str, Any],
    *,
    line_number: int | None,
    position: int,
) -> None:
    name = package.get("name")
    version = package.get("version")
    if not isinstance(name, str) or not name:
        outcome.warnings.append(
            warn(
                WarningCode.MALFORMED_ENTRY,
                "A poetry.lock [[package]] entry has no name and was skipped",
                manifest_path=context.path,
                line_number=line_number,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return
    if not isinstance(version, str) or not version:
        outcome.warnings.append(
            warn(
                WarningCode.MALFORMED_ENTRY,
                "A poetry.lock [[package]] entry has no resolved version; the package was skipped because "
                "BlastRadius never invents versions",
                manifest_path=context.path,
                line_number=line_number,
                package=name,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return

    groups: tuple[str, ...] = ()
    raw_groups = package.get("groups")
    if isinstance(raw_groups, list):
        groups = tuple(str(group) for group in raw_groups if isinstance(group, str))
    category = package.get("category")
    if not groups and isinstance(category, str):
        groups = (category,)
    if not groups:
        outcome.warnings.append(
            warn(
                WarningCode.LOCKFILE_NO_DEV_MARKERS,
                "A poetry.lock package entry declares no dependency group; the package is treated as a runtime "
                "dependency and its directness stays unknown until matched against a manifest",
                severity=Severity.INFO,
                manifest_path=context.path,
                line_number=line_number,
                package=name,
            )
        )
    # ``groups`` (lock v2) / ``category`` (v1) mark which dependency groups
    # need the package.  A package that is also in "main" is a runtime
    # dependency; only packages absent from "main" count as development-only.
    is_dev = bool(groups) and "main" not in groups
    is_optional = bool(package.get("optional", False))

    requires_python = package.get("python-versions")
    if not isinstance(requires_python, str) or requires_python.strip() in {"", "*"}:
        requires_python = None
    marker = package.get("markers")
    if not isinstance(marker, str):
        marker = None

    source_kind = SourceKind.REGISTRY
    source_reference: str | None = None
    source = package.get("source")
    if isinstance(source, dict):
        source_type = source.get("type")
        source_url = source.get("url")
        if isinstance(source_type, str):
            source_kind = {
                "git": SourceKind.GIT,
                "file": SourceKind.PATH,
                "directory": SourceKind.PATH,
                "url": SourceKind.URL,
                "legacy": SourceKind.REGISTRY,
            }.get(source_type, SourceKind.UNKNOWN)
        if isinstance(source_url, str):
            source_reference = source_url

    files = package.get("files")
    if isinstance(files, list):
        outcome.metadata.setdefault("file_counts", {})
        file_counts = outcome.metadata["file_counts"]
        if isinstance(file_counts, dict):
            file_counts[name] = len(files)

    dependencies = package.get("dependencies")
    dependency_edges = _package_edges(
        context, outcome, name=name, version=version, dependencies=dependencies, line_number=line_number
    )

    origin = RecordOrigin(
        path=context.path,
        manifest_format=FORMAT.value,
        section="package",
        line_number=line_number,
        snippet=f'[[package]] name = "{safe_text(name, 80)}" version = "{safe_text(version, 40)}"',
        evidence=f"resolved by poetry.lock in [[package]] entry #{position + 1}",
    )
    resolved = build_resolved_package(
        origin=origin,
        original_name=name,
        version=version,
        relation=DependencyRelation.UNKNOWN,
        is_dev=is_dev,
        is_optional=is_optional,
        groups=groups,
        marker=marker,
        requires_python=requires_python,
        source_kind=source_kind,
        source_reference=source_reference,
        dependency_count=len(dependency_edges),
    )
    outcome.resolved_packages.append(resolved)
    outcome.edges.extend(dependency_edges)
    outcome.count_section("packages")
    if is_dev:
        outcome.count_section("dev_packages")


def _package_edges(
    context: ParserContext,
    outcome: ParseOutcome,
    *,
    name: str,
    version: str,
    dependencies: Any,
    line_number: int | None,
) -> list[Any]:
    """Build edges from a ``[package.dependencies]`` table.

    Poetry allows several alternative constraints for one dependency (for
    example one per Python version); each alternative becomes its own edge so
    that markers and extras stay attached to the constraint they qualify.
    """
    edges: list[Any] = []
    if dependencies is None:
        return edges
    if not isinstance(dependencies, dict):
        outcome.warnings.append(
            warn(
                WarningCode.MALFORMED_ENTRY,
                "A poetry.lock package 'dependencies' entry is not a table; edges for it were skipped",
                manifest_path=context.path,
                line_number=line_number,
                package=name,
            )
        )
        outcome.status = ManifestParseStatus.PARTIAL
        return edges

    for raw_dep_name, value in dependencies.items():
        dep_name = str(raw_dep_name)
        entries = value if isinstance(value, list) else [value]
        if isinstance(value, list) and len(entries) > 1:
            outcome.warnings.append(
                warn(
                    WarningCode.MULTIPLE_CONSTRAINTS_FOR_PACKAGE,
                    "A poetry.lock dependency declares multiple alternative constraints; each alternative was "
                    "recorded as its own edge",
                    severity=Severity.INFO,
                    manifest_path=context.path,
                    line_number=line_number,
                    package=dep_name,
                    dependency_of=name,
                    constraints=[safe_text(entry, 80) for entry in entries],
                )
            )

        for entry in entries:
            constraint: str | None = None
            marker: str | None = None
            extras: tuple[str, ...] = ()
            optional = False

            if isinstance(entry, str):
                constraint = entry.strip() or None
            elif isinstance(entry, dict):
                raw_version = entry.get("version")
                if isinstance(raw_version, str) and raw_version.strip():
                    constraint = raw_version.strip()
                raw_marker = entry.get("markers")
                if isinstance(raw_marker, str):
                    marker = raw_marker
                if entry.get("optional"):
                    optional = True
                raw_extras = entry.get("extras")
                if isinstance(raw_extras, list):
                    extras = tuple(str(extra) for extra in raw_extras if isinstance(extra, str))
            else:
                outcome.warnings.append(
                    warn(
                        WarningCode.MALFORMED_ENTRY,
                        "A poetry.lock dependency edge has an unsupported shape and was skipped",
                        manifest_path=context.path,
                        line_number=line_number,
                        package=name,
                        dependency=dep_name,
                    )
                )
                outcome.status = ManifestParseStatus.PARTIAL
                continue

            origin = RecordOrigin(
                path=context.path,
                manifest_format=FORMAT.value,
                section="package.dependencies",
                line_number=line_number,
                snippet=f'{safe_text(name, 40)} depends on {safe_text(dep_name, 40)}',
                evidence=f"edge declared by poetry.lock package '{name}' {version}",
            )
            edges.append(
                build_edge(
                    origin=origin,
                    from_name=name,
                    from_version=version,
                    to_name=dep_name,
                    to_version_constraint=constraint,
                    marker=marker,
                    extras=extras,
                    optional=optional,
                )
            )
    return edges


__all__ = ["FORMAT", "parse_poetry_lock"]
